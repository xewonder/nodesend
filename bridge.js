const express = require("express");
const cors = require("cors");
const nodemailer = require("nodemailer");

const app = express();

app.use(cors());
app.use(express.json({ limit: "1mb" }));

const PORT = Number(process.env.PORT || 3001);
const BRIDGE_API_KEY = process.env.BRIDGE_API_KEY;
const ROCKETCHAT_WEBHOOK_URL = process.env.ROCKETCHAT_WEBHOOK_URL;

const OPENAI_BASE_URL = "https://api.openai.com/v1";

/**
 * Hard-coded Alibaba Token Plan model discovery list.
 *
 * NOTE:
 * BridgeMind's application/database may maintain its own
 * provider/model catalog. This list exists only for the
 * legacy /ai/models Alibaba discovery endpoint.
 */
const ALIBABA_TOKEN_PLAN_MODELS = [
  {
    id: "qwen3.8-flash",
    name: "Qwen 3.8 Flash"
  },
  {
    id: "qwen3.8-max",
    name: "Qwen 3.8 Max"
  }
];

/**
 * Checks the API key supplied by the caller.
 */
function requireApiKey(req, res, next) {
  const providedKey = req.get("x-api-key");

  if (!BRIDGE_API_KEY) {
    return res.status(500).json({
      success: false,
      error: "BRIDGE_API_KEY is not configured"
    });
  }

  if (!providedKey || providedKey !== BRIDGE_API_KEY) {
    return res.status(403).json({
      success: false,
      error: "Forbidden"
    });
  }

  next();
}

/**
 * Normalize provider base URL.
 */
function sanitizeBaseUrl(value) {
  return String(value || "")
    .trim()
    .replace(/\/+$/, "");
}

/**
 * Restrict Alibaba proxy calls to Alibaba/DashScope hosts.
 */
function isAllowedAlibabaBaseUrl(baseUrl) {
  try {
    const url = new URL(baseUrl);

    if (url.protocol !== "https:") {
      return false;
    }

    const host = url.hostname.toLowerCase();

    return (
      host.endsWith(".maas.aliyuncs.com") ||
      host === "dashscope-intl.aliyuncs.com" ||
      host === "dashscope.aliyuncs.com" ||
      host === "dashscope-us.aliyuncs.com" ||
      host === "cn-hongkong.dashscope.aliyuncs.com"
    );
  } catch {
    return false;
  }
}

/**
 * Safely parse an HTTP response.
 */
async function parseResponse(response) {
  const responseText = await response.text();

  let responseBody;

  try {
    responseBody = JSON.parse(responseText);
  } catch {
    responseBody = responseText;
  }

  return {
    ok: response.ok,
    status: response.status,
    body: responseBody
  };
}

/**
 * Remove proxy-only fields from a BridgeMind request.
 *
 * Everything else is passed to the AI provider unchanged.
 *
 * This is deliberate:
 * NodeSend should transport provider parameters,
 * not invent or reinterpret them.
 */
function buildProviderBody(input = {}) {
  const {
    provider,
    config,
    ...providerBody
  } = input;

  return providerBody;
}

/**
 * Call Alibaba OpenAI-compatible endpoint.
 *
 * Credentials are supplied transiently in the request.
 * They are not stored by NodeSend.
 */
async function callAlibaba(config, path, body) {
  const apiKey = String(config?.apiKey || "").trim();
  const baseUrl = sanitizeBaseUrl(config?.baseUrl);

  if (!apiKey) {
    throw new Error("Alibaba API key is required");
  }

  if (!baseUrl) {
    throw new Error("Alibaba base URL is required");
  }

  if (!isAllowedAlibabaBaseUrl(baseUrl)) {
    throw new Error("Alibaba base URL is not allowed");
  }

  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  return parseResponse(response);
}

/**
 * Call OpenAI API.
 *
 * Credentials are supplied transiently in the request.
 * They are not stored by NodeSend.
 */
async function callOpenAI(config, path, options = {}) {
  const apiKey = String(config?.apiKey || "").trim();

  if (!apiKey) {
    throw new Error("OpenAI API key is required");
  }

  const response = await fetch(`${OPENAI_BASE_URL}${path}`, {
    method: options.method || "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    ...(options.body !== undefined
      ? {
          body: JSON.stringify(options.body)
        }
      : {})
  });

  return parseResponse(response);
}

/**
 * Root information.
 */
app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "NodeSend",
    version: "bridge-pass-through-v1",
    endpoints: {
      health: "GET /health",
      email: "POST /send",
      rocketchat: "POST /rocketchat",
      aiModels: "POST /ai/models",
      aiTest: "POST /ai/test",
      aiChat: "POST /ai/chat"
    },
    providers: [
      "alibaba",
      "openai"
    ]
  });
});

/**
 * Health check.
 */
app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: "NodeSend",
    version: "bridge-pass-through-v1",
    status: "healthy",
    rocketchatConfigured: Boolean(
      ROCKETCHAT_WEBHOOK_URL
    ),
    aiProxyConfigured: true,
    providers: {
      alibaba: true,
      openai: true
    }
  });
});

/**
 * Send an email using SMTP settings supplied in the request.
 */
app.post("/send", requireApiKey, async (req, res) => {
  try {
    const { config, email } = req.body || {};

    if (!config || !email) {
      return res.status(400).json({
        success: false,
        error: "Both config and email are required"
      });
    }

    const host = String(config.host || "").trim();
    const port = Number(config.port);
    const username = String(
      config.username || ""
    ).trim();
    const password = String(config.password || "");

    const from = String(email.from || "").trim();
    const to = email.to;
    const subject = String(email.subject || "");
    const text = email.text;
    const html = email.html;
    const cc = email.cc;
    const bcc = email.bcc;

    if (!host || !port || !username || !password) {
      return res.status(400).json({
        success: false,
        error:
          "SMTP host, port, username and password are required"
      });
    }

    if (!from || !to || !subject) {
      return res.status(400).json({
        success: false,
        error:
          "Email from, to and subject are required"
      });
    }

    if (!text && !html) {
      return res.status(400).json({
        success: false,
        error:
          "Email text or html content is required"
      });
    }

    const transporter = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: {
        user: username,
        pass: password
      }
    });

    await transporter.verify();

    const result = await transporter.sendMail({
      from,
      to,
      cc,
      bcc,
      subject,
      text,
      html
    });

    return res.json({
      success: true,
      messageId: result.messageId,
      accepted: result.accepted,
      rejected: result.rejected
    });
  } catch (error) {
    console.error(
      "Email error:",
      error.message
    );

    return res.status(500).json({
      success: false,
      error:
        error.message ||
        "Email could not be sent"
    });
  }
});

/**
 * Send a message through a Rocket.Chat incoming webhook.
 */
app.post(
  "/rocketchat",
  requireApiKey,
  async (req, res) => {
    try {
      if (!ROCKETCHAT_WEBHOOK_URL) {
        return res.status(500).json({
          success: false,
          error:
            "ROCKETCHAT_WEBHOOK_URL is not configured"
        });
      }

      const {
        text,
        channel,
        username,
        emoji,
        avatar,
        alias,
        attachments
      } = req.body || {};

      if (!text) {
        return res.status(400).json({
          success: false,
          error: "text is required"
        });
      }

      const payload = {
        text
      };

      if (channel) payload.channel = channel;
      if (username) payload.username = username;
      if (alias) payload.alias = alias;
      if (emoji) payload.emoji = emoji;
      if (avatar) payload.avatar = avatar;
      if (attachments) {
        payload.attachments = attachments;
      }

      const response = await fetch(
        ROCKETCHAT_WEBHOOK_URL,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify(payload)
        }
      );

      const result =
        await parseResponse(response);

      if (!result.ok) {
        return res
          .status(result.status)
          .json({
            success: false,
            error:
              "Rocket.Chat rejected the request",
            details: result.body
          });
      }

      return res.json({
        success: true,
        rocketchat: result.body
      });
    } catch (error) {
      console.error(
        "Rocket.Chat error:",
        error.message
      );

      return res.status(500).json({
        success: false,
        error:
          error.message ||
          "Rocket.Chat message could not be sent"
      });
    }
  }
);

/**
 * List available AI models.
 *
 * Alibaba:
 * returns the current local Token Plan discovery list.
 *
 * OpenAI:
 * dynamically queries GET /v1/models.
 *
 * BridgeMind may use its database catalog as the
 * authoritative list for Settings.
 */
app.post(
  "/ai/models",
  requireApiKey,
  async (req, res) => {
    try {
      const {
        provider,
        config
      } = req.body || {};

      if (provider === "alibaba") {
        return res.json({
          success: true,
          provider: "alibaba",
          source:
            "local-token-plan-list",
          models:
            ALIBABA_TOKEN_PLAN_MODELS
        });
      }

      if (provider === "openai") {
        if (!config?.apiKey) {
          return res.status(400).json({
            success: false,
            error:
              "OpenAI apiKey is required"
          });
        }

        const result = await callOpenAI(
          config,
          "/models",
          {
            method: "GET"
          }
        );

        if (!result.ok) {
          return res
            .status(result.status)
            .json({
              success: false,
              provider: "openai",
              error:
                "OpenAI model discovery failed",
              details: result.body
            });
        }

        const models =
          Array.isArray(
            result.body?.data
          )
            ? result.body.data
                .map((model) => ({
                  id: model.id,
                  name: model.id,
                  created:
                    model.created || null,
                  ownedBy:
                    model.owned_by || null
                }))
                .filter(
                  (model) => model.id
                )
                .sort((a, b) =>
                  a.id.localeCompare(b.id)
                )
            : [];

        return res.json({
          success: true,
          provider: "openai",
          source: "openai-api",
          total: models.length,
          models
        });
      }

      return res.status(400).json({
        success: false,
        error:
          "Unsupported AI provider"
      });
    } catch (error) {
      console.error(
        "AI models error:",
        error.message
      );

      return res.status(500).json({
        success: false,
        error:
          error.message ||
          "AI model discovery failed"
      });
    }
  }
);

/**
 * Test AI connection and selected model.
 *
 * IMPORTANT:
 * NodeSend does NOT invent model-specific options.
 *
 * The app may optionally send extra provider parameters,
 * such as:
 *
 * reasoning_effort
 * temperature
 * max_tokens
 * max_completion_tokens
 *
 * If supplied, they are passed through.
 *
 * If omitted, NodeSend does not create them.
 */
app.post(
  "/ai/test",
  requireApiKey,
  async (req, res) => {
    try {
      const {
        provider,
        config,
        model
      } = req.body || {};

      if (!model) {
        return res.status(400).json({
          success: false,
          error: "model is required"
        });
      }

      if (provider === "alibaba") {
        if (
          !config?.apiKey ||
          !config?.baseUrl
        ) {
          return res.status(400).json({
            success: false,
            error:
              "Alibaba apiKey and baseUrl are required"
          });
        }

        /**
         * Build a minimal test body.
         *
         * Any optional parameters supplied by the app
         * are preserved.
         */
        const extraBody =
          buildProviderBody(
            req.body
          );

        delete extraBody.model;
        delete extraBody.messages;

        const body = {
          model: String(model),
          messages: [
            {
              role: "user",
              content:
                "Reply only with OK"
            }
          ],
          ...extraBody
        };

        const result =
          await callAlibaba(
            config,
            "/chat/completions",
            body
          );

        if (!result.ok) {
          return res
            .status(result.status)
            .json({
              success: false,
              provider:
                "alibaba",
              model,
              error:
                "Alibaba model test failed",
              details:
                result.body
            });
        }

        return res.json({
          success: true,
          provider: "alibaba",
          model,
          response:
            result.body
              ?.choices?.[0]
              ?.message?.content ??
            null
        });
      }

      if (provider === "openai") {
        if (!config?.apiKey) {
          return res.status(400).json({
            success: false,
            error:
              "OpenAI apiKey is required"
          });
        }

        /**
         * Start with whatever optional provider
         * parameters the APP supplied.
         *
         * NodeSend does NOT add:
         *
         * reasoning_effort
         * temperature
         * max_tokens
         * max_completion_tokens
         *
         * unless the app sent them.
         */
        const extraBody =
          buildProviderBody(
            req.body
          );

        delete extraBody.model;
        delete extraBody.messages;

        const body = {
          model: String(model),
          messages: [
            {
              role: "user",
              content:
                "Reply only with OK"
            }
          ],
          ...extraBody
        };

        /**
         * Safe diagnostic:
         * logs parameter names only.
         *
         * No credentials or prompts.
         */
        console.log(
          "[OpenAI /ai/test body keys]",
          Object.keys(body)
        );

        const result =
          await callOpenAI(
            config,
            "/chat/completions",
            {
              body
            }
          );

        if (!result.ok) {
          return res
            .status(result.status)
            .json({
              success: false,
              provider: "openai",
              model,
              error:
                "OpenAI model test failed",
              details:
                result.body
            });
        }

        return res.json({
          success: true,
          provider: "openai",
          model,
          response:
            result.body
              ?.choices?.[0]
              ?.message?.content ??
            null
        });
      }

      return res.status(400).json({
        success: false,
        error:
          "Unsupported AI provider"
      });
    } catch (error) {
      console.error(
        "AI test error:",
        error.message
      );

      return res.status(500).json({
        success: false,
        error:
          error.message ||
          "AI model test failed"
      });
    }
  }
);

/**
 * Generic AI chat proxy.
 *
 * IMPORTANT ARCHITECTURE:
 *
 * NodeSend is deliberately a thin transport layer.
 *
 * The BridgeMind app decides which provider parameters
 * to send.
 *
 * Examples:
 *
 * Alibaba:
 *
 * {
 *   "provider": "alibaba",
 *   "config": {
 *     "apiKey": "...",
 *     "baseUrl": "https://..."
 *   },
 *   "model": "qwen3.8-flash",
 *   "messages": [...],
 *   "temperature": 0,
 *   "max_tokens": 20,
 *   "enable_thinking": false
 * }
 *
 * OpenAI without reasoning:
 *
 * {
 *   "provider": "openai",
 *   "config": {
 *     "apiKey": "..."
 *   },
 *   "model": "gpt-4",
 *   "messages": [...],
 *   "max_tokens": 20
 * }
 *
 * OpenAI with reasoning:
 *
 * {
 *   "provider": "openai",
 *   "config": {
 *     "apiKey": "..."
 *   },
 *   "model": "some-reasoning-model",
 *   "messages": [...],
 *   "max_completion_tokens": 1000,
 *   "reasoning_effort": "low"
 * }
 *
 * NodeSend passes these provider parameters through.
 */
app.post(
  "/ai/chat",
  requireApiKey,
  async (req, res) => {
    try {
      const {
        provider,
        config,
        model,
        messages
      } = req.body || {};

      if (!model) {
        return res.status(400).json({
          success: false,
          error: "model is required"
        });
      }

      if (
        !Array.isArray(messages) ||
        messages.length === 0
      ) {
        return res.status(400).json({
          success: false,
          error:
            "messages must be a non-empty array"
        });
      }

      if (messages.length > 100) {
        return res.status(400).json({
          success: false,
          error:
            "Too many messages"
        });
      }

      /**
       * Strip only NodeSend's proxy envelope.
       *
       * Everything else is passed to the
       * selected provider.
       */
      const providerBody =
        buildProviderBody(req.body);

      providerBody.model =
        String(model);

      providerBody.messages =
        messages;

      if (provider === "alibaba") {
        if (
          !config?.apiKey ||
          !config?.baseUrl
        ) {
          return res.status(400).json({
            success: false,
            error:
              "Alibaba apiKey and baseUrl are required"
          });
        }

        console.log(
          "[Alibaba /ai/chat body keys]",
          Object.keys(providerBody)
        );

        const result =
          await callAlibaba(
            config,
            "/chat/completions",
            providerBody
          );

        if (!result.ok) {
          return res
            .status(result.status)
            .json({
              success: false,
              provider:
                "alibaba",
              model,
              error:
                "Alibaba AI request failed",
              details:
                result.body
            });
        }

        return res.json({
          success: true,
          provider: "alibaba",
          model,
          response: result.body
        });
      }

      if (provider === "openai") {
        if (!config?.apiKey) {
          return res.status(400).json({
            success: false,
            error:
              "OpenAI apiKey is required"
          });
        }

        /**
         * CRITICAL:
         *
         * No reasoning_effort is created here.
         *
         * If the application supplied it,
         * it remains in providerBody.
         *
         * If the application omitted it,
         * it does not exist.
         */
        console.log(
          "[OpenAI /ai/chat body keys]",
          Object.keys(providerBody)
        );

        const result =
          await callOpenAI(
            config,
            "/chat/completions",
            {
              body: providerBody
            }
          );

        if (!result.ok) {
          return res
            .status(result.status)
            .json({
              success: false,
              provider: "openai",
              model,
              error:
                "OpenAI AI request failed",
              details:
                result.body
            });
        }

        return res.json({
          success: true,
          provider: "openai",
          model,
          response: result.body
        });
      }

      return res.status(400).json({
        success: false,
        error:
          "Unsupported AI provider"
      });
    } catch (error) {
      console.error(
        "AI chat error:",
        error.message
      );

      return res.status(500).json({
        success: false,
        error:
          error.message ||
          "AI request failed"
      });
    }
  }
);

/**
 * Fallback 404.
 */
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Endpoint not found"
  });
});

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `NodeSend listening on 0.0.0.0:${PORT}`
    );
  }
);
