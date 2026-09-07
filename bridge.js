const express = require("express");
const cors = require("cors");
const nodemailer = require("nodemailer");

const app = express();

app.use(cors());
app.use(express.json({ limit: "1mb" }));

const PORT = Number(process.env.PORT || 3001);
const BRIDGE_API_KEY = process.env.BRIDGE_API_KEY;
const ROCKETCHAT_WEBHOOK_URL = process.env.ROCKETCHAT_WEBHOOK_URL;

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
  return String(value || "").trim().replace(/\/+$/, "");
}

/**
 * Restrict AI proxy calls to Alibaba/DashScope hosts.
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
 * List Alibaba models.
 *
 * For Token Plan, model discovery is queried through the
 * Singapore international DashScope model-list endpoint.
 */
async function listAlibabaModels(config) {
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

  let modelsUrl;

  const url = new URL(baseUrl);

  if (url.hostname === "token-plan.ap-southeast-1.maas.aliyuncs.com") {
    modelsUrl =
      "https://dashscope-intl.aliyuncs.com/api/v1/models" +
      "?providers=qwen&capabilities=TG&page_no=1&page_size=100";
  } else {
    modelsUrl =
      `${url.origin}/api/v1/models` +
      "?providers=qwen&capabilities=TG&page_no=1&page_size=100";
  }

  const response = await fetch(modelsUrl, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    }
  });

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
 * Root information.
 */
app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "NodeSend",
    endpoints: {
      health: "GET /health",
      email: "POST /send",
      rocketchat: "POST /rocketchat",
      aiModels: "POST /ai/models",
      aiTest: "POST /ai/test",
      aiChat: "POST /ai/chat"
    }
  });
});

/**
 * Health check.
 */
app.get("/health", (req, res) => {
  res.json({
    success: true,
    service: "NodeSend",
    status: "healthy",
    rocketchatConfigured: Boolean(ROCKETCHAT_WEBHOOK_URL),
    aiProxyConfigured: true
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
    const username = String(config.username || "").trim();
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
        error: "SMTP host, port, username and password are required"
      });
    }

    if (!from || !to || !subject) {
      return res.status(400).json({
        success: false,
        error: "Email from, to and subject are required"
      });
    }

    if (!text && !html) {
      return res.status(400).json({
        success: false,
        error: "Email text or html content is required"
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
    console.error("Email error:", error.message);

    return res.status(500).json({
      success: false,
      error: error.message || "Email could not be sent"
    });
  }
});

/**
 * Send a message through a Rocket.Chat incoming webhook.
 */
app.post("/rocketchat", requireApiKey, async (req, res) => {
  try {
    if (!ROCKETCHAT_WEBHOOK_URL) {
      return res.status(500).json({
        success: false,
        error: "ROCKETCHAT_WEBHOOK_URL is not configured"
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
    if (attachments) payload.attachments = attachments;

    const response = await fetch(ROCKETCHAT_WEBHOOK_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });

    const responseText = await response.text();

    let responseBody;

    try {
      responseBody = JSON.parse(responseText);
    } catch {
      responseBody = responseText;
    }

    if (!response.ok) {
      return res.status(response.status).json({
        success: false,
        error: "Rocket.Chat rejected the request",
        details: responseBody
      });
    }

    return res.json({
      success: true,
      rocketchat: responseBody
    });
  } catch (error) {
    console.error("Rocket.Chat error:", error.message);

    return res.status(500).json({
      success: false,
      error: error.message || "Rocket.Chat message could not be sent"
    });
  }
});

/**
 * List available Alibaba AI models.
 *
 * Expected request:
 *
 * {
 *   "provider": "alibaba",
 *   "config": {
 *     "apiKey": "...",
 *     "baseUrl": "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1"
 *   }
 * }
 */
app.post("/ai/models", requireApiKey, async (req, res) => {
  try {
    const { provider, config } = req.body || {};

    if (provider !== "alibaba") {
      return res.status(400).json({
        success: false,
        error: "Unsupported AI provider"
      });
    }

    if (!config?.apiKey || !config?.baseUrl) {
      return res.status(400).json({
        success: false,
        error: "Alibaba apiKey and baseUrl are required"
      });
    }

    const result = await listAlibabaModels(config);

    if (!result.ok) {
      return res.status(result.status).json({
        success: false,
        provider: "alibaba",
        error: "Alibaba model discovery failed",
        details: result.body
      });
    }

    let rawModels = [];

    if (Array.isArray(result.body?.output?.models)) {
      rawModels = result.body.output.models;
    } else if (Array.isArray(result.body?.data)) {
      rawModels = result.body.data;
    } else if (Array.isArray(result.body?.models)) {
      rawModels = result.body.models;
    }

    const models = rawModels
      .map((model) => {
        const id =
          model.model ||
          model.id ||
          model.name ||
          null;

        return {
          id,
          name:
            model.name ||
            model.model ||
            model.id ||
            null,
          provider:
            model.provider ||
            "qwen",
          capabilities:
            model.capabilities ||
            [],
          features:
            model.features ||
            [],
          contextWindow:
            model.model_info?.context_window ??
            model.context_window ??
            null,
          maxOutputTokens:
            model.model_info?.max_output_tokens ??
            model.max_output_tokens ??
            null
        };
      })
      .filter((model) => model.id);

    return res.json({
      success: true,
      provider: "alibaba",
      total:
        result.body?.output?.total ??
        result.body?.total ??
        models.length,
      models
    });
  } catch (error) {
    console.error("Alibaba models error:", error.message);

    return res.status(500).json({
      success: false,
      error: error.message || "Alibaba model discovery failed"
    });
  }
});

/**
 * Test an Alibaba AI connection and selected model.
 *
 * Expected request:
 *
 * {
 *   "provider": "alibaba",
 *   "config": {
 *     "apiKey": "...",
 *     "baseUrl": "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1"
 *   },
 *   "model": "..."
 * }
 */
app.post("/ai/test", requireApiKey, async (req, res) => {
  try {
    const { provider, config, model } = req.body || {};

    if (provider !== "alibaba") {
      return res.status(400).json({
        success: false,
        error: "Unsupported AI provider"
      });
    }

    if (!config?.apiKey || !config?.baseUrl) {
      return res.status(400).json({
        success: false,
        error: "Alibaba apiKey and baseUrl are required"
      });
    }

    if (!model) {
      return res.status(400).json({
        success: false,
        error: "model is required"
      });
    }

    const result = await callAlibaba(
      config,
      "/chat/completions",
      {
        model: String(model),
        messages: [
          {
            role: "user",
            content: "Reply only with OK"
          }
        ],
        max_tokens: 10,
        temperature: 0
      }
    );

    if (!result.ok) {
      return res.status(result.status).json({
        success: false,
        provider: "alibaba",
        model,
        error: "Alibaba model test failed",
        details: result.body
      });
    }

    const answer =
      result.body?.choices?.[0]?.message?.content ?? null;

    return res.json({
      success: true,
      provider: "alibaba",
      model,
      response: answer
    });
  } catch (error) {
    console.error("Alibaba AI test error:", error.message);

    return res.status(500).json({
      success: false,
      error: error.message || "Alibaba AI test failed"
    });
  }
});

/**
 * Generic Alibaba AI chat proxy.
 *
 * Expected request:
 *
 * {
 *   "provider": "alibaba",
 *   "config": {
 *     "apiKey": "...",
 *     "baseUrl": "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1"
 *   },
 *   "model": "...",
 *   "messages": [...],
 *   "temperature": 0.2,
 *   "max_tokens": 1000
 * }
 */
app.post("/ai/chat", requireApiKey, async (req, res) => {
  try {
    const {
      provider,
      config,
      model,
      messages,
      temperature = 0.2,
      max_tokens = 1000
    } = req.body || {};

    if (provider !== "alibaba") {
      return res.status(400).json({
        success: false,
        error: "Unsupported AI provider"
      });
    }

    if (!config?.apiKey || !config?.baseUrl) {
      return res.status(400).json({
        success: false,
        error: "Alibaba apiKey and baseUrl are required"
      });
    }

    if (!model) {
      return res.status(400).json({
        success: false,
        error: "model is required"
      });
    }

    if (!Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({
        success: false,
        error: "messages must be a non-empty array"
      });
    }

    if (messages.length > 100) {
      return res.status(400).json({
        success: false,
        error: "Too many messages"
      });
    }

    const safeMaxTokens = Math.min(
      Math.max(Number(max_tokens) || 1000, 1),
      8000
    );

    const parsedTemperature = Number(temperature);

    const safeTemperature = Number.isFinite(parsedTemperature)
      ? Math.min(Math.max(parsedTemperature, 0), 2)
      : 0.2;

    const result = await callAlibaba(
      config,
      "/chat/completions",
      {
        model: String(model),
        messages,
        temperature: safeTemperature,
        max_tokens: safeMaxTokens
      }
    );

    if (!result.ok) {
      return res.status(result.status).json({
        success: false,
        provider: "alibaba",
        model,
        error: "Alibaba AI request failed",
        details: result.body
      });
    }

    return res.json({
      success: true,
      provider: "alibaba",
      model,
      response: result.body
    });
  } catch (error) {
    console.error("Alibaba AI error:", error.message);

    return res.status(500).json({
      success: false,
      error: error.message || "Alibaba AI request failed"
    });
  }
});

/**
 * Fallback 404.
 */
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Endpoint not found"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`NodeSend listening on 0.0.0.0:${PORT}`);
});
