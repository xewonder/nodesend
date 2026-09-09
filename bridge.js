const express = require("express");
const cors = require("cors");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const app = express();

app.use(cors());
app.use(express.json({ limit: "1mb" }));

const PORT = Number(process.env.PORT || 3001);

const BRIDGE_API_KEY = process.env.BRIDGE_API_KEY;
const ROCKETCHAT_WEBHOOK_URL =
  process.env.ROCKETCHAT_WEBHOOK_URL;

const OPENAI_BASE_URL = "https://api.openai.com/v1";

/**
 * RSA private key used ONLY for decrypting AI provider
 * credentials sent by BridgeMind.
 *
 * Supports either:
 *
 * 1. A true multiline PEM environment variable
 *
 * or
 *
 * 2. A single-line value containing literal \n characters
 */
const NODESEND_PRIVATE_KEY_PEM = String(
  process.env.NODESEND_PRIVATE_KEY_PEM || ""
)
  .replace(/\\n/g, "\n")
  .trim();

/**
 * TEMPORARY migration switch.
 *
 * Recommended migration procedure:
 *
 * 1. Set ALLOW_PLAINTEXT_AI_KEYS=true
 * 2. Deploy this NodeSend version
 * 3. Update Greta/BridgeMind to send encryptedApiKey
 * 4. Verify encrypted requests work
 * 5. Change ALLOW_PLAINTEXT_AI_KEYS=false
 * 6. Redeploy
 *
 * Once migration is complete, plaintext AI provider
 * credentials will be rejected.
 *
 * IMPORTANT:
 * This affects AI provider credentials ONLY.
 * It does NOT affect SMTP passwords.
 */
const ALLOW_PLAINTEXT_AI_KEYS =
  String(
    process.env.ALLOW_PLAINTEXT_AI_KEYS || "false"
  ).toLowerCase() === "true";

/**
 * Hard-coded Alibaba Token Plan discovery list.
 *
 * BridgeMind may maintain its own database-driven
 * provider/model catalog. This list remains only for
 * the NodeSend /ai/models Alibaba discovery endpoint.
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
 * Checks the NodeSend API key supplied by the caller.
 *
 * This is separate from OpenAI/Alibaba credentials.
 */
function requireApiKey(req, res, next) {
  const providedKey = req.get("x-api-key");

  if (!BRIDGE_API_KEY) {
    return res.status(500).json({
      success: false,
      error: "BRIDGE_API_KEY is not configured"
    });
  }

  if (
    !providedKey ||
    providedKey !== BRIDGE_API_KEY
  ) {
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
 * Restrict Alibaba proxy calls to Alibaba/DashScope
 * hosts.
 */
function isAllowedAlibabaBaseUrl(baseUrl) {
  try {
    const url = new URL(baseUrl);

    if (url.protocol !== "https:") {
      return false;
    }

    const host =
      url.hostname.toLowerCase();

    return (
      host.endsWith(
        ".maas.aliyuncs.com"
      ) ||
      host ===
        "dashscope-intl.aliyuncs.com" ||
      host ===
        "dashscope.aliyuncs.com" ||
      host ===
        "dashscope-us.aliyuncs.com" ||
      host ===
        "cn-hongkong.dashscope.aliyuncs.com"
    );
  } catch {
    return false;
  }
}

/**
 * Safely parse an HTTP response.
 */
async function parseResponse(response) {
  const responseText =
    await response.text();

  let responseBody;

  try {
    responseBody =
      JSON.parse(responseText);
  } catch {
    responseBody =
      responseText;
  }

  return {
    ok: response.ok,
    status: response.status,
    body: responseBody
  };
}

/**
 * Verify the configured NodeSend RSA private key.
 */
function getNodeSendPrivateKey() {
  if (!NODESEND_PRIVATE_KEY_PEM) {
    throw new Error(
      "NODESEND_PRIVATE_KEY_PEM is not configured"
    );
  }

  return crypto.createPrivateKey({
    key: NODESEND_PRIVATE_KEY_PEM,
    format: "pem"
  });
}

/**
 * Derive the public RSA key from the private key.
 *
 * The public key is safe to expose to the browser.
 */
function getNodeSendPublicKeyPem() {
  const privateKey =
    getNodeSendPrivateKey();

  const publicKey =
    crypto.createPublicKey(
      privateKey
    );

  return publicKey.export({
    type: "spki",
    format: "pem"
  });
}

/**
 * Decrypt a BridgeMind provider API key.
 *
 * Expected browser encryption:
 *
 * RSA-OAEP
 * SHA-256
 *
 * Expected transport encoding:
 *
 * base64
 */
function decryptProviderApiKey(
  encryptedApiKey
) {
  if (!encryptedApiKey) {
    throw new Error(
      "encryptedApiKey is required"
    );
  }

  const privateKey =
    getNodeSendPrivateKey();

  let encryptedBuffer;

  try {
    encryptedBuffer = Buffer.from(
      String(encryptedApiKey),
      "base64"
    );
  } catch {
    throw new Error(
      "encryptedApiKey is not valid base64"
    );
  }

  if (!encryptedBuffer.length) {
    throw new Error(
      "encryptedApiKey is empty"
    );
  }

  let decryptedBuffer;

  try {
    decryptedBuffer =
      crypto.privateDecrypt(
        {
          key: privateKey,
          padding:
            crypto.constants
              .RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256"
        },
        encryptedBuffer
      );
  } catch {
    throw new Error(
      "Provider API key decryption failed"
    );
  }

  const apiKey =
    decryptedBuffer
      .toString("utf8")
      .trim();

  if (!apiKey) {
    throw new Error(
      "Decrypted provider API key is empty"
    );
  }

  return apiKey;
}

/**
 * Resolve an AI provider credential.
 *
 * Preferred:
 *
 * config.encryptedApiKey
 *
 * Temporary migration fallback:
 *
 * config.apiKey
 *
 * Plaintext fallback works ONLY when:
 *
 * ALLOW_PLAINTEXT_AI_KEYS=true
 *
 * SMTP credentials are NOT handled by this function.
 */
function resolveProviderApiKey(config) {
  if (config?.encryptedApiKey) {
    return decryptProviderApiKey(
      config.encryptedApiKey
    );
  }

  if (
    ALLOW_PLAINTEXT_AI_KEYS &&
    config?.apiKey
  ) {
    console.warn(
      "[SECURITY] Legacy plaintext AI provider API key received"
    );

    return String(
      config.apiKey
    ).trim();
  }

  if (
    config?.apiKey &&
    !ALLOW_PLAINTEXT_AI_KEYS
  ) {
    throw new Error(
      "Plaintext AI provider API keys are disabled. Send config.encryptedApiKey."
    );
  }

  throw new Error(
    "AI provider API key is required"
  );
}

/**
 * Remove NodeSend-only proxy envelope fields.
 *
 * Everything else is intended for the selected provider.
 *
 * IMPORTANT:
 *
 * NodeSend does NOT invent:
 *
 * reasoning_effort
 * temperature
 * max_tokens
 * max_completion_tokens
 * enable_thinking
 *
 * Those are BridgeMind/provider policy decisions.
 */
function buildProviderBody(
  input = {}
) {
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
 * Provider credential is decrypted only in memory.
 * NodeSend never persists it.
 */
async function callAlibaba(
  config,
  path,
  body
) {
  const apiKey =
    resolveProviderApiKey(config);

  const baseUrl =
    sanitizeBaseUrl(
      config?.baseUrl
    );

  if (!baseUrl) {
    throw new Error(
      "Alibaba base URL is required"
    );
  }

  if (
    !isAllowedAlibabaBaseUrl(
      baseUrl
    )
  ) {
    throw new Error(
      "Alibaba base URL is not allowed"
    );
  }

  const startedAt = Date.now();

  console.log(
    "[Alibaba fetch started]",
    {
      path,
      fields:
        body &&
        typeof body === "object"
          ? Object.keys(body)
          : []
    }
  );

  try {
    const response = await fetch(
      `${baseUrl}${path}`,
      {
        method: "POST",
        headers: {
          Authorization:
            `Bearer ${apiKey}`,
          "Content-Type":
            "application/json"
        },
        body: JSON.stringify(
          body
        )
      }
    );

    console.log(
      "[Alibaba response]",
      {
        status:
          response.status,
        elapsedMs:
          Date.now() -
          startedAt
      }
    );

    return parseResponse(
      response
    );
  } catch (error) {
    console.error(
      "[Alibaba fetch error]",
      {
        name:
          error?.name ||
          "Error",
        message:
          error?.message ||
          "Unknown error",
        elapsedMs:
          Date.now() -
          startedAt
      }
    );

    throw error;
  }
}

/**
 * Call OpenAI API.
 *
 * Provider credential is decrypted only in memory.
 * NodeSend never persists it.
 */
async function callOpenAI(
  config,
  path,
  options = {}
) {
  const apiKey =
    resolveProviderApiKey(config);

  const startedAt = Date.now();

  console.log(
    "[OpenAI fetch started]",
    {
      path,
      method:
        options.method ||
        "POST",
      fields:
        options.body &&
        typeof options.body ===
          "object"
          ? Object.keys(
              options.body
            )
          : []
    }
  );

  try {
    const response = await fetch(
      `${OPENAI_BASE_URL}${path}`,
      {
        method:
          options.method ||
          "POST",
        headers: {
          Authorization:
            `Bearer ${apiKey}`,
          "Content-Type":
            "application/json",
          ...(options.headers ||
            {})
        },
        ...(options.body !==
        undefined
          ? {
              body:
                JSON.stringify(
                  options.body
                )
            }
          : {})
      }
    );

    console.log(
      "[OpenAI response]",
      {
        status:
          response.status,
        elapsedMs:
          Date.now() -
          startedAt
      }
    );

    return parseResponse(
      response
    );
  } catch (error) {
    console.error(
      "[OpenAI fetch error]",
      {
        name:
          error?.name ||
          "Error",
        message:
          error?.message ||
          "Unknown error",
        elapsedMs:
          Date.now() -
          startedAt
      }
    );

    throw error;
  }
}

/**
 * Root information.
 */
app.get("/", (req, res) => {
  res.json({
    success: true,
    service: "NodeSend",
    version:
      "bridge-encrypted-credentials-v1",
    endpoints: {
      health:
        "GET /health",
      publicKey:
        "GET /crypto/public-key",
      email:
        "POST /send",
      rocketchat:
        "POST /rocketchat",
      aiModels:
        "POST /ai/models",
      aiTest:
        "POST /ai/test",
      aiChat:
        "POST /ai/chat"
    },
    providers: [
      "alibaba",
      "openai"
    ]
  });
});

/**
 * Health check.
 *
 * Does NOT expose private or public key material.
 */
app.get(
  "/health",
  (req, res) => {
    let encryptionConfigured =
      Boolean(
        NODESEND_PRIVATE_KEY_PEM
      );

    /**
     * Also check whether Node can
     * successfully parse the PEM.
     */
    if (
      encryptionConfigured
    ) {
      try {
        getNodeSendPrivateKey();
      } catch {
        encryptionConfigured =
          false;
      }
    }

    res.json({
      success: true,
      service: "NodeSend",
      version:
        "bridge-encrypted-credentials-v1",
      status: "healthy",

      encryptionConfigured,

      plaintextAIKeysAllowed:
        ALLOW_PLAINTEXT_AI_KEYS,

      rocketchatConfigured:
        Boolean(
          ROCKETCHAT_WEBHOOK_URL
        ),

      aiProxyConfigured:
        true,

      providers: {
        alibaba: true,
        openai: true
      }
    });
  }
);

/**
 * Public encryption key.
 *
 * This route intentionally does NOT require x-api-key.
 *
 * A public encryption key is not secret.
 *
 * The corresponding PRIVATE key remains only inside
 * NodeSend/Coolify.
 */
app.get(
  "/crypto/public-key",
  (req, res) => {
    try {
      const publicKey =
        getNodeSendPublicKeyPem();

      return res.json({
        success: true,
        algorithm:
          "RSA-OAEP",
        hash: "SHA-256",
        encoding:
          "PEM-SPKI",
        publicKey
      });
    } catch (error) {
      console.error(
        "Public key error:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,
          error:
            "NodeSend encryption is not configured"
        });
    }
  }
);

/**
 * ========================================================
 * EMAIL
 * ========================================================
 *
 * IMPORTANT:
 *
 * SMTP is deliberately NOT changed by the AI credential
 * encryption work.
 *
 * Existing fields remain:
 *
 * config.host
 * config.port
 * config.username
 * config.password
 *
 * This keeps existing email behavior intact.
 */
app.post(
  "/send",
  requireApiKey,
  async (req, res) => {
    try {
      const {
        config,
        email
      } = req.body || {};

      if (
        !config ||
        !email
      ) {
        return res
          .status(400)
          .json({
            success: false,
            error:
              "Both config and email are required"
          });
      }

      const host =
        String(
          config.host || ""
        ).trim();

      const port =
        Number(
          config.port
        );

      const username =
        String(
          config.username || ""
        ).trim();

      const password =
        String(
          config.password || ""
        );

      const from =
        String(
          email.from || ""
        ).trim();

      const to =
        email.to;

      const subject =
        String(
          email.subject || ""
        );

      const text =
        email.text;

      const html =
        email.html;

      const cc =
        email.cc;

      const bcc =
        email.bcc;

      if (
        !host ||
        !port ||
        !username ||
        !password
      ) {
        return res
          .status(400)
          .json({
            success: false,
            error:
              "SMTP host, port, username and password are required"
          });
      }

      if (
        !from ||
        !to ||
        !subject
      ) {
        return res
          .status(400)
          .json({
            success: false,
            error:
              "Email from, to and subject are required"
          });
      }

      if (
        !text &&
        !html
      ) {
        return res
          .status(400)
          .json({
            success: false,
            error:
              "Email text or html content is required"
          });
      }

      const transporter =
        nodemailer
          .createTransport({
            host,
            port,
            secure:
              port === 465,
            auth: {
              user:
                username,
              pass:
                password
            }
          });

      await transporter.verify();

      const result =
        await transporter
          .sendMail({
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
        messageId:
          result.messageId,
        accepted:
          result.accepted,
        rejected:
          result.rejected
      });
    } catch (error) {
      console.error(
        "Email error:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,
          error:
            error.message ||
            "Email could not be sent"
        });
    }
  }
);

/**
 * ========================================================
 * ROCKET.CHAT
 * ========================================================
 *
 * Existing Rocket.Chat behavior is unchanged.
 */
app.post(
  "/rocketchat",
  requireApiKey,
  async (req, res) => {
    try {
      if (
        !ROCKETCHAT_WEBHOOK_URL
      ) {
        return res
          .status(500)
          .json({
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
        return res
          .status(400)
          .json({
            success: false,
            error:
              "text is required"
          });
      }

      const payload = {
        text
      };

      if (channel) {
        payload.channel =
          channel;
      }

      if (username) {
        payload.username =
          username;
      }

      if (alias) {
        payload.alias =
          alias;
      }

      if (emoji) {
        payload.emoji =
          emoji;
      }

      if (avatar) {
        payload.avatar =
          avatar;
      }

      if (attachments) {
        payload.attachments =
          attachments;
      }

      const response =
        await fetch(
          ROCKETCHAT_WEBHOOK_URL,
          {
            method: "POST",
            headers: {
              "Content-Type":
                "application/json"
            },
            body:
              JSON.stringify(
                payload
              )
          }
        );

      const result =
        await parseResponse(
          response
        );

      if (!result.ok) {
        return res
          .status(
            result.status
          )
          .json({
            success: false,
            error:
              "Rocket.Chat rejected the request",
            details:
              result.body
          });
      }

      return res.json({
        success: true,
        rocketchat:
          result.body
      });
    } catch (error) {
      console.error(
        "Rocket.Chat error:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,
          error:
            error.message ||
            "Rocket.Chat message could not be sent"
        });
    }
  }
);

/**
 * ========================================================
 * AI MODEL DISCOVERY
 * ========================================================
 *
 * Alibaba:
 * returns local Token Plan discovery list.
 *
 * OpenAI:
 * dynamically calls GET /v1/models.
 *
 * AI credentials may be supplied as:
 *
 * config.encryptedApiKey
 *
 * During migration ONLY, plaintext config.apiKey can be
 * accepted when ALLOW_PLAINTEXT_AI_KEYS=true.
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

      if (
        provider ===
        "alibaba"
      ) {
        /**
         * Alibaba discovery currently uses the local
         * Token Plan allowlist, so there is no need to
         * decrypt the provider credential here.
         */
        return res.json({
          success: true,
          provider:
            "alibaba",
          source:
            "local-token-plan-list",
          models:
            ALIBABA_TOKEN_PLAN_MODELS
        });
      }

      if (
        provider ===
        "openai"
      ) {
        /**
         * resolveProviderApiKey() is called inside
         * callOpenAI().
         */
        const result =
          await callOpenAI(
            config,
            "/models",
            {
              method:
                "GET"
            }
          );

        if (!result.ok) {
          return res
            .status(
              result.status
            )
            .json({
              success: false,
              provider:
                "openai",
              error:
                "OpenAI model discovery failed",
              details:
                result.body
            });
        }

        const models =
          Array.isArray(
            result.body?.data
          )
            ? result.body.data
                .map(
                  (model) => ({
                    id:
                      model.id,
                    name:
                      model.id,
                    created:
                      model.created ||
                      null,
                    ownedBy:
                      model.owned_by ||
                      null
                  })
                )
                .filter(
                  (model) =>
                    model.id
                )
                .sort(
                  (a, b) =>
                    a.id.localeCompare(
                      b.id
                    )
                )
            : [];

        return res.json({
          success: true,
          provider:
            "openai",
          source:
            "openai-api",
          total:
            models.length,
          models
        });
      }

      return res
        .status(400)
        .json({
          success: false,
          error:
            "Unsupported AI provider"
        });
    } catch (error) {
      console.error(
        "AI models error:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,
          error:
            error.message ||
            "AI model discovery failed"
        });
    }
  }
);

/**
 * ========================================================
 * AI CONNECTION TEST
 * ========================================================
 *
 * NodeSend deliberately does NOT invent model-specific
 * parameters here.
 *
 * BridgeMind can send optional provider parameters if
 * required.
 *
 * For most Test Connection operations, BridgeMind should
 * send only:
 *
 * provider
 * config
 * model
 *
 * NodeSend adds only the minimal test message.
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
        return res
          .status(400)
          .json({
            success: false,
            error:
              "model is required"
          });
      }

      /**
       * Strip the NodeSend proxy envelope.
       *
       * Any explicit provider-specific parameters sent
       * by BridgeMind remain.
       */
      const extraBody =
        buildProviderBody(
          req.body
        );

      /**
       * NodeSend controls the model and test message
       * for this endpoint.
       */
      delete extraBody.model;
      delete extraBody.messages;

      const body = {
        model:
          String(model),

        messages: [
          {
            role: "user",
            content:
              "Reply only with OK"
          }
        ],

        ...extraBody
      };

      if (
        provider ===
        "alibaba"
      ) {
        if (
          !config?.baseUrl
        ) {
          return res
            .status(400)
            .json({
              success: false,
              error:
                "Alibaba baseUrl is required"
            });
        }

        console.log(
          "[Alibaba /ai/test]",
          {
            model:
              String(model),
            fields:
              Object.keys(
                body
              )
          }
        );

        const result =
          await callAlibaba(
            config,
            "/chat/completions",
            body
          );

        if (!result.ok) {
          return res
            .status(
              result.status
            )
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
          provider:
            "alibaba",
          model,
          response:
            result.body
              ?.choices?.[0]
              ?.message
              ?.content ??
            null
        });
      }

      if (
        provider ===
        "openai"
      ) {
        console.log(
          "[OpenAI /ai/test]",
          {
            model:
              String(model),
            fields:
              Object.keys(
                body
              )
          }
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
            .status(
              result.status
            )
            .json({
              success: false,
              provider:
                "openai",
              model,
              error:
                "OpenAI model test failed",
              details:
                result.body
            });
        }

        return res.json({
          success: true,
          provider:
            "openai",
          model,
          response:
            result.body
              ?.choices?.[0]
              ?.message
              ?.content ??
            null
        });
      }

      return res
        .status(400)
        .json({
          success: false,
          error:
            "Unsupported AI provider"
        });
    } catch (error) {
      console.error(
        "AI test error:",
        error.message
      );

      return res
        .status(500)
        .json({
          success: false,
          error:
            error.message ||
            "AI model test failed"
        });
    }
  }
);

/**
 * ========================================================
 * GENERIC AI CHAT PROXY
 * ========================================================
 *
 * NODE SEND ARCHITECTURE
 * ----------------------
 *
 * BridgeMind owns AI request policy.
 *
 * NodeSend owns:
 *
 * - authentication
 * - encrypted provider credential decryption
 * - provider routing
 * - transport
 * - returning the provider response
 *
 * NodeSend does NOT decide:
 *
 * - reasoning_effort
 * - max_tokens
 * - max_completion_tokens
 * - temperature
 * - enable_thinking
 * - model capability
 *
 * Everything except:
 *
 * provider
 * config
 *
 * is passed through to the selected AI provider.
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
        return res
          .status(400)
          .json({
            success: false,
            error:
              "model is required"
          });
      }

      if (
        !Array.isArray(
          messages
        ) ||
        messages.length === 0
      ) {
        return res
          .status(400)
          .json({
            success: false,
            error:
              "messages must be a non-empty array"
          });
      }

      if (
        messages.length > 100
      ) {
        return res
          .status(400)
          .json({
            success: false,
            error:
              "Too many messages"
          });
      }

      /**
       * Remove ONLY NodeSend's proxy envelope.
       *
       * Provider-specific options remain untouched.
       */
      const providerBody =
        buildProviderBody(
          req.body
        );

      providerBody.model =
        String(model);

      providerBody.messages =
        messages;

      if (
        provider ===
        "alibaba"
      ) {
        if (
          !config?.baseUrl
        ) {
          return res
            .status(400)
            .json({
              success: false,
              error:
                "Alibaba baseUrl is required"
            });
        }

        console.log(
          "[Alibaba /ai/chat]",
          {
            model:
              String(model),
            fields:
              Object.keys(
                providerBody
              )
          }
        );

        const result =
          await callAlibaba(
            config,
            "/chat/completions",
            providerBody
          );

        if (!result.ok) {
          return res
            .status(
              result.status
            )
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
          provider:
            "alibaba",
          model,
          response:
            result.body
        });
      }

      if (
        provider ===
        "openai"
      ) {
        console.log(
          "[OpenAI /ai/chat]",
          {
            model:
              String(model),
            fields:
              Object.keys(
                providerBody
              )
          }
        );

        const result =
          await callOpenAI(
            config,
            "/chat/completions",
            {
              body:
                providerBody
            }
          );

        if (!result.ok) {
          return res
            .status(
              result.status
            )
            .json({
              success: false,
              provider:
                "openai",
              model,
              error:
                "OpenAI AI request failed",
              details:
                result.body
            });
        }

        return res.json({
          success: true,
          provider:
            "openai",
          model,
          response:
            result.body
        });
      }

      return res
        .status(400)
        .json({
          success: false,
          error:
            "Unsupported AI provider"
        });
    } catch (error) {
      console.error(
        "AI chat error:",
        error.message
      );

      return res
        .status(500)
        .json({
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
    error:
      "Endpoint not found"
  });
});

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `NodeSend listening on 0.0.0.0:${PORT}`
    );

    console.log(
      "[NodeSend]",
      {
        version:
          "bridge-encrypted-credentials-v1",

        encryptionConfigured:
          Boolean(
            NODESEND_PRIVATE_KEY_PEM
          ),

        plaintextAIKeysAllowed:
          ALLOW_PLAINTEXT_AI_KEYS
      }
    );
  }
);
