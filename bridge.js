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
 * ========================================================
 * NODESEND VERSION
 * ========================================================
 */

const NODESEND_VERSION =
  "bridge-encrypted-credentials-v2";

/**
 * ========================================================
 * AI CREDENTIAL ENCRYPTION CONFIGURATION
 * ========================================================
 *
 * Preferred:
 *
 * NODESEND_PRIVATE_KEY_B64
 *
 * This should contain the BASE64 encoding of the entire
 * RSA private PEM file.
 *
 * Example generation:
 *
 * Linux:
 *
 * base64 -w 0 nodesend-private.pem
 *
 * macOS:
 *
 * base64 < nodesend-private.pem | tr -d '\n'
 *
 *
 * Legacy fallback:
 *
 * NODESEND_PRIVATE_KEY_PEM
 *
 * This supports either:
 *
 * - real multiline PEM
 * - literal \n sequences
 *
 * B64 takes priority when both exist.
 */

const NODESEND_PRIVATE_KEY_B64 = String(
  process.env.NODESEND_PRIVATE_KEY_B64 || ""
).trim();

const NODESEND_PRIVATE_KEY_PEM_RAW = String(
  process.env.NODESEND_PRIVATE_KEY_PEM || ""
).trim();

/**
 * Decode the configured private key.
 */
function loadPrivateKeyPem() {
  if (NODESEND_PRIVATE_KEY_B64) {
    try {
      const pem = Buffer.from(
        NODESEND_PRIVATE_KEY_B64,
        "base64"
      )
        .toString("utf8")
        .trim();

      if (!pem) {
        throw new Error(
          "Decoded private key is empty"
        );
      }

      return pem;
    } catch (error) {
      console.error(
        "[NodeSend] Failed to decode NODESEND_PRIVATE_KEY_B64:",
        error.message
      );

      return "";
    }
  }

  if (NODESEND_PRIVATE_KEY_PEM_RAW) {
    return NODESEND_PRIVATE_KEY_PEM_RAW
      .replace(/\\n/g, "\n")
      .trim();
  }

  return "";
}

const NODESEND_PRIVATE_KEY_PEM =
  loadPrivateKeyPem();

/**
 * Temporary migration switch.
 *
 * true:
 * NodeSend can temporarily accept config.apiKey
 *
 * false:
 * NodeSend accepts only config.encryptedApiKey
 *
 * After Greta/BridgeMind has been migrated successfully,
 * set this to false in Coolify.
 *
 * IMPORTANT:
 * This affects AI provider keys ONLY.
 * SMTP email passwords are completely separate.
 */
const ALLOW_PLAINTEXT_AI_KEYS =
  String(
    process.env.ALLOW_PLAINTEXT_AI_KEYS ||
      "false"
  ).toLowerCase() === "true";

/**
 * ========================================================
 * ALIBABA MODEL DISCOVERY
 * ========================================================
 *
 * BridgeMind may use its database catalog as the
 * authoritative model list.
 *
 * This list remains for the existing NodeSend
 * Alibaba /ai/models behavior.
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
 * ========================================================
 * AUTHENTICATION
 * ========================================================
 */

/**
 * Validate BridgeMind -> NodeSend x-api-key.
 */
function requireApiKey(req, res, next) {
  const providedKey =
    req.get("x-api-key");

  if (!BRIDGE_API_KEY) {
    return res.status(500).json({
      success: false,
      error:
        "BRIDGE_API_KEY is not configured"
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
 * ========================================================
 * COMMON HELPERS
 * ========================================================
 */

function sanitizeBaseUrl(value) {
  return String(value || "")
    .trim()
    .replace(/\/+$/, "");
}

/**
 * Restrict Alibaba proxy calls to known Alibaba /
 * DashScope hosts.
 */
function isAllowedAlibabaBaseUrl(
  baseUrl
) {
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
 * Parse provider HTTP response safely.
 */
async function parseResponse(
  response
) {
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
 * Remove NodeSend-only envelope fields.
 *
 * Everything else is passed to the provider unchanged.
 *
 * NodeSend does NOT invent or normalize:
 *
 * reasoning_effort
 * max_tokens
 * max_completion_tokens
 * temperature
 * enable_thinking
 * top_p
 * verbosity
 * etc.
 *
 * BridgeMind owns AI request policy.
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
 * ========================================================
 * RSA KEY HELPERS
 * ========================================================
 */

/**
 * Parse and validate the configured RSA private key.
 */
function getNodeSendPrivateKey() {
  if (!NODESEND_PRIVATE_KEY_PEM) {
    throw new Error(
      "NodeSend RSA private key is not configured"
    );
  }

  try {
    return crypto.createPrivateKey({
      key:
        NODESEND_PRIVATE_KEY_PEM,
      format: "pem"
    });
  } catch (error) {
    throw new Error(
      `NodeSend RSA private key is invalid: ${error.message}`
    );
  }
}

/**
 * Derive the corresponding PUBLIC key from the
 * PRIVATE key stored in Coolify.
 *
 * The public key is safe to expose.
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
 * Check whether RSA encryption is correctly configured.
 */
function isEncryptionConfigured() {
  try {
    const privateKey =
      getNodeSendPrivateKey();

    crypto.createPublicKey(
      privateKey
    );

    return true;
  } catch {
    return false;
  }
}

/**
 * Decrypt a provider API key encrypted by the browser.
 *
 * Browser must use:
 *
 * RSA-OAEP
 * SHA-256
 *
 * Ciphertext transport:
 *
 * Base64
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
    encryptedBuffer =
      Buffer.from(
        String(
          encryptedApiKey
        ).trim(),
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
 * Resolve provider credential.
 *
 * Preferred:
 *
 * config.encryptedApiKey
 *
 * Migration-only fallback:
 *
 * config.apiKey
 */
function resolveProviderApiKey(
  config
) {
  if (
    config?.encryptedApiKey
  ) {
    return decryptProviderApiKey(
      config.encryptedApiKey
    );
  }

  if (
    config?.apiKey &&
    ALLOW_PLAINTEXT_AI_KEYS
  ) {
    console.warn(
      "[SECURITY] Legacy plaintext AI provider key received"
    );

    const apiKey =
      String(
        config.apiKey
      ).trim();

    if (!apiKey) {
      throw new Error(
        "Plaintext AI provider API key is empty"
      );
    }

    return apiKey;
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
 * ========================================================
 * ALIBABA PROVIDER
 * ========================================================
 */

async function callAlibaba(
  config,
  path,
  body
) {
  const apiKey =
    resolveProviderApiKey(
      config
    );

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

  const startedAt =
    Date.now();

  console.log(
    "[Alibaba fetch started]",
    {
      path,
      fields:
        body &&
        typeof body ===
          "object"
          ? Object.keys(body)
          : []
    }
  );

  try {
    const response =
      await fetch(
        `${baseUrl}${path}`,
        {
          method: "POST",
          headers: {
            Authorization:
              `Bearer ${apiKey}`,
            "Content-Type":
              "application/json"
          },
          body:
            JSON.stringify(body)
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
 * ========================================================
 * OPENAI PROVIDER
 * ========================================================
 */

async function callOpenAI(
  config,
  path,
  options = {}
) {
  const apiKey =
    resolveProviderApiKey(
      config
    );

  const startedAt =
    Date.now();

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
    const response =
      await fetch(
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
 * ========================================================
 * ROOT
 * ========================================================
 */

app.get(
  "/",
  (req, res) => {
    res.json({
      success: true,
      service: "NodeSend",
      version:
        NODESEND_VERSION,

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
  }
);

/**
 * ========================================================
 * HEALTH
 * ========================================================
 */

app.get(
  "/health",
  (req, res) => {
    res.json({
      success: true,

      service:
        "NodeSend",

      version:
        NODESEND_VERSION,

      status:
        "healthy",

      encryptionConfigured:
        isEncryptionConfigured(),

      privateKeySource:
        NODESEND_PRIVATE_KEY_B64
          ? "base64"
          : NODESEND_PRIVATE_KEY_PEM_RAW
            ? "pem"
            : "none",

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
 * ========================================================
 * PUBLIC RSA KEY
 * ========================================================
 *
 * Public key intentionally does NOT require x-api-key.
 *
 * It is public by definition.
 *
 * Browser uses it to encrypt provider credentials.
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

        hash:
          "SHA-256",

        encoding:
          "PEM-SPKI",

        publicKey
      });
    } catch (error) {
      console.error(
        "[NodeSend public key error]",
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
 * EMAIL HAS NOT BEEN CHANGED.
 *
 * SMTP still uses:
 *
 * config.host
 * config.port
 * config.username
 * config.password
 *
 * AI encryption does NOT touch this endpoint.
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
          config.username ||
            ""
        ).trim();

      const password =
        String(
          config.password ||
            ""
        );

      const from =
        String(
          email.from || ""
        ).trim();

      const to =
        email.to;

      const subject =
        String(
          email.subject ||
            ""
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
        nodemailer.createTransport({
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
        await transporter.sendMail({
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
 * Existing behavior unchanged.
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

      /**
       * Alibaba currently uses local discovery,
       * so provider credentials are not needed here.
       */
      if (
        provider ===
        "alibaba"
      ) {
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

      /**
       * OpenAI dynamically queries /v1/models.
       *
       * Credential is resolved/decrypted inside
       * callOpenAI().
       */
      if (
        provider ===
        "openai"
      ) {
        const result =
          await callOpenAI(
            config,
            "/models",
            {
              method: "GET"
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
 * AI TEST
 * ========================================================
 *
 * NodeSend adds only the small test message.
 *
 * Any optional provider parameters deliberately sent by
 * BridgeMind are passed through.
 *
 * NodeSend does NOT invent:
 *
 * reasoning_effort
 * max_tokens
 * max_completion_tokens
 * temperature
 * etc.
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

      const extraBody =
        buildProviderBody(
          req.body
        );

      /**
       * NodeSend owns these fields for the test.
       */
      delete extraBody.model;
      delete extraBody.messages;

      const body = {
        model:
          String(model),

        messages: [
          {
            role:
              "user",

            content:
              "Reply only with OK"
          }
        ],

        ...extraBody
      };

      /**
       * Alibaba
       */
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
              Object.keys(body)
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

      /**
       * OpenAI
       */
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
              Object.keys(body)
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
 * BridgeMind owns AI request policy.
 *
 * NodeSend owns:
 *
 * - BridgeMind authentication
 * - provider credential decryption
 * - provider routing
 * - HTTP transport
 * - returning provider responses
 *
 * NodeSend strips only:
 *
 * provider
 * config
 *
 * All other provider fields are passed through unchanged.
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

      const providerBody =
        buildProviderBody(
          req.body
        );

      providerBody.model =
        String(model);

      providerBody.messages =
        messages;

      /**
       * Alibaba
       */
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

      /**
       * OpenAI
       */
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
 * ========================================================
 * 404
 * ========================================================
 */

app.use(
  (req, res) => {
    res
      .status(404)
      .json({
        success: false,
        error:
          "Endpoint not found"
      });
  }
);

/**
 * ========================================================
 * START SERVER
 * ========================================================
 */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `NodeSend listening on 0.0.0.0:${PORT}`
    );

    console.log(
      "[NodeSend startup]",
      {
        version:
          NODESEND_VERSION,

        privateKeySource:
          NODESEND_PRIVATE_KEY_B64
            ? "base64"
            : NODESEND_PRIVATE_KEY_PEM_RAW
              ? "pem"
              : "none",

        encryptionConfigured:
          isEncryptionConfigured(),

        plaintextAIKeysAllowed:
          ALLOW_PLAINTEXT_AI_KEYS
      }
    );
  }
);
