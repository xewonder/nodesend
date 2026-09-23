/**
 * NodeSend / BridgeMind relay — bridge.js
 *
 * Preserves the existing /send, /rocketchat, /ai/models, /ai/test and /ai/chat
 * request/response contracts. Adds cancellable AI upstream requests,
 * sanitized request-level timing and an optional authoritative /quota adapter.
 *
 * Runtime: Node.js >= 18 (native fetch, AbortController).
 * Dependencies: express, cors, nodemailer.
 *
 * IMPORTANT QUOTA CONTRACT:
 * There is no inferred/estimated provider balance here. To make /quota work,
 * configure NODESEND_QUOTA_URL as a trusted HTTPS service returning:
 *   {"available":true,"remaining":123,"limit":1000,"unit":"credits",
 *    "resetAt":"2026-10-01T00:00:00Z","scope":"server-account"}
 * NODESEND_QUOTA_BEARER_TOKEN is an optional server-side credential.
 * If absent, unreachable or malformed, /quota fails closed with HTTP 503.
 * An account-specific balance must not be used as proof of another user's quota.
 */

"use strict";

const express = require("express");
const cors = require("cors");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const app = express();
app.use(cors({ exposedHeaders: ["X-Request-Id", "Server-Timing"] }));
app.use(express.json({ limit: "1mb" }));

const PORT = Number(process.env.PORT || 3001);
const BRIDGE_API_KEY = process.env.BRIDGE_API_KEY || "";
const ROCKETCHAT_WEBHOOK_URL = process.env.ROCKETCHAT_WEBHOOK_URL || "";
const OPENAI_BASE_URL = "https://api.openai.com/v1";
const NODESEND_VERSION = "bridge-cancel-timing-quota-v3";
const ALLOW_PLAINTEXT_AI_KEYS =
  String(process.env.ALLOW_PLAINTEXT_AI_KEYS || "false").toLowerCase() === "true";

// Separate upstream timeout, not a generation-parameter override.
// Set higher than BridgeMind's own client timeout when desired; the disconnect
// handler should abort earlier if the proxy conveys the client's disconnect.
const UPSTREAM_TIMEOUT_MS = boundedInt(
  process.env.NODESEND_UPSTREAM_TIMEOUT_MS,
  90000, 1000, 600000
);
const QUOTA_TIMEOUT_MS = boundedInt(
  process.env.NODESEND_QUOTA_TIMEOUT_MS,
  5000, 500, 30000
);
const NODESEND_QUOTA_URL = String(process.env.NODESEND_QUOTA_URL || "").trim();
const NODESEND_QUOTA_BEARER_TOKEN = process.env.NODESEND_QUOTA_BEARER_TOKEN || "";
const PRIVATE_KEY_B64 = String(process.env.NODESEND_PRIVATE_KEY_B64 || "").trim();
const PRIVATE_KEY_PEM_RAW = String(process.env.NODESEND_PRIVATE_KEY_PEM || "").trim();

const ALIBABA_ALLOWED_HOSTS = String(process.env.ALIBABA_ALLOWED_HOSTS || "")
  .split(",").map(x => x.trim().toLowerCase()).filter(Boolean);

const ALIBABA_TOKEN_PLAN_MODELS = [
  { id: "qwen3.8-flash", name: "Qwen 3.8 Flash" },
  { id: "qwen3.8-max", name: "Qwen 3.8 Max" }
];

function boundedInt(value, fallback, min, max) {
  const n = Number(value);
  return Number.isSafeInteger(n) && n >= min && n <= max ? n : fallback;
}

function requireApiKey(req, res, next) {
  if (!BRIDGE_API_KEY) {
    return res.status(500).json({ success: false, error: "BRIDGE_API_KEY is not configured" });
  }
  const supplied = req.get("x-api-key") || "";
  const a = Buffer.from(supplied);
  const b = Buffer.from(BRIDGE_API_KEY);
  if (!a.length || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).json({ success: false, error: "Forbidden" });
  }
  next();
}

function loadPrivateKeyPem() {
  if (PRIVATE_KEY_B64) {
    const pem = Buffer.from(PRIVATE_KEY_B64, "base64").toString("utf8").trim();
    if (!pem.includes("-----BEGIN") || !pem.includes("PRIVATE KEY-----")) {
      throw new Error("NODESEND_PRIVATE_KEY_B64 does not decode to a private PEM key");
    }
    return pem;
  }
  return PRIVATE_KEY_PEM_RAW.replace(/\\n/g, "\n").trim();
}

function getNodeSendPrivateKey() {
  const pem = loadPrivateKeyPem();
  if (!pem) throw new Error("NodeSend RSA private key is not configured");
  try { return crypto.createPrivateKey({ key: pem, format: "pem" }); }
  catch { throw new Error("NodeSend RSA private key is invalid"); }
}

function isEncryptionConfigured() {
  try { crypto.createPublicKey(getNodeSendPrivateKey()); return true; }
  catch { return false; }
}

function decryptProviderApiKey(encryptedApiKey) {
  if (typeof encryptedApiKey !== "string" || !encryptedApiKey.trim()) {
    throw new Error("encryptedApiKey is required");
  }
  // Buffer.from(..., 'base64') is permissive. Reject malformed ciphertext.
  const encoded = encryptedApiKey.trim();
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    throw new Error("encryptedApiKey is not valid base64");
  }
  let plaintext;
  try {
    plaintext = crypto.privateDecrypt({
      key: getNodeSendPrivateKey(),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256"
    }, Buffer.from(encoded, "base64"));
  } catch {
    throw new Error("Provider API key decryption failed");
  }
  const apiKey = plaintext.toString("utf8").trim();
  if (!apiKey) throw new Error("Decrypted provider API key is empty");
  return apiKey;
}

function resolveProviderApiKey(config) {
  if (config?.encryptedApiKey) return decryptProviderApiKey(config.encryptedApiKey);
  if (config?.apiKey && ALLOW_PLAINTEXT_AI_KEYS) {
    const key = String(config.apiKey).trim();
    if (!key) throw new Error("Plaintext AI provider API key is empty");
    console.warn("[NodeSend] Legacy plaintext provider key received (never logged)");
    return key;
  }
  if (config?.apiKey) {
    throw new Error("Plaintext AI provider API keys are disabled. Send config.encryptedApiKey.");
  }
  throw new Error("AI provider API key is required");
}

function isAllowedAlibabaBaseUrl(baseUrl) {
  try {
    const url = new URL(baseUrl);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) return false;
    const hostname = url.hostname.toLowerCase();
    if (ALIBABA_ALLOWED_HOSTS.length) return ALIBABA_ALLOWED_HOSTS.includes(hostname);
    return hostname.endsWith(".maas.aliyuncs.com") || [
      "dashscope-intl.aliyuncs.com",
      "dashscope.aliyuncs.com",
      "dashscope-us.aliyuncs.com",
      "cn-hongkong.dashscope.aliyuncs.com"
    ].includes(hostname);
  } catch { return false; }
}

function providerEndpoint(provider, config, path) {
  if (provider === "openai") return `${OPENAI_BASE_URL}${path}`;
  if (provider !== "alibaba") throw Object.assign(new Error("Unsupported AI provider"), { status: 400 });
  const baseUrl = String(config?.baseUrl || "").trim().replace(/\/+$/, "");
  if (!baseUrl) throw Object.assign(new Error("Alibaba baseUrl is required"), { status: 400 });
  if (!isAllowedAlibabaBaseUrl(baseUrl)) {
    throw Object.assign(new Error("Alibaba base URL is not allowed"), { status: 400 });
  }
  return `${baseUrl}${path}`;
}

// Only the NodeSend routing envelope is removed. No temperature, token, or
// reasoning settings are invented or rewritten by this relay.
function buildProviderBody(input = {}) {
  const { provider, config, ...providerBody } = input;
  return providerBody;
}

function requestIdentity(req, res) {
  // New ID per NodeSend HTTP attempt, even when the caller retries using the
  // same client correlation ID. The caller may log both for reconciliation.
  const id = crypto.randomUUID();
  res.setHeader("X-Request-Id", id);
  return id;
}

function safeEvent(name, data) {
  // Callers must provide only whitelisted scalar metadata, never bodies,
  // messages, keys, prompts, hidden hands or upstream errors verbatim.
  console.info(`[NodeSend] ${name}`, JSON.stringify(data));
}

function requestLifecycle(req, res, requestId) {
  const started = performance.now();
  const controller = new AbortController();
  let cause = null;
  const disconnect = () => {
    if (!res.writableEnded && !controller.signal.aborted) {
      cause = "client_disconnected";
      controller.abort(new Error(cause));
      safeEvent("client_disconnected", { requestId, elapsedMs: Math.round(performance.now() - started) });
    }
  };
  res.once("close", disconnect);
  req.once("aborted", disconnect);
  const timer = setTimeout(() => {
    if (!controller.signal.aborted) {
      cause = "upstream_timeout";
      controller.abort(new Error(cause));
    }
  }, UPSTREAM_TIMEOUT_MS);
  timer.unref?.();
  return {
    signal: controller.signal,
    get cause() { return cause; },
    elapsed() { return performance.now() - started; },
    dispose() {
      clearTimeout(timer);
      res.off("close", disconnect);
      req.off("aborted", disconnect);
    }
  };
}

function timeHeader({ upstreamHeadersMs, upstreamBodyMs, relayTotalMs }) {
  const entries = [];
  const add = (name, value) => {
    if (Number.isFinite(value) && value >= 0) entries.push(`${name};dur=${value.toFixed(1)}`);
  };
  add("upstream_headers", upstreamHeadersMs);
  add("upstream_body", upstreamBodyMs);
  add("relay_total", relayTotalMs);
  return entries.join(", ");
}

async function requestProvider({ provider, config, path, method = "POST", body, lifecycle, requestId }) {
  const url = providerEndpoint(provider, config, path);
  const apiKey = resolveProviderApiKey(config);
  const sentAt = performance.now();
  const sanitized = {
    requestId, provider, method, path,
    requestBytes: body === undefined ? 0 : Buffer.byteLength(JSON.stringify(body)),
    messageCount: Array.isArray(body?.messages) ? body.messages.length : 0,
    model: typeof body?.model === "string" && /^[A-Za-z0-9_.-]{1,80}$/.test(body.model)
      ? body.model : null,
    generationSettings: {
      hasMaxTokens: body?.max_tokens !== undefined,
      hasMaxCompletionTokens: body?.max_completion_tokens !== undefined,
      reasoningEffort: ["none", "minimal", "low", "medium", "high", "xhigh"]
        .includes(body?.reasoning_effort) ? body.reasoning_effort : null,
      enableThinking: typeof body?.enable_thinking === "boolean" ? body.enable_thinking : null
    }
  };
  safeEvent("upstream_start", sanitized);
  const response = await fetch(url, {
    method,
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: lifecycle.signal
  });
  const headersAt = performance.now();
  // Signal stays attached while the body is being received/decoded.
  const raw = await response.text();
  const bodyAt = performance.now();
  let parsed;
  try { parsed = JSON.parse(raw); } catch { parsed = raw; }
  const metrics = {
    upstreamHeadersMs: headersAt - sentAt,
    upstreamBodyMs: bodyAt - headersAt,
    // Relay total is finalized immediately before writing the outer response.
    relayTotalMs: lifecycle.elapsed()
  };
  safeEvent("upstream_complete", {
    requestId, provider, status: response.status,
    upstreamHeadersMs: Math.round(metrics.upstreamHeadersMs),
    upstreamBodyMs: Math.round(metrics.upstreamBodyMs),
    relayElapsedMs: Math.round(metrics.relayTotalMs),
    usagePresent: Boolean(parsed && typeof parsed === "object" && parsed.usage)
  });
  return { ok: response.ok, status: response.status, body: parsed, metrics };
}

async function relayAI(req, res, operation) {
  const requestId = requestIdentity(req, res);
  const lifecycle = requestLifecycle(req, res, requestId);
  try {
    const input = req.body || {};
    const { provider, config, model, messages } = input;
    if (!["alibaba", "openai"].includes(provider)) {
      return res.status(400).json({ success: false, error: "Unsupported AI provider", requestId });
    }
    let result;
    if (operation === "models") {
      if (provider === "alibaba") {
        return res.json({
          success: true, provider: "alibaba", source: "local-token-plan-list",
          models: ALIBABA_TOKEN_PLAN_MODELS
        });
      }
      result = await requestProvider({
        provider, config, path: "/models", method: "GET", lifecycle, requestId
      });
      if (!result.ok) {
        res.setHeader("Server-Timing", timeHeader({ ...result.metrics, relayTotalMs: lifecycle.elapsed() }));
        return res.status(result.status).json({
          success: false, provider, error: "OpenAI model discovery failed", details: result.body
        });
      }
      const models = Array.isArray(result.body?.data)
        ? result.body.data.filter(x => x?.id).map(x => ({
          id: x.id, name: x.id, created: x.created || null, ownedBy: x.owned_by || null
        })).sort((a, b) => a.id.localeCompare(b.id)) : [];
      res.setHeader("Server-Timing", timeHeader({ ...result.metrics, relayTotalMs: lifecycle.elapsed() }));
      return res.json({ success: true, provider: "openai", source: "openai-api", total: models.length, models });
    }
    if (typeof model !== "string" || !model.trim()) {
      return res.status(400).json({ success: false, error: "model is required" });
    }
    let providerBody;
    if (operation === "test") {
      providerBody = buildProviderBody(input);
      delete providerBody.model;
      delete providerBody.messages;
      providerBody = {
        model, messages: [{ role: "user", content: "Reply only with OK" }], ...providerBody
      };
    } else {
      if (!Array.isArray(messages) || messages.length === 0 || messages.length > 100) {
        return res.status(400).json({ success: false, error: "messages must contain 1–100 entries" });
      }
      providerBody = buildProviderBody(input);
      providerBody.model = model;
      providerBody.messages = messages;
    }
    result = await requestProvider({
      provider, config,
      path: "/chat/completions", body: providerBody, lifecycle, requestId
    });
    // Browser callers can inspect these headers if the request completes.
    res.setHeader("Server-Timing", timeHeader({ ...result.metrics, relayTotalMs: lifecycle.elapsed() }));
    if (!result.ok) {
      return res.status(result.status).json({
        success: false, provider, model,
        error: `${provider === "alibaba" ? "Alibaba" : "OpenAI"} ${operation === "test" ? "model test" : "AI request"} failed`,
        details: result.body
      });
    }
    if (operation === "test") {
      return res.json({
        success: true, provider, model, response: result.body?.choices?.[0]?.message?.content ?? null
      });
    }
    // Complete provider body is preserved, including usage when supplied.
    return res.json({ success: true, provider, model, response: result.body });
  } catch (error) {
    if (lifecycle.cause === "client_disconnected" || res.destroyed) {
      // There is no connected caller left to receive a JSON response.
      return;
    }
    const timeout = lifecycle.cause === "upstream_timeout";
    const invalid = error?.status === 400 || (/required|disabled|invalid|decryption|not allowed|not configured/i).test(error?.message || "");
    safeEvent("request_failed", {
      requestId, operation, provider: req.body?.provider || null,
      cause: timeout ? "upstream_timeout" : invalid ? "validation" : "upstream_or_network_error",
      elapsedMs: Math.round(lifecycle.elapsed())
    });
    if (res.headersSent) return;
    return res.status(timeout ? 504 : invalid ? 400 : 502).json({
      success: false,
      error: timeout ? "NodeSend upstream timeout" : invalid ? error.message : "AI upstream request failed",
      code: timeout ? "UPSTREAM_TIMEOUT" : invalid ? "INVALID_REQUEST" : "UPSTREAM_ERROR",
      requestId
    });
  } finally {
    lifecycle.dispose();
  }
}

// /quota is a verified-service adapter, NOT a made-up credit counter.
// Both GET and POST are supported; client-supplied provider credentials are
// neither required nor forwarded. Every lookup is fresh, without a cache.
async function quotaHandler(req, res) {
  const requestId = requestIdentity(req, res);
  if (!NODESEND_QUOTA_URL) {
    return res.status(503).json({
      success: false, available: false, code: "QUOTA_SERVICE_UNAVAILABLE",
      error: "An authoritative quota service is not configured", requestId
    });
  }
  let quotaUrl;
  try {
    quotaUrl = new URL(NODESEND_QUOTA_URL);
    if (quotaUrl.protocol !== "https:" || quotaUrl.username || quotaUrl.password || quotaUrl.hash) {
      throw new Error("Invalid quota URL");
    }
  } catch {
    return res.status(503).json({ success: false, available: false,
      code: "QUOTA_SERVICE_UNAVAILABLE", requestId });
  }
  const started = performance.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), QUOTA_TIMEOUT_MS);
  timer.unref?.();
  const disconnect = () => { if (!res.writableEnded) controller.abort(); };
  res.once("close", disconnect);
  try {
    const headers = { Accept: "application/json" };
    if (NODESEND_QUOTA_BEARER_TOKEN) {
      headers.Authorization = `Bearer ${NODESEND_QUOTA_BEARER_TOKEN}`;
    }
    const upstream = await fetch(quotaUrl.href, { method: "GET", headers, signal: controller.signal });
    if (!upstream.ok) throw new Error("Quota service returned a non-success response");
    const data = await upstream.json();
    if (!data || typeof data !== "object" ||
        typeof data.available !== "boolean" ||
        (data.remaining !== undefined && (!Number.isFinite(data.remaining) || data.remaining < 0)) ||
        (data.limit !== undefined && (!Number.isFinite(data.limit) || data.limit < 0))) {
      throw new Error("Quota response does not meet contract");
    }
    if (data.available === false || data.remaining === 0) {
      res.setHeader("Server-Timing", timeHeader({ relayTotalMs: performance.now() - started }));
      return res.status(429).json({
        success: false, available: false, code: "QUOTA_EXHAUSTED", requestId,
        ...(Number.isFinite(data.remaining) ? { remaining: data.remaining } : {}),
        ...(typeof data.resetAt === "string" ? { resetAt: data.resetAt } : {})
      });
    }
    if (data.remaining === undefined) {
      // A mere 'available' boolean alone is not enough to enforce a numerical
      // limit for every app. Return the availability without inventing balance.
      safeEvent("quota_available_without_balance", { requestId });
    }
    const result = {
      success: true, available: true, source: "configured-authoritative-quota-service",
      requestId,
      ...(Number.isFinite(data.remaining) ? { remaining: data.remaining } : {}),
      ...(Number.isFinite(data.limit) ? { limit: data.limit } : {}),
      ...(typeof data.unit === "string" ? { unit: data.unit } : {}),
      ...(typeof data.resetAt === "string" ? { resetAt: data.resetAt } : {}),
      ...(typeof data.scope === "string" ? { scope: data.scope } : {})
    };
    res.setHeader("Server-Timing", timeHeader({ relayTotalMs: performance.now() - started }));
    safeEvent("quota_checked", { requestId, available: true, elapsedMs: Math.round(performance.now() - started) });
    return res.json(result);
  } catch {
    safeEvent("quota_unavailable", { requestId, elapsedMs: Math.round(performance.now() - started) });
    if (res.destroyed) return;
    return res.status(503).json({
      success: false, available: false, code: "QUOTA_SERVICE_UNAVAILABLE",
      error: "Quota could not be verified", requestId
    });
  } finally {
    clearTimeout(timer);
    res.off("close", disconnect);
  }
}

app.get("/", (req, res) => res.json({
  success: true, service: "NodeSend", version: NODESEND_VERSION,
  endpoints: {
    health: "GET /health", publicKey: "GET /crypto/public-key",
    email: "POST /send", rocketchat: "POST /rocketchat",
    aiModels: "POST /ai/models", aiTest: "POST /ai/test",
    aiChat: "POST /ai/chat", quota: "GET|POST /quota"
  }, providers: ["alibaba", "openai"]
}));

app.get("/health", (req, res) => res.json({
  success: true, service: "NodeSend", version: NODESEND_VERSION,
  status: "healthy", encryptionConfigured: isEncryptionConfigured(),
  privateKeySource: PRIVATE_KEY_B64 ? "base64" : PRIVATE_KEY_PEM_RAW ? "pem" : "none",
  plaintextAIKeysAllowed: ALLOW_PLAINTEXT_AI_KEYS,
  rocketchatConfigured: Boolean(ROCKETCHAT_WEBHOOK_URL),
  aiProxyConfigured: true, quotaConfigured: Boolean(NODESEND_QUOTA_URL),
  providers: { alibaba: true, openai: true }
}));

// Public RSA key is intentionally accessible without the private x-api-key.
app.get("/crypto/public-key", (req, res) => {
  try {
    const publicKey = crypto.createPublicKey(getNodeSendPrivateKey()).export({
      type: "spki", format: "pem"
    });
    return res.json({
      success: true, algorithm: "RSA-OAEP", hash: "SHA-256", encoding: "PEM-SPKI", publicKey
    });
  } catch {
    return res.status(500).json({ success: false, error: "NodeSend encryption is not configured" });
  }
});

// Existing SMTP contract preserved; AI-key encryption does not affect SMTP.
app.post("/send", requireApiKey, async (req, res) => {
  try {
    const { config, email } = req.body || {};
    if (!config || !email) {
      return res.status(400).json({ success: false, error: "Both config and email are required" });
    }
    const host = String(config.host || "").trim();
    const port = Number(config.port);
    const username = String(config.username || "").trim();
    const password = String(config.password || "");
    const from = String(email.from || "").trim();
    const to = email.to;
    const subject = String(email.subject || "");
    if (!host || !port || !username || !password) {
      return res.status(400).json({ success: false,
        error: "SMTP host, port, username and password are required" });
    }
    if (!from || !to || !subject) {
      return res.status(400).json({ success: false, error: "Email from, to and subject are required" });
    }
    if (!email.text && !email.html) {
      return res.status(400).json({ success: false, error: "Email text or html content is required" });
    }
    const transporter = nodemailer.createTransport({
      host, port, secure: port === 465, auth: { user: username, pass: password }
    });
    await transporter.verify();
    const sent = await transporter.sendMail({
      from, to, cc: email.cc, bcc: email.bcc,
      subject, text: email.text, html: email.html
    });
    return res.json({
      success: true, messageId: sent.messageId,
      accepted: sent.accepted, rejected: sent.rejected
    });
  } catch (error) {
    // Existing SMTP response contract; do not log passwords/config/body.
    console.error("[NodeSend] SMTP request failed", error?.name || "Error");
    return res.status(500).json({ success: false, error: "Email could not be sent" });
  }
});

app.post("/rocketchat", requireApiKey, async (req, res) => {
  if (!ROCKETCHAT_WEBHOOK_URL) {
    return res.status(500).json({ success: false,
      error: "ROCKETCHAT_WEBHOOK_URL is not configured" });
  }
  const { text, channel, username, emoji, avatar, alias, attachments } = req.body || {};
  if (!text) return res.status(400).json({ success: false, error: "text is required" });
  const payload = { text };
  for (const [key, value] of Object.entries({ channel, username, emoji, avatar, alias, attachments })) {
    if (value) payload[key] = value;
  }
  try {
    const upstream = await fetch(ROCKETCHAT_WEBHOOK_URL, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const raw = await upstream.text();
    let parsed;
    try { parsed = JSON.parse(raw); } catch { parsed = raw; }
    if (!upstream.ok) return res.status(upstream.status).json({
      success: false, error: "Rocket.Chat rejected the request", details: parsed
    });
    return res.json({ success: true, rocketchat: parsed });
  } catch {
    return res.status(500).json({ success: false, error: "Rocket.Chat message could not be sent" });
  }
});

app.post("/ai/models", requireApiKey, (req, res) => relayAI(req, res, "models"));
app.post("/ai/test", requireApiKey, (req, res) => relayAI(req, res, "test"));
app.post("/ai/chat", requireApiKey, (req, res) => relayAI(req, res, "chat"));
app.get("/quota", requireApiKey, quotaHandler);
app.post("/quota", requireApiKey, quotaHandler);

app.use((req, res) => res.status(404).json({ success: false, error: "Endpoint not found" }));

if (require.main === module) {
  app.listen(PORT, "0.0.0.0", () => {
    safeEvent("startup", {
      version: NODESEND_VERSION, port: PORT,
      encryptionConfigured: isEncryptionConfigured(),
      privateKeySource: PRIVATE_KEY_B64 ? "base64" : PRIVATE_KEY_PEM_RAW ? "pem" : "none",
      plaintextAIKeysAllowed: ALLOW_PLAINTEXT_AI_KEYS,
      quotaConfigured: Boolean(NODESEND_QUOTA_URL)
    });
  });
}

// Exported to permit local mock-provider/disconnect tests without binding a port.
module.exports = {
  app, requestLifecycle, timeHeader, isAllowedAlibabaBaseUrl,
  buildProviderBody, NODESEND_VERSION
};
