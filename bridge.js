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
 * AI endpoints (/ai/models, /ai/test, /ai/chat, GET /ai/quota,
 * GET|PUT /ai/quota/config) are authenticated by the caller's BridgeMind Bearer
 * session, validated server-side against the NCB proxy (/auth/get-session). The
 * identity used for quota comes from that validated session, NEVER from a
 * user_id in the request body or query string. The counter itself lives in a
 * dedicated PostgreSQL (quota_config, quota_user_override, quota_usage) that
 * only NodeSend can reach, reserved atomically BEFORE the provider is contacted
 * by a single INSERT ... ON CONFLICT ... DO UPDATE ... WHERE guard; a denial or
 * an unreachable quota store returns 429/503 and the provider is not called.
 * NCB is no longer consulted for any ai_quota_* table.
 *
 * The two authorities are deliberately separate: the NCB session proves WHO the
 * caller is, Postgres proves HOW MANY calls they have left.
 *
 * GET|PUT /ai/quota/config additionally require the validated session's admin
 * role; an ordinary user gets 403 and no database detail is ever returned.
 *
 * The generic /quota adapter below is a SEPARATE surface: it is the
 * server-account adapter and still uses requireApiKey. It is not per-user quota.
 *
 * GENERIC SERVER-ACCOUNT /quota CONTRACT:
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
const NODESEND_VERSION = "bridge-postgres-quota-v5";
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

// BridgeMind session authority. AI endpoints are authenticated by the caller's
// BridgeMind Bearer session, validated here against NCB — never by a shared
// browser-visible key. These default to the same proxy/instance BridgeMind uses.
const NCB_PROXY_BASE = String(process.env.NCB_PROXY_BASE ||
  "https://rmvzorxcl35mttidiexhtp5g2m0hpsqo.lambda-url.us-east-2.on.aws").trim();
const NCB_INSTANCE = String(process.env.NCB_INSTANCE || "55954_bridgemind").trim();
const NCB_TIMEOUT_MS = boundedInt(process.env.NODESEND_NCB_TIMEOUT_MS, 8000, 500, 30000);

// Authoritative per-user quota storage. NCB proves WHO the caller is; this
// Postgres proves HOW MANY calls they have left, and is reachable only from
// NodeSend — that separation is what makes the quota unforgable. Either name is
// accepted; the quota-specific one wins. Never expose either as a VITE_* value.
const QUOTA_DATABASE_URL = String(
  process.env.BRIDGEMIND_QUOTA_DATABASE_URL || process.env.DATABASE_URL || ""
).trim();
const QUOTA_DB_TIMEOUT_MS = boundedInt(
  process.env.NODESEND_QUOTA_DB_TIMEOUT_MS, 5000, 250, 30000
);
const QUOTA_DB_POOL_MAX = boundedInt(
  process.env.NODESEND_QUOTA_DB_POOL_MAX, 5, 1, 50
);
const QUOTA_DB_RETRY_BACKOFF_MS = boundedInt(
  process.env.NODESEND_QUOTA_DB_RETRY_BACKOFF_MS, 5000, 250, 60000
);

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

function buildNcbUrl(path) {
  const url = new URL(path, NCB_PROXY_BASE);
  url.searchParams.set("Instance", NCB_INSTANCE);
  return url.toString();
}

function getBearerToken(req) {
  const authorization = req.get("authorization") || "";
  return authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
}

// NCB is called with the caller's own session token, exactly as the BridgeMind
// Express proxy does, so NCB's row-level rules still decide what that user may
// read or write. No service credential is invented here.
async function ncbRequest(req, path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), NCB_TIMEOUT_MS);
  timer.unref?.();
  try {
    return await fetch(buildNcbUrl(path), {
      ...options,
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${getBearerToken(req)}`,
        ...options.headers
      },
      signal: controller.signal
    });
  } finally {
    clearTimeout(timer);
  }
}

// Resolves the owner of the presented session. The token itself is never
// logged, and a user_id in the request body is never consulted.
async function resolveSessionUser(req) {
  if (!getBearerToken(req)) {
    return { ok: false, status: 401, code: "auth_error", error: "Authentication required" };
  }
  let response;
  try {
    response = await ncbRequest(req, "/auth/get-session");
  } catch {
    // Session authority unreachable is not the same as signed out: fail closed
    // with 503 so the client signs in again only when it is genuinely invalid.
    return {
      ok: false, status: 503, code: "session_service_unavailable",
      error: "Session could not be verified"
    };
  }
  const body = await response.json().catch(() => ({}));
  const user = response.ok ? (body?.data?.user || body?.user || null) : null;
  if (!user?.id) {
    return { ok: false, status: 401, code: "auth_error", error: "Authentication required" };
  }
  return { ok: true, userId: String(user.id), role: String(user.role || "") };
}

// Only the validated identity is attached; nothing else from the session is.
async function requireBridgeSession(req, res, next) {
  const requestId = requestIdentity(req, res);
  req.nodeSendRequestId = requestId;
  const resolved = await resolveSessionUser(req);
  if (!resolved.ok) {
    safeEvent("session_rejected", { requestId, code: resolved.code, status: resolved.status });
    return res.status(resolved.status).json({
      success: false, status: resolved.code, error: resolved.error, requestId
    });
  }
  req.bridgeUser = { id: resolved.userId, role: resolved.role };
  return next();
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
  // A session-guard id created before the handler is reused so one attempt logs
  // under one id rather than appearing as two unrelated requests.
  if (req.nodeSendRequestId) {
    res.setHeader("X-Request-Id", req.nodeSendRequestId);
    return req.nodeSendRequestId;
  }
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

async function requestProvider({ provider, config, resolvedApiKey, path, method = "POST", body, lifecycle, requestId }) {
  const url = providerEndpoint(provider, config, path);
  const apiKey = resolvedApiKey || resolveProviderApiKey(config);
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
    // Reservation order for /ai/chat: the provider credential is resolved and the
    // model validated BEFORE any quota is spent, so a request the provider would
    // simply reject costs the user nothing. A denied reservation returns here and
    // the provider is never contacted.
    let reservation = null;
    let resolvedApiKey = null;
    if (operation === "chat") {
      resolvedApiKey = resolveProviderApiKey(config);
      reservation = await reserveAiCall(req.bridgeUser?.id);
      if (!reservation.allowed) {
        const status = reservation.reason === "quota_service_unavailable" ? 503 : 429;
        safeEvent("quota_denied", {
          requestId, operation, reason: reservation.reason,
          // Identity only — never the bearer token that resolved it.
          userId: req.bridgeUser?.id || null,
          elapsedMs: Math.round(lifecycle.elapsed())
        });
        res.setHeader("Server-Timing", timeHeader({ relayTotalMs: lifecycle.elapsed() }));
        return res.status(status).json({
          success: false, status: reservation.reason, error: reservation.reason,
          quota: reservation.quota, requestId
        });
      }
    }

    result = await requestProvider({
      provider, config, resolvedApiKey,
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
    // The reservation summary rides alongside it so the client's quota badge
    // updates from the same authoritative response that granted the call.
    return res.json({
      success: true, provider, model, response: result.body,
      ...(reservation?.quota ? { quota: reservation.quota } : {})
    });
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

// ── BRIDGEMIND PER-USER MONTHLY QUOTA (Postgres-authoritative) ─────────────
// Identity comes from the validated NCB session; the counter comes from a
// Postgres that only NodeSend can reach, so neither half can be forged by the
// caller. Semantics carried over from BridgeMind: calendar-month UTC period
// key, per-user override > global default, quota disabled = unlimited, and
// fail CLOSED whenever the authoritative store cannot be read or written.
//
// There is no in-process mutex and no read-check-write any more. The increment
// and the limit test happen inside one UPSERT, under the lock Postgres takes on
// the row matched by the ON CONFLICT arbiter, so two NodeSend replicas cannot
// both push a user past a limit.
const QUOTA_MIN_CALL_LIMIT = 1;
const QUOTA_MAX_CALL_LIMIT = 100000;

// Idempotent and non-destructive: nothing here drops, truncates, deletes or
// recreates a table, so running the relay against live quota data is a no-op
// after the first time. The config row is seeded, never overwritten.
const QUOTA_SCHEMA_SQL = [
  `CREATE TABLE IF NOT EXISTS quota_config (
     id integer PRIMARY KEY CHECK (id = 1),
     quota_enabled boolean NOT NULL DEFAULT true,
     default_call_limit integer NOT NULL DEFAULT 100
       CHECK (default_call_limit BETWEEN 1 AND ${QUOTA_MAX_CALL_LIMIT}),
     period_type text NOT NULL DEFAULT 'monthly' CHECK (period_type = 'monthly'),
     updated_at timestamptz NOT NULL DEFAULT now()
   )`,
  `CREATE TABLE IF NOT EXISTS quota_user_override (
     user_id text PRIMARY KEY CHECK (user_id <> ''),
     enabled boolean NOT NULL DEFAULT true,
     call_limit integer NOT NULL CHECK (call_limit BETWEEN 1 AND ${QUOTA_MAX_CALL_LIMIT}),
     updated_at timestamptz NOT NULL DEFAULT now()
   )`,
  `CREATE TABLE IF NOT EXISTS quota_usage (
     id bigserial PRIMARY KEY,
     user_id text NOT NULL CHECK (user_id <> ''),
     period_key text NOT NULL CHECK (period_key ~ '^[0-9]{4}-(0[1-9]|1[0-2])$'),
     calls_used integer NOT NULL DEFAULT 0 CHECK (calls_used >= 0),
     applied_limit integer NOT NULL CHECK (applied_limit BETWEEN 1 AND ${QUOTA_MAX_CALL_LIMIT}),
     updated_at timestamptz NOT NULL DEFAULT now()
   )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS quota_usage_user_period_uk
     ON quota_usage (user_id, period_key)`,
  `INSERT INTO quota_config (id, quota_enabled, default_call_limit, period_type, updated_at)
     VALUES (1, true, 100, 'monthly', now())
     ON CONFLICT (id) DO NOTHING`
];

// The whole reservation is this one statement. `q` is the existing row and
// `EXCLUDED` the proposed one, so the guard is evaluated against the value the
// increment would produce, under the row lock. Zero rows back means the guard
// rejected it: the allowance is spent.
const RESERVE_QUOTA_SQL = `
  INSERT INTO quota_usage AS q (user_id, period_key, calls_used, applied_limit, updated_at)
  VALUES ($1::text, $2::text, 1, $3::integer, now())
  ON CONFLICT (user_id, period_key) DO UPDATE
    SET calls_used = q.calls_used + 1,
        applied_limit = EXCLUDED.applied_limit,
        updated_at = now()
    WHERE q.calls_used < EXCLUDED.applied_limit
  RETURNING q.calls_used AS calls_used, q.applied_limit AS applied_limit`;

const READ_QUOTA_USAGE_SQL =
  "SELECT calls_used FROM quota_usage WHERE user_id = $1::text AND period_key = $2::text";

// One round trip for the read surface: the config singleton, this user's
// override and this period's counter. A missing usage row is zero usage, not a
// missing user. The user id always comes from the validated session.
const READ_QUOTA_STATE_SQL = `
  SELECT c.quota_enabled, c.default_call_limit, c.period_type,
         o.enabled AS override_enabled, o.call_limit AS override_call_limit,
         u.calls_used AS calls_used
    FROM quota_config c
    LEFT JOIN quota_user_override o ON o.user_id = $1::text
    LEFT JOIN quota_usage u ON u.user_id = $1::text AND u.period_key = $2::text
   WHERE c.id = 1`;

const READ_QUOTA_CONFIG_SQL =
  "SELECT quota_enabled, default_call_limit, period_type, updated_at FROM quota_config WHERE id = 1";

const WRITE_QUOTA_CONFIG_SQL = `
  UPDATE quota_config
     SET quota_enabled = COALESCE($1::boolean, quota_enabled),
         default_call_limit = COALESCE($2::integer, default_call_limit),
         updated_at = now()
   WHERE id = 1
  RETURNING quota_enabled, default_call_limit, period_type, updated_at`;

let quotaPool = null;
let quotaBootstrap = null;
let quotaLastFailureAt = 0;
// The only thing ever reported about the store is this label. The connection
// string, its host, its user and its database name never leave the process.
let quotaStorageStatus = QUOTA_DATABASE_URL ? "pending" : "unconfigured";

function quotaStorageState() {
  return { configured: Boolean(QUOTA_DATABASE_URL), status: quotaStorageStatus };
}

// Lazily connects and applies the schema once. A store that cannot be reached
// yields null, which every quota caller fails closed on; a backoff keeps an
// outage from turning each AI request into a fresh DDL round trip.
async function ensureQuotaPool() {
  if (quotaStorageStatus === "ready") return quotaPool;
  if (!QUOTA_DATABASE_URL) {
    quotaStorageStatus = "unconfigured";
    return null;
  }
  if (quotaStorageStatus === "driver_missing") return null;
  if (quotaStorageStatus === "unreachable" &&
      Date.now() - quotaLastFailureAt < QUOTA_DB_RETRY_BACKOFF_MS) {
    return null;
  }
  if (!quotaPool) {
    let pg;
    try { pg = require("pg"); }
    catch {
      quotaStorageStatus = "driver_missing";
      return null;
    }
    quotaPool = new pg.Pool({
      connectionString: QUOTA_DATABASE_URL,
      max: QUOTA_DB_POOL_MAX,
      connectionTimeoutMillis: QUOTA_DB_TIMEOUT_MS,
      idleTimeoutMillis: 30000,
      statement_timeout: QUOTA_DB_TIMEOUT_MS
    });
    // A backend that dies and comes back must not poison the relay for good.
    quotaPool.on("error", () => {
      quotaStorageStatus = "unreachable";
      quotaLastFailureAt = Date.now();
      quotaBootstrap = null;
    });
  }
  if (!quotaBootstrap) {
    quotaBootstrap = (async () => {
      for (const statement of QUOTA_SCHEMA_SQL) await quotaPool.query(statement);
      quotaStorageStatus = "ready";
      return quotaPool;
    })().catch(() => {
      quotaStorageStatus = "unreachable";
      quotaLastFailureAt = Date.now();
      quotaBootstrap = null;
      return null;
    });
  }
  return quotaBootstrap;
}

function getCurrentPeriodKey(now = new Date()) {
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}

function getNextResetAt(periodKey) {
  const [y, m] = periodKey.split("-").map(Number);
  return new Date(Date.UTC(y, m, 1)).toISOString();
}

// The effective allowance for one user: an enabled per-user override beats the
// global default. Kept separate from the SQL so the precedence rule is testable
// without a database.
function resolveQuotaLimit(row) {
  const defaultLimit = Number(row.default_call_limit);
  if (row.override_enabled === true && Number.isSafeInteger(Number(row.override_call_limit))) {
    return Number(row.override_call_limit);
  }
  return defaultLimit;
}

// A stored limit outside the validated range means somebody edited the table by
// hand. That is a broken row, not a licence for unlimited calls, so it fails
// closed rather than being coerced into something plausible.
function isSensibleQuotaLimit(limit) {
  return Number.isSafeInteger(limit) &&
    limit >= QUOTA_MIN_CALL_LIMIT && limit <= QUOTA_MAX_CALL_LIMIT;
}

function buildQuotaSummary(periodKey, used, limit) {
  return {
    enabled: true, unlimited: false, period: periodKey, used, limit,
    remaining: Math.max(0, limit - used),
    percentage: limit > 0 ? Math.round((used / limit) * 100) : 0,
    resetAt: getNextResetAt(periodKey)
  };
}

function unavailableQuotaSummary(periodKey) {
  return {
    enabled: true, unlimited: false, error: "quota_service_unavailable",
    period: periodKey, used: null, limit: null, remaining: null,
    percentage: null, resetAt: getNextResetAt(periodKey)
  };
}

// Called BEFORE provider dispatch. A denial must never reach the provider.
// Two statements: one to read the allowance this user is held to, one atomic
// UPSERT that both increments and enforces it. Only the second one is allowed to
// change the counter, and it re-tests the limit under the row lock, so the
// counter can never pass the limit no matter how many replicas are racing.
async function reserveAiCall(userId) {
  if (!userId) return { allowed: false, reason: "auth_required", quota: null };

  const pool = await ensureQuotaPool();
  if (!pool) return { allowed: false, reason: "quota_service_unavailable", quota: null };

  const periodKey = getCurrentPeriodKey();
  let state;
  try {
    const result = await pool.query(READ_QUOTA_STATE_SQL, [userId, periodKey]);
    // No row means the config singleton is gone: nothing to enforce against, so
    // nothing is allowed. Fabricating a default would be unbounded usage.
    state = result.rows[0] || null;
  } catch {
    return { allowed: false, reason: "quota_service_unavailable", quota: null };
  }
  if (!state) return { allowed: false, reason: "quota_service_unavailable", quota: null };

  if (state.quota_enabled !== true) {
    return {
      allowed: true, reason: "quota_disabled",
      quota: {
        enabled: false, unlimited: true, period: periodKey,
        used: 0, limit: null, remaining: null, percentage: 0,
        resetAt: getNextResetAt(periodKey)
      }
    };
  }

  const limit = resolveQuotaLimit(state);
  if (!isSensibleQuotaLimit(limit)) {
    return { allowed: false, reason: "quota_service_unavailable", quota: null };
  }

  try {
    const reserved = await pool.query(RESERVE_QUOTA_SQL, [userId, periodKey, limit]);
    if (reserved.rows.length) {
      return {
        allowed: true,
        quota: buildQuotaSummary(periodKey, Number(reserved.rows[0].calls_used), limit)
      };
    }
  } catch {
    return { allowed: false, reason: "quota_service_unavailable", quota: null };
  }

  // The guard rejected the increment: the allowance was already spent. The
  // follow-up read only makes the 429 payload more precise; if it fails too, the
  // call is refused either way, at the limit the guard applied.
  let used = limit;
  try {
    const current = await pool.query(READ_QUOTA_USAGE_SQL, [userId, periodKey]);
    if (current.rows.length) used = Number(current.rows[0].calls_used);
  } catch { /* exhaustion holds regardless of this read */ }
  return {
    allowed: false, reason: "quota_exhausted",
    quota: {
      ...buildQuotaSummary(periodKey, Math.min(used, limit), limit),
      percentage: 100
    }
  };
}

// Read-only status for GET /ai/quota, always for the validated session's own
// user id. Fails closed: an unreachable store is reported as unavailable with
// nulls, never as a fabricated used=0 with a plausible limit.
async function getQuotaStatus(userId) {
  if (!userId) return { enabled: false, unlimited: false, error: "auth_required" };

  const periodKey = getCurrentPeriodKey();
  const pool = await ensureQuotaPool();
  if (!pool) return unavailableQuotaSummary(periodKey);

  let state;
  try {
    const result = await pool.query(READ_QUOTA_STATE_SQL, [userId, periodKey]);
    state = result.rows[0] || null;
  } catch {
    return unavailableQuotaSummary(periodKey);
  }
  if (!state) return unavailableQuotaSummary(periodKey);

  if (state.quota_enabled !== true) {
    return {
      enabled: false, unlimited: true, period: periodKey, used: 0, limit: null,
      remaining: null, percentage: 0, resetAt: getNextResetAt(periodKey)
    };
  }

  const limit = resolveQuotaLimit(state);
  if (!isSensibleQuotaLimit(limit)) return unavailableQuotaSummary(periodKey);

  return buildQuotaSummary(periodKey, Number(state.calls_used ?? 0), limit);
}

// ── ADMIN QUOTA CONFIG (Postgres-authoritative, admin-role gated) ───────────
// The role comes from the validated session only. Both spellings the app's own
// isAdministrator() accepts are honoured, so a user the admin UI shows as an
// administrator is never locked out of the panel by the relay.
function isBridgeAdminRole(role) {
  const normalized = String(role || "").trim().toLowerCase();
  return normalized === "admin" || normalized === "administrator";
}

function requireBridgeAdmin(req, res, next) {
  if (!isBridgeAdminRole(req.bridgeUser?.role)) {
    const requestId = req.nodeSendRequestId || requestIdentity(req, res);
    safeEvent("quota_admin_denied", { requestId, userId: req.bridgeUser?.id || null });
    return res.status(403).json({
      success: false, status: "forbidden", error: "Admin access required", requestId
    });
  }
  return next();
}

// Accepts the shapes the BridgeMind admin UI already sends — JSON boolean, 1/0,
// or the strings thereof — and nothing else. Returns undefined for "not usable",
// which is a 400 rather than a guess.
function normalizeQuotaEnabled(value) {
  if (typeof value === "boolean") return value;
  if (value === 1 || value === "1" || value === 0 || value === "0") return Number(value) === 1;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true") return true;
    if (normalized === "false") return false;
  }
  return undefined;
}

function normalizeQuotaLimit(value) {
  if (typeof value === "string" && !value.trim()) return undefined;
  const limit = Number(value);
  return isSensibleQuotaLimit(limit) ? limit : undefined;
}

function serializeQuotaConfig(row) {
  const updatedAt = row.updated_at instanceof Date ? row.updated_at.toISOString() : String(row.updated_at ?? "");
  return {
    quota_enabled: row.quota_enabled === true,
    default_call_limit: Number(row.default_call_limit),
    period_type: String(row.period_type || "monthly"),
    updated_at: updatedAt
  };
}

// A quota store that cannot be reached is an outage, and the admin has to see
// that as one. No host, user, database name or driver message is ever returned.
function quotaConfigUnavailable(res, requestId) {
  safeEvent("quota_config_unavailable", { requestId });
  return res.status(503).json({
    success: false, status: "quota_service_unavailable",
    error: "Quota configuration unavailable", requestId
  });
}

async function readQuotaConfigHandler(req, res) {
  const requestId = requestIdentity(req, res);
  try {
    const pool = await ensureQuotaPool();
    if (!pool) return quotaConfigUnavailable(res, requestId);
    const result = await pool.query(READ_QUOTA_CONFIG_SQL);
    if (!result.rows.length) return quotaConfigUnavailable(res, requestId);
    return res.json({ success: true, ...serializeQuotaConfig(result.rows[0]), requestId });
  } catch {
    return quotaConfigUnavailable(res, requestId);
  }
}

async function writeQuotaConfigHandler(req, res) {
  const requestId = requestIdentity(req, res);
  const body = req.body || {};
  const sendsEnabled = body.quota_enabled !== undefined && body.quota_enabled !== null;
  const sendsLimit = body.default_call_limit !== undefined && body.default_call_limit !== null;

  if (!sendsEnabled && !sendsLimit) {
    return res.status(400).json({
      success: false, status: "invalid_quota_config",
      error: "quota_enabled or default_call_limit is required", requestId
    });
  }
  const quotaEnabled = sendsEnabled ? normalizeQuotaEnabled(body.quota_enabled) : null;
  if (sendsEnabled && quotaEnabled === undefined) {
    return res.status(400).json({
      success: false, status: "invalid_quota_config",
      error: "quota_enabled must be a boolean or 0/1", requestId
    });
  }
  const defaultLimit = sendsLimit ? normalizeQuotaLimit(body.default_call_limit) : null;
  if (sendsLimit && defaultLimit === undefined) {
    return res.status(400).json({
      success: false, status: "invalid_quota_config",
      error: `default_call_limit must be an integer between ${QUOTA_MIN_CALL_LIMIT} and ${QUOTA_MAX_CALL_LIMIT}`,
      requestId
    });
  }

  try {
    const pool = await ensureQuotaPool();
    if (!pool) return quotaConfigUnavailable(res, requestId);
    const result = await pool.query(WRITE_QUOTA_CONFIG_SQL, [quotaEnabled, defaultLimit]);
    if (!result.rows.length) return quotaConfigUnavailable(res, requestId);
    const saved = serializeQuotaConfig(result.rows[0]);
    // Identity and the two scalar values only — never the SQL, the row id or
    // anything that describes the store.
    safeEvent("quota_config_updated", {
      requestId, userId: req.bridgeUser.id,
      quota_enabled: saved.quota_enabled, default_call_limit: saved.default_call_limit
    });
    return res.json({ success: true, saved: true, ...saved, requestId });
  } catch {
    return quotaConfigUnavailable(res, requestId);
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
    aiChat: "POST /ai/chat", aiQuota: "GET /ai/quota",
    aiQuotaConfig: "GET|PUT /ai/quota/config",
    tricksterBidHealth: "GET /trickster/bid/health",
    tricksterBidSuggest: "POST /trickster/bid/suggest-bid",
    tricksterPlayHealth: "GET /trickster/play/health",
    tricksterPlaySuggest: "POST /trickster/play/suggest-card",
    quota: "GET|POST /quota"
  },
  auth: { ai: "BridgeMind Bearer session", aiQuotaConfig: "Bearer session + admin role", relay: "x-api-key" },
  trickster: { auth: "BridgeMind Bearer session", upstreams: tricksterConfiguredState(), timeoutMs: tricksterTimeoutMs(), apiKeyConfigured: Boolean(process.env.TRICKSTER_API_KEY) },
  quotaStorage: { authority: "postgres", tables: ["quota_config", "quota_user_override", "quota_usage"] },
  providers: ["alibaba", "openai"]
}));

app.get("/health", (req, res) => res.json({
  success: true, service: "NodeSend", version: NODESEND_VERSION,
  status: "healthy", encryptionConfigured: isEncryptionConfigured(),
  privateKeySource: PRIVATE_KEY_B64 ? "base64" : PRIVATE_KEY_PEM_RAW ? "pem" : "none",
  plaintextAIKeysAllowed: ALLOW_PLAINTEXT_AI_KEYS,
  rocketchatConfigured: Boolean(ROCKETCHAT_WEBHOOK_URL),
  aiProxyConfigured: true, quotaConfigured: Boolean(NODESEND_QUOTA_URL),
  // Operator visibility for the Trickster gateway: hosts and configuration only,
  // never a key. The two upstream hosts are public by nature; the API key is
  // reported as configured/not configured and is never read out.
  trickster: { routes: 4, auth: "BridgeMind Bearer session", upstreams: tricksterConfiguredState(), timeoutMs: tricksterTimeoutMs(), apiKeyConfigured: Boolean(process.env.TRICKSTER_API_KEY) },
  quotaAuthority: "postgres", quotaStorage: quotaStorageState(),
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

// AI endpoints authenticate the BridgeMind Bearer session and enforce per-user
// quota here, because a static frontend has no trusted server of its own. The
// quota counter is Postgres-only: NCB supplies identity, never the number.
// /send, /rocketchat and the generic /quota adapter keep requireApiKey: they are
// server-to-server surfaces with no BridgeMind session behind them.
app.post("/ai/models", requireBridgeSession, (req, res) => relayAI(req, res, "models"));
app.post("/ai/test", requireBridgeSession, (req, res) => relayAI(req, res, "test"));
app.post("/ai/chat", requireBridgeSession, (req, res) => relayAI(req, res, "chat"));
app.get("/ai/quota", requireBridgeSession, async (req, res) => {
  const requestId = requestIdentity(req, res);
  try {
    const status = await getQuotaStatus(req.bridgeUser.id);
    if (status?.error === "quota_service_unavailable") {
      // Fail closed on the read surface too: an unverifiable quota is reported
      // as unavailable rather than as a clean 0 / limit.
      safeEvent("quota_status_unavailable", { requestId, userId: req.bridgeUser.id });
      return res.status(503).json({ ...status, requestId });
    }
    safeEvent("quota_status_served", { requestId, userId: req.bridgeUser.id, period: status.period });
    return res.json({ ...status, requestId });
  } catch {
    safeEvent("quota_status_unavailable", { requestId, userId: req.bridgeUser.id });
    return res.status(503).json({
      success: false, error: "quota_service_unavailable",
      enabled: true, unlimited: false, period: getCurrentPeriodKey(), used: null,
      limit: null, remaining: null, percentage: null,
      resetAt: getNextResetAt(getCurrentPeriodKey()), requestId
    });
  }
});
// Admin quota configuration is a third surface: session-authenticated AND
// role-gated, reading/writing only the config singleton in Postgres. An
// ordinary user gets 403 before any query runs.
app.get("/ai/quota/config", requireBridgeSession, requireBridgeAdmin, readQuotaConfigHandler);
app.put("/ai/quota/config", requireBridgeSession, requireBridgeAdmin, writeQuotaConfigHandler);
app.get("/quota", requireApiKey, quotaHandler);
app.post("/quota", requireApiKey, quotaHandler);

// ── TRICKSTER GATEWAY ──────────────────────────────────────────────────────
// BridgeMind's frontend is a STATIC Vite build with no server of its own, and the
// two TRICKSTER services (bidding, card play) send no CORS headers and answer a
// preflight with 405, so a browser page can neither host these routes nor call the
// services directly. These four routes are the way in. They are a transport, not a
// player: the incoming JSON body is forwarded unchanged, the upstream status is
// preserved, and the documented response shape is validated before anything is
// handed back. No bid and no card is ever decided here, and nothing falls back to
// the AI when a service is down — a failed decision is returned as a failure so the
// table can show it and let the player retry.
//
// Authentication is the existing BridgeMind Bearer session, the same
// requireBridgeSession that guards /ai/chat. Not BRIDGE_API_KEY: that key is
// browser-visible by design for the server-to-server relay surfaces, and an
// open relay to a third party is exactly what this must not become. The
// authenticated user comes only from the validated session (req.bridgeUser),
// never from a request body.
const TRICKSTER_UPSTREAMS = {
  bid: {
    env: "TRICKSTER_BID_URL", default: "https://bid.bridgemind.app",
    endpoints: { health: "/health", suggest: "/suggest-bid" }
  },
  play: {
    env: "TRICKSTER_PLAY_URL", default: "https://play.bridgemind.app",
    endpoints: { health: "/health", suggest: "/suggest-card" }
  }
};
// The one documented success shape per operation. Anything else is a contract
// change, and it is refused rather than forwarded into a game state.
const TRICKSTER_RESPONSE_SHAPES = {
  "bid:health": ["status"], "play:health": ["status"],
  "bid:suggest": ["bid"], "play:suggest": ["suit", "rank"]
};
// Read per request, so an operator can repoint a service without a restart.
// https (or loopback for a local test) with no embedded credentials, or the
// route fails closed: a misconfigured URL must not turn into a redirect to
// somewhere unknown with a user's session behind it.
function tricksterBaseUrl(service) {
  const spec = TRICKSTER_UPSTREAMS[service];
  if (!spec) return null;
  const raw = String(process.env[spec.env] || "").trim().replace(/\/+$/, "");
  const base = raw || spec.default;
  let parsed;
  try { parsed = new URL(base); } catch { return null; }
  if (parsed.username || parsed.password) return null;
  if (parsed.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(parsed.hostname)) return null;
  return base;
}
function tricksterTimeoutMs() {
  return boundedInt(process.env.TRICKSTER_TIMEOUT_MS, 15000, 500, 60000);
}
// Server-to-server credentials for the upstream services are reserved, not wired:
// the key exists only here and in one header. It is never read from a request,
// never echoed in a response, and never named by a VITE_* variable anywhere.
function tricksterUpstreamHeaders() {
  const headers = { "Content-Type": "application/json", Accept: "application/json" };
  const key = String(process.env.TRICKSTER_API_KEY || "").trim();
  if (key) headers["x-api-key"] = key;
  return headers;
}
// An upstream internal must not reach a browser: the message is only passed when
// it names a rejected field, and anything that looks like a stack, a file path or
// an exception type is replaced by a stable code.
const TRICKSTER_LEAK_MARKERS = /(stack|exception|traceback|\.cs\b|\.dll|\.py\b|\.java\b|at [A-Za-z_][\w.]*\.[A-Za-z_]\w*|\/var\/|\/app\/|[A-Za-z]:\\\\)/i;
function tricksterSafeError(parsed, status) {
  const message = typeof parsed?.error === "string" ? parsed.error.slice(0, 200) : "";
  if (message && !TRICKSTER_LEAK_MARKERS.test(message)) return message;
  return `trickster_upstream_${Number(status) || 500}`;
}
function tricksterShapeOk(shapeKey, payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return false;
  const expected = TRICKSTER_RESPONSE_SHAPES[shapeKey];
  const keys = Object.keys(payload).sort();
  if (!expected || keys.length !== expected.length || keys.join() !== [...expected].sort().join()) return false;
  if (shapeKey === "bid:suggest") return typeof payload.bid === "string" && payload.bid.length > 0 && payload.bid.length <= 8;
  if (shapeKey === "play:suggest") return Number.isInteger(payload.suit) && Number.isInteger(payload.rank);
  return typeof payload.status === "string" && payload.status.length <= 64;
}
function tricksterConfiguredState() {
  const state = {};
  for (const service of Object.keys(TRICKSTER_UPSTREAMS)) {
    const base = tricksterBaseUrl(service);
    let host = "invalid";
    try { host = base ? new URL(base).host : "invalid"; } catch { /* stays invalid */ }
    state[service] = host;
  }
  return state;
}

// `fetchImpl` is a seam for the deterministic harness; production uses global fetch.
async function proxyTrickster(service, operation, req, res, fetchImpl = globalThis.fetch) {
  const requestId = req.nodeSendRequestId || requestIdentity(req, res);
  const spec = TRICKSTER_UPSTREAMS[service];
  const base = tricksterBaseUrl(service);
  if (!spec || !base) {
    safeEvent("trickster_unconfigured", { requestId, service });
    return res.status(503).json({ error: `${service === "play" ? "TRICKSTER_PLAY_URL" : "TRICKSTER_BID_URL"} is not a valid https URL` });
  }
  const isPost = req.method === "POST";
  let serializedBody;
  if (isPost) {
    if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) {
      return res.status(400).json({ error: "Request body must be a JSON object." });
    }
    // Forwarded unchanged: no field is added, renamed, defaulted or removed here.
    serializedBody = JSON.stringify(req.body);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), tricksterTimeoutMs());
  let upstream;
  try {
    upstream = await fetchImpl(base + spec.endpoints[operation], {
      method: req.method,
      headers: tricksterUpstreamHeaders(),
      ...(serializedBody === undefined ? {} : { body: serializedBody }),
      signal: controller.signal
    });
  } catch (error) {
    clearTimeout(timer);
    const timedOut = error?.name === "AbortError" || error?.name === "TimeoutError";
    safeEvent(timedOut ? "trickster_timeout" : "trickster_unreachable", { requestId, service, operation });
    return res.status(timedOut ? 504 : 502).json({ error: timedOut ? "trickster_timeout" : "trickster_unreachable" });
  }
  clearTimeout(timer);

  const text = await upstream.text().catch(() => "");
  let payload = null;
  if (text) {
    try { payload = JSON.parse(text); } catch { payload = undefined; }
  }
  if (payload === undefined) {
    // An HTML error page or a truncated body from whatever sits in front of the
    // service must never be forwarded as if it were a decision.
    safeEvent("trickster_invalid_response", { requestId, service, operation, status: upstream.status });
    return res.status(502).json({ error: "trickster_invalid_response" });
  }
  if (upstream.status !== 200) {
    // The upstream chooses the status; only its message is kept, and only when it
    // is safe. Response shape mirrors the client's documented error contract.
    safeEvent("trickster_upstream_rejected", {
      requestId, service, operation, status: upstream.status,
      // Logged in the same sanitised form the caller sees, so an upstream internal
      // cannot survive in a log line either.
      reason: tricksterSafeError(payload, upstream.status).slice(0, 120)
    });
    return res.status(upstream.status).json({
      error: tricksterSafeError(payload, upstream.status), upstreamStatus: upstream.status
    });
  }
  const shapeKey = `${service}:${operation}`;
  if (!tricksterShapeOk(shapeKey, payload)) {
    safeEvent("trickster_unexpected_shape", { requestId, service, operation, keys: payload && typeof payload === "object" ? Object.keys(payload).join(",") : typeof payload });
    return res.status(502).json({ error: "trickster_unexpected_shape" });
  }
  safeEvent("trickster_served", { requestId, service, operation, userId: req.bridgeUser?.id ?? null });
  // 200 bodies are the documented shape and nothing else: no requestId, no
  // service metadata, so the caller sees the same body either gateway serves it.
  return res.status(200).json(payload);
}

// A wrong method on a path that exists answers 405 with an Allow header, exactly
// as both upstream services do (measured: GET /suggest-card -> 405 allow=POST),
// instead of falling through to the 404 the SPA catch-all would give.
function tricksterMethodNotAllowed(req, res) {
  res.setHeader("Allow", "POST");
  return res.status(405).json({ error: "Method not allowed." });
}

app.get("/trickster/bid/health", requireBridgeSession, (req, res) => proxyTrickster("bid", "health", req, res));
app.get("/trickster/play/health", requireBridgeSession, (req, res) => proxyTrickster("play", "health", req, res));
app.post("/trickster/bid/suggest-bid", requireBridgeSession, (req, res) => proxyTrickster("bid", "suggest", req, res));
app.post("/trickster/play/suggest-card", requireBridgeSession, (req, res) => proxyTrickster("play", "suggest", req, res));
app.get("/trickster/bid/suggest-bid", requireBridgeSession, tricksterMethodNotAllowed);
app.get("/trickster/play/suggest-card", requireBridgeSession, tricksterMethodNotAllowed);

app.use((req, res) => res.status(404).json({ success: false, error: "Endpoint not found" }));

if (require.main === module) {
  app.listen(PORT, "0.0.0.0", () => {
    safeEvent("startup", {
      version: NODESEND_VERSION, port: PORT,
      encryptionConfigured: isEncryptionConfigured(),
      privateKeySource: PRIVATE_KEY_B64 ? "base64" : PRIVATE_KEY_PEM_RAW ? "pem" : "none",
      plaintextAIKeysAllowed: ALLOW_PLAINTEXT_AI_KEYS,
      quotaConfigured: Boolean(NODESEND_QUOTA_URL),
      quotaAuthority: "postgres", quotaStorage: quotaStorageState().status
    });
  });
  // Warm the schema so the first AI call is not also the one that pays for the
  // DDL round trips. Fail-soft: an unreachable store here must not stop the
  // relay from serving /send, /rocketchat or the session-gated reads — those
  // paths fail closed per request.
  ensureQuotaPool().then((pool) => {
    safeEvent("quota_storage_ready", { poolConfigured: Boolean(pool), status: quotaStorageStatus });
  });
}

// Exported to permit local mock-provider/disconnect tests without binding a port.
// The SQL constants are exported so the real-database harness exercises the exact
// statements this relay runs, instead of a copy that could drift from them.
module.exports = {
  app, requestLifecycle, timeHeader, isAllowedAlibabaBaseUrl,
  buildProviderBody, NODESEND_VERSION,
  QUOTA_SCHEMA_SQL, RESERVE_QUOTA_SQL, READ_QUOTA_STATE_SQL,
  READ_QUOTA_USAGE_SQL, READ_QUOTA_CONFIG_SQL, WRITE_QUOTA_CONFIG_SQL,
  // The Trickster gateway's own rules, exported so the harness can test the real
  // predicates instead of a copy of them. The routes themselves are exercised over
  // HTTP through `app`, which is what proves the session guard is attached.
  TRICKSTER_UPSTREAMS, TRICKSTER_RESPONSE_SHAPES, tricksterBaseUrl, tricksterTimeoutMs,
  tricksterUpstreamHeaders, tricksterSafeError, tricksterShapeOk, tricksterConfiguredState,
  isBridgeAdminRole, resolveQuotaLimit, isSensibleQuotaLimit
};
