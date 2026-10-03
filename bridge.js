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
 * user_id in the request body or query string. The counter lives in the NCB
 * instance's own ai_quota_* tables (ai_quota_config, ai_quota_user_override,
 * ai_quota_usage), reached through the same data API BridgeMind's client uses,
 * with the caller's own session bearer. The counter is reserved BEFORE the
 * provider is contacted; a denial or an unreachable quota store returns
 * 429/503 and the provider is not called.
 *
 * One authority, two jobs: the NCB session proves WHO the caller is and its
 * ai_quota_* rows prove HOW MANY calls they have left. Because every quota read
 * and write is made as the caller with the caller's token, there is no second
 * store and no service credential anywhere on this path.
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
const NODESEND_VERSION = "bridge-ncb-quota-v6";
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
// NCB is also the per-user quota store: the same two values address it, so the
// quota path adds no configuration and no credential of its own.
const NCB_PROXY_BASE = String(process.env.NCB_PROXY_BASE ||
  "https://rmvzorxcl35mttidiexhtp5g2m0hpsqo.lambda-url.us-east-2.on.aws").trim();
const NCB_INSTANCE = String(process.env.NCB_INSTANCE || "55954_bridgemind").trim();
const NCB_TIMEOUT_MS = boundedInt(process.env.NODESEND_NCB_TIMEOUT_MS, 8000, 500, 30000);

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
      reservation = await reserveAiCall(req);
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

// ── BRIDGEMIND PER-USER MONTHLY QUOTA (NCB-authoritative) ──────────────
// Identity and the counter come from the same place: the caller's validated NCB
// session proves WHO they are, and the NCB instance's own ai_quota_* rows prove
// HOW MANY calls they have left. Every quota read and write is made as the
// caller, with the caller's session bearer, so there is no second database and
// no service credential to leak. The user id is always `req.bridgeUser.id` from
// /auth/get-session — never a user_id in the request body or query string.
//
// The three tables already exist in NCB and were deliberately kept through the
// historical-game reset. NodeSend issues no DDL of any kind: nothing here
// creates, alters, drops or truncates a table or an index.
//
// Semantics preserved: calendar-month UTC period key, per-user override >
// global default, quota disabled = unlimited, and fail CLOSED whenever the
// authoritative state is missing, ambiguous, out of range or unreadable.
const QUOTA_MIN_CALL_LIMIT = 1;
const QUOTA_MAX_CALL_LIMIT = 100000;

// The API name of each table is what the /data/ route accepts. Note that NCB's
// physical storage name may carry an instance suffix (the provider-credentials
// table's API name literally does), so these strings are route segments only —
// they are never used as SQL identifiers anywhere in this file.
const AI_QUOTA_CONFIG_TABLE = "ai_quota_config";
const AI_QUOTA_OVERRIDE_TABLE = "ai_quota_user_override";
const AI_QUOTA_USAGE_TABLE = "ai_quota_usage";

// ── NCB DATA API ───────────────────────────────────────────────────────
// Not invented: this is the surface BridgeMind's own client uses today
// (src/api.js `dataFetch`, server/quotaService.js, server/index.js
// `PUT /api/ai/quota/config`). The operation is the first segment after
// `/data/`, the table the second. Filters are plain equality query-string
// column names — the only operators anywhere in the app are `col[gte]` and
// `col[lte]`, and nothing else is expressible. A row is addressed by id in the
// URL for update/delete; `/data/read/{table}/{id}` is recorded by the app itself
// as answering HTTP 500, so a single row comes from a filtered list read, which
// is what `fetchRecordedHandById` does too. Create and update bodies are FLAT
// top-level column maps with no envelope. Reads answer
// `{status:"success", data:[…]}`; an empty result is HTTP 200 with no rows, and
// no caller anywhere distinguishes a 404 from an empty list.
//
// There is no atomic primitive on this surface: no `$inc`, no upsert, no
// ON CONFLICT analogue, no transaction, no batch, no row version and no
// conditional write. That is a measured absence, not an assumption — see the
// concurrency note above `withUserQuotaLock`.

// The only thing ever reported about the store is this label — no host, no
// table listing, no NCB error text. "pending" until the first quota round trip
// answers, because a quota call is only ever made as a signed-in caller: there
// is no boot-time probe, and inventing one would mean a credential this
// architecture deliberately does not have.
let quotaStorageStatus = ncbQuotaConfigured() ? "pending" : "unconfigured";

function ncbQuotaConfigured() {
  return Boolean(NCB_PROXY_BASE && NCB_INSTANCE);
}

function markQuotaReachable() {
  if (ncbQuotaConfigured()) quotaStorageStatus = "ready";
}

// "invalid" and "unreachable" both mean every quota surface fails closed; the
// distinction is for the operator only, so an outage is not mistaken for a
// corrupted row and vice versa.
function markQuotaFailure(kind) {
  quotaStorageStatus = kind === "invalid" ? "invalid" : "unreachable";
}

function quotaStorageState() {
  return { configured: ncbQuotaConfigured(), status: quotaStorageStatus };
}

// A read that answers anything other than a row list is an unreadable store, not
// an empty one. `data: null` is the app's own spelling for "no rows"
// (quotaService.js tests `!body?.data?.length`), so it is empty, not invalid.
function ncbRowList(body) {
  if (!body || typeof body !== "object" || !("data" in body)) return null;
  const data = body.data;
  if (data === null || data === undefined) return [];
  if (Array.isArray(data)) return data.filter((row) => row && typeof row === "object");
  return typeof data === "object" ? [data] : null;
}

async function ncbDataRead(req, table, filters = {}) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  }
  const query = params.toString();
  const path = `/data/read/${encodeURIComponent(table)}${query ? `?${query}` : ""}`;
  let response;
  try {
    response = await ncbRequest(req, path);
  } catch {
    markQuotaFailure("transport");
    return { ok: false, reason: "transport" };
  }
  if (!response.ok) {
    markQuotaFailure("http");
    return { ok: false, reason: `http_${Number(response.status) || 0}` };
  }
  const body = await response.json().catch(() => null);
  if (body && typeof body === "object" && body.status === "error") {
    markQuotaFailure("rejected");
    return { ok: false, reason: "rejected" };
  }
  const rows = ncbRowList(body);
  if (!rows) {
    markQuotaFailure("invalid");
    return { ok: false, reason: "envelope" };
  }
  markQuotaReachable();
  return { ok: true, rows };
}

async function ncbDataWrite(req, path, values, method) {
  let response;
  try {
    response = await ncbRequest(req, path, { method, body: JSON.stringify(values) });
  } catch {
    markQuotaFailure("transport");
    return { ok: false, reason: "transport" };
  }
  if (!response.ok) {
    markQuotaFailure("http");
    return { ok: false, reason: `http_${Number(response.status) || 0}` };
  }
  // A 200 whose body says `status:"error"` is a rejected write. Counting it as a
  // spend would charge the user for a call that did not happen; ignoring it would
  // let the counter run ahead of the truth in the other direction.
  const body = await response.json().catch(() => null);
  if (body && typeof body === "object" && body.status === "error") {
    markQuotaFailure("rejected");
    return { ok: false, reason: "rejected" };
  }
  markQuotaReachable();
  return { ok: true };
}

function ncbDataCreate(req, table, values) {
  return ncbDataWrite(req, `/data/create/${encodeURIComponent(table)}`, values, "POST");
}

function ncbDataUpdate(req, table, id, values) {
  return ncbDataWrite(req,
    `/data/update/${encodeURIComponent(table)}/${encodeURIComponent(id)}`, values, "PUT");
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
// global default. Kept as a pure function of the row pair so the precedence rule
// is testable without any store at all.
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

// NCB's flag columns are 0/1 integers, not booleans — the app's own reader does
// `Number(row.quota_enabled ?? 1)` and `Number(row.enabled) === 1` — but a MySQL
// driver can hand back a real boolean too. Both spellings are accepted here so
// the store's response format is never a reason to misread an allowance; the
// caller supplies the fallback for a value that is neither. The safe fallback for
// `quota_enabled` is true: enabled means ENFORCED, so an unreadable flag cannot
// turn into unlimited calls.
function ncbFlag(value, fallback) {
  if (typeof value === "boolean") return value;
  if (value === 1 || value === 0 || value === "1" || value === "0") return Number(value) === 1;
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "true") return true;
    if (normalized === "false") return false;
  }
  return fallback;
}

function ncbInt(value) {
  if (value === null || value === undefined || value === "") return null;
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : null;
}

// NCB DATETIME columns reject the ISO form with 'Z' and milliseconds — recorded
// in the app as an HTTP 500 "Error creating record." on a sibling table — so
// timestamps go out as 'YYYY-MM-DD HH:MM:SS' in UTC, the same conversion the
// app's own writers use.
function ncbDateTime(date = new Date()) {
  return date.toISOString().replace("T", " ").slice(0, 19);
}

// The quota counter for one user, read as it actually is rather than as it was
// configured to be. Three independent filtered reads go out in parallel because
// the data API has no join and no batch endpoint.
//
// Every row the store hands back is re-checked against the session identity this
// request is about: an equality filter is never assumed to have been applied,
// because enforcing against another user's counter — or writing to another
// user's row — is worse than a 503.
async function readNcbQuotaState(req, userId, periodKey) {
  if (!userId || !periodKey) return { ok: false, reason: "auth_required" };
  const ownedBy = (rows) => rows.filter((row) => String(row.user_id ?? "") === String(userId));

  const [config, override, usage] = await Promise.all([
    ncbDataRead(req, AI_QUOTA_CONFIG_TABLE, {}),
    ncbDataRead(req, AI_QUOTA_OVERRIDE_TABLE, { user_id: userId }),
    ncbDataRead(req, AI_QUOTA_USAGE_TABLE, { user_id: userId, period_key: periodKey })
  ]);
  for (const part of [config, override, usage]) {
    if (!part.ok) return { ok: false, reason: part.reason };
  }

  // The config singleton is enforced against, never invented: no row means there
  // is nothing to hold the user to, and fabricating a default would hand out
  // unbounded usage the moment the table is cleared. Two rows means two
  // conflicting allowances, so neither can be trusted.
  if (config.rows.length !== 1) {
    return { ok: false, reason: config.rows.length ? "config_ambiguous" : "config_missing" };
  }
  const configRow = config.rows[0];
  if (String(configRow.period_type || "monthly").trim().toLowerCase() !== "monthly") {
    // Only the calendar-month period is implemented. Counting a week's usage
    // against a month's reset would over-grant, so an unexpected period is an
    // invalid state, not a hint to guess.
    return { ok: false, reason: "period_type_unsupported" };
  }
  const defaultCallLimit = ncbInt(configRow.default_call_limit);
  if (defaultCallLimit === null) return { ok: false, reason: "config_limit_missing" };

  const overrideRow = ownedBy(override.rows)[0] || null;
  if (ownedBy(override.rows).length > 1) return { ok: false, reason: "override_ambiguous" };
  const overrideEnabled = overrideRow ? ncbFlag(overrideRow.enabled, false) : false;
  const overrideCallLimit = overrideRow ? ncbInt(overrideRow.call_limit) : null;
  if (overrideEnabled && overrideCallLimit === null) {
    // An enabled override whose limit cannot be read is not a licence to fall
    // back to the (possibly larger) default.
    return { ok: false, reason: "override_limit_missing" };
  }

  const usageRows = ownedBy(usage.rows).filter(
    (row) => String(row.period_key ?? "") === String(periodKey)
  );
  if (usageRows.length > 1) return { ok: false, reason: "usage_ambiguous" };
  const usageRow = usageRows[0] || null;
  // A missing usage row is zero usage, not a missing user. A present row whose
  // counter is not a non-negative integer is a broken counter, and is not coerced.
  const callsUsed = usageRow ? ncbInt(usageRow.calls_used ?? 0) : 0;
  if (callsUsed === null || callsUsed < 0) return { ok: false, reason: "usage_counter_invalid" };

  return {
    ok: true,
    configId: configRow.id,
    quotaEnabled: ncbFlag(configRow.quota_enabled, true),
    defaultCallLimit,
    periodType: "monthly",
    overrideEnabled,
    overrideCallLimit,
    usageId: usageRow ? usageRow.id : null,
    callsUsed
  };
}

function quotaDisabledSummary(periodKey) {
  return {
    enabled: false, unlimited: true, period: periodKey,
    used: 0, limit: null, remaining: null, percentage: 0,
    resetAt: getNextResetAt(periodKey)
  };
}

function quotaExhaustedSummary(periodKey, used, limit) {
  return {
    ...buildQuotaSummary(periodKey, Math.min(used, limit), limit),
    percentage: 100
  };
}

// CONCURRENCY — the honest statement of what this can and cannot guarantee.
//
// The retired Postgres path reserved with one atomic UPSERT: the increment and
// the `calls_used < applied_limit` test happened inside a single statement, under
// the row lock, so no number of replicas could push a user past a limit. NCB
// offers nothing equivalent. Its data API is read / create / update / delete over
// HTTP with equality filters and no envelope; there is no increment operator, no
// upsert, no ON CONFLICT analogue, no transaction, no batch, no row version, no
// ETag and no conditional write. That was established by reading every call site
// in BridgeMind's own client, not assumed.
//
// So the reservation is a read-check-write, and the safest thing available is to
// make it ONE critical section per user for the lifetime of this NodeSend
// process. Requests from the same session are then serialised end to end: two
// racing calls cannot both observe used=4 against a limit of 5.
//
// What that does NOT cover, and cannot without a primitive NCB does not have:
//   - More than one NodeSend replica. Each replica holds its own locks, so two
//     replicas serving one user can both pass the check and both write, and the
//     counter can land below the number of calls actually granted.
//   - A `create` racing a `create`: the tables carry no unique constraint that
//     HTTP can rely on, so two rows for one (user, period) are possible. The
//     next read sees the ambiguity and fails closed with 503 rather than picking
//     a winner, which turns the race into a visible outage instead of a silent
//     miscount.
//   - The store itself: NCB does not verify that the `user_id` being written
//     matches the session making the write (recorded in the app as
//     "client_verified_session, NOT server-enforced billing-grade ownership").
//     NodeSend always stamps `req.bridgeUser.id` and re-checks every row it reads
//     against it, but a caller who talks to NCB directly with their own token is
//     outside this relay's reach. Per-user quota here is enforced honestly, not
//     cryptographically.
// Deployment assumption: a single NodeSend process. If that changes, the counter
// needs a store with a real atomic primitive, not a bigger lock.
const quotaUserLocks = new Map();

function withUserQuotaLock(userId, task) {
  const key = String(userId);
  const previous = quotaUserLocks.get(key) || Promise.resolve();
  // The chain stores only a never-rejecting promise, so one failed reservation
  // cannot poison every later request from the same user.
  const run = previous.then(task, task);
  const settled = run.then(() => undefined, () => undefined);
  quotaUserLocks.set(key, settled);
  settled.then(() => {
    if (quotaUserLocks.get(key) === settled) quotaUserLocks.delete(key);
  });
  return run;
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
// The whole reservation — read the allowance, test it, increment it — runs inside
// one per-user critical section, because NCB cannot do it in one statement. See
// the concurrency note above withUserQuotaLock for exactly what that guarantees
// and what it does not.
async function reserveAiCall(req) {
  const userId = req.bridgeUser?.id;
  if (!userId) return { allowed: false, reason: "auth_required", quota: null };
  return withUserQuotaLock(userId, () => reserveQuotaLocked(req, userId, getCurrentPeriodKey()));
}

async function reserveQuotaLocked(req, userId, periodKey) {
  const state = await readNcbQuotaState(req, userId, periodKey);
  if (!state.ok) {
    // The reason is a stable code, never an NCB body or message.
    safeEvent("quota_state_unavailable", { userId, reason: state.reason });
    return { allowed: false, reason: "quota_service_unavailable", quota: null };
  }

  // Quota disabled is unlimited and spends nothing: no write is attempted, so a
  // disabled quota cannot grow a usage row or overwrite one.
  if (!state.quotaEnabled) {
    return { allowed: true, reason: "quota_disabled", quota: quotaDisabledSummary(periodKey) };
  }

  const limit = resolveQuotaLimit({
    default_call_limit: state.defaultCallLimit,
    override_enabled: state.overrideEnabled,
    override_call_limit: state.overrideCallLimit
  });
  if (!isSensibleQuotaLimit(limit)) {
    safeEvent("quota_state_unavailable", { userId, reason: "limit_out_of_range" });
    return { allowed: false, reason: "quota_service_unavailable", quota: null };
  }

  // Tested inside the lock against the value just read, which is the closest
  // analogue the data API allows to the old UPSERT's WHERE guard.
  if (state.callsUsed >= limit) {
    return {
      allowed: false, reason: "quota_exhausted",
      quota: quotaExhaustedSummary(periodKey, state.callsUsed, limit)
    };
  }

  const values = {
    calls_used: state.callsUsed + 1,
    applied_limit: limit,
    updated_at: ncbDateTime()
  };
  // A period's first call creates the row, so user_id and period_key go
  // explicitly: omitting a NOT NULL column is a documented HTTP 500 on this API.
  // The user id is always the validated session's — never a value from the request.
  const written = state.usageId === null || state.usageId === undefined
    ? await ncbDataCreate(req, AI_QUOTA_USAGE_TABLE, {
      user_id: userId, period_key: periodKey, ...values
    })
    : await ncbDataUpdate(req, AI_QUOTA_USAGE_TABLE, state.usageId, values);
  if (!written.ok) {
    safeEvent("quota_reserve_failed", { userId, reason: written.reason });
    return { allowed: false, reason: "quota_service_unavailable", quota: null };
  }

  return { allowed: true, quota: buildQuotaSummary(periodKey, state.callsUsed + 1, limit) };
}

// Read-only status for GET /ai/quota, always for the validated session's own user
// id, and never a lock or a write. Fails closed: an unreadable or ambiguous store
// is reported as unavailable with nulls, never as a fabricated used=0 with a
// plausible limit.
async function getQuotaStatus(req) {
  const userId = req.bridgeUser?.id;
  if (!userId) return { enabled: false, unlimited: false, error: "auth_required" };

  const periodKey = getCurrentPeriodKey();
  const state = await readNcbQuotaState(req, userId, periodKey);
  if (!state.ok) return unavailableQuotaSummary(periodKey);

  if (!state.quotaEnabled) return quotaDisabledSummary(periodKey);

  const limit = resolveQuotaLimit({
    default_call_limit: state.defaultCallLimit,
    override_enabled: state.overrideEnabled,
    override_call_limit: state.overrideCallLimit
  });
  if (!isSensibleQuotaLimit(limit)) return unavailableQuotaSummary(periodKey);

  return buildQuotaSummary(periodKey, state.callsUsed, limit);
}

// ── ADMIN QUOTA CONFIG (NCB-authoritative, admin-role gated) ────────────
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

// The stored flag is a 0/1 integer; the response contract the admin UI already
// consumes is a JSON boolean. The conversion happens here and nowhere else, so
// neither the caller's spelling nor the column's ever leaks into a comparison.
function serializeQuotaConfig(row) {
  return {
    quota_enabled: ncbFlag(row.quota_enabled, true),
    default_call_limit: Number(row.default_call_limit),
    period_type: String(row.period_type || "monthly"),
    // NCB hands a DATETIME column back as a string already; nothing is re-based
    // onto a timezone the store never claimed.
    updated_at: String(row.updated_at ?? "")
  };
}

// The config singleton, read through the data API. `reason` is always a stable
// code: the store's own body, status text and table layout never travel with it.
async function readNcbQuotaConfig(req) {
  const read = await ncbDataRead(req, AI_QUOTA_CONFIG_TABLE, {});
  if (!read.ok) return { ok: false, reason: read.reason };
  if (read.rows.length === 0) return { ok: false, reason: "config_missing" };
  if (read.rows.length > 1) return { ok: false, reason: "config_ambiguous" };
  const row = read.rows[0];
  const limit = ncbInt(row.default_call_limit);
  if (limit === null || !isSensibleQuotaLimit(limit)) {
    return { ok: false, reason: "config_limit_invalid" };
  }
  return { ok: true, row };
}

// A quota store that cannot be reached, or that answers with something unusable,
// is an outage — and the admin has to see it as one rather than as a config with
// blank fields. The reason is logged as a code and never returned.
function quotaConfigUnavailable(res, requestId, reason) {
  safeEvent("quota_config_unavailable", { requestId, reason: String(reason || "unknown") });
  return res.status(503).json({
    success: false, status: "quota_service_unavailable",
    error: "Quota configuration unavailable", requestId
  });
}

async function readQuotaConfigHandler(req, res) {
  const requestId = requestIdentity(req, res);
  const config = await readNcbQuotaConfig(req);
  if (!config.ok) return quotaConfigUnavailable(res, requestId, config.reason);
  return res.json({ success: true, ...serializeQuotaConfig(config.row), requestId });
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

  const read = await ncbDataRead(req, AI_QUOTA_CONFIG_TABLE, {});
  if (!read.ok) return quotaConfigUnavailable(res, requestId, read.reason);
  if (read.rows.length > 1) return quotaConfigUnavailable(res, requestId, "config_ambiguous");
  const existing = read.rows[0] || null;

  // The data API has no COALESCE-style partial update, so "not sent" is honoured
  // by merging the unset half from the row just read — never by defaulting it.
  // With no row to merge into, a partial PUT could only be answered by inventing
  // an allowance, so it is refused instead of guessed at.
  const enabled = quotaEnabled !== null ? quotaEnabled : ncbFlag(existing?.quota_enabled, null);
  const limit = defaultLimit !== null ? defaultLimit : ncbInt(existing?.default_call_limit);
  if (enabled === null || enabled === undefined || limit === null || !isSensibleQuotaLimit(limit)) {
    safeEvent("quota_config_incomplete", { requestId, userId: req.bridgeUser.id });
    return res.status(400).json({
      success: false, status: "quota_config_missing",
      error: "There is no quota configuration row to update; send both quota_enabled and default_call_limit",
      requestId
    });
  }

  // 0/1 going back, because that is the column's type; period_type travels only
  // on create, where omitting a NOT NULL column is a documented HTTP 500.
  const payload = {
    quota_enabled: enabled ? 1 : 0,
    default_call_limit: limit,
    updated_at: ncbDateTime()
  };
  const written = existing && existing.id !== undefined && existing.id !== null
    ? await ncbDataUpdate(req, AI_QUOTA_CONFIG_TABLE, existing.id, payload)
    : await ncbDataCreate(req, AI_QUOTA_CONFIG_TABLE, { ...payload, period_type: "monthly" });
  if (!written.ok) return quotaConfigUnavailable(res, requestId, written.reason);

  // The write is not believed until it reads back. NCB's create/update response is
  // not a row, and `saved: true` for an update the store accepted and ignored
  // would be exactly the failure this relay exists to prevent.
  const verify = await readNcbQuotaConfig(req);
  if (!verify.ok) {
    safeEvent("quota_config_unverified", { requestId, reason: verify.reason });
    return quotaConfigUnavailable(res, requestId, "write_unverified");
  }
  const saved = serializeQuotaConfig(verify.row);
  // Identity and the two scalar values only — never the row id, the request path
  // or anything else that describes the store.
  safeEvent("quota_config_updated", {
    requestId, userId: req.bridgeUser.id,
    quota_enabled: saved.quota_enabled, default_call_limit: saved.default_call_limit
  });
  return res.json({ success: true, saved: true, ...saved, requestId });
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
  quotaStorage: { authority: "ncb", tables: [AI_QUOTA_CONFIG_TABLE, AI_QUOTA_OVERRIDE_TABLE, AI_QUOTA_USAGE_TABLE] },
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
  quotaAuthority: "ncb", quotaStorage: quotaStorageState(),
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
// quota counter is the same NCB instance's ai_quota_* tables, reached as the
// caller: one authority supplies both the identity and the number.
// /send, /rocketchat and the generic /quota adapter keep requireApiKey: they are
// server-to-server surfaces with no BridgeMind session behind them.
app.post("/ai/models", requireBridgeSession, (req, res) => relayAI(req, res, "models"));
app.post("/ai/test", requireBridgeSession, (req, res) => relayAI(req, res, "test"));
app.post("/ai/chat", requireBridgeSession, (req, res) => relayAI(req, res, "chat"));
app.get("/ai/quota", requireBridgeSession, async (req, res) => {
  const requestId = requestIdentity(req, res);
  try {
    const status = await getQuotaStatus(req);
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
// role-gated, reading and writing only the config row in the NCB instance. An
// ordinary user gets 403 before any request runs.
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
      quotaAuthority: "ncb", quotaStorage: quotaStorageState().status
    });
  });
  // No quota warm-up here, deliberately. Every ai_quota_* access is made as the
  // caller with the caller's own session bearer, so at boot there is no identity
  // to make one with — and a boot-time probe would require exactly the service
  // credential this architecture refuses to have. The store's status therefore
  // starts "pending" and becomes "ready" or "unreachable" on the first real
  // quota request; every path fails closed until then.
}

// Exported to permit local mock-provider/disconnect tests without binding a port.
// The quota internals are exported so the harness can exercise the real read/write
// predicates and the real concurrency queue instead of a copy of them.
module.exports = {
  app, requestLifecycle, timeHeader, isAllowedAlibabaBaseUrl,
  buildProviderBody, NODESEND_VERSION,
  AI_QUOTA_CONFIG_TABLE, AI_QUOTA_OVERRIDE_TABLE, AI_QUOTA_USAGE_TABLE,
  ncbRowList, ncbFlag, ncbInt, ncbDateTime, getCurrentPeriodKey, getNextResetAt,
  // The Trickster gateway's own rules, exported so the harness can test the real
  // predicates instead of a copy of them. The routes themselves are exercised over
  // HTTP through `app`, which is what proves the session guard is attached.
  TRICKSTER_UPSTREAMS, TRICKSTER_RESPONSE_SHAPES, tricksterBaseUrl, tricksterTimeoutMs,
  tricksterUpstreamHeaders, tricksterSafeError, tricksterShapeOk, tricksterConfiguredState,
  isBridgeAdminRole, resolveQuotaLimit, isSensibleQuotaLimit, withUserQuotaLock
};
