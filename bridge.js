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
 * QUOTA CONTRACT — NodeSend is the ONLY quota backend:
 * AI endpoints (/ai/models, /ai/test, /ai/chat, GET /ai/quota,
 * GET|PUT /ai/quota/config) are authenticated by the caller's BridgeMind Bearer
 * session, validated server-side against the NCB proxy (/auth/get-session). The
 * identity used for quota comes from that validated session, NEVER from a
 * user_id in the request body or query string.
 *
 * The same NCB proxy is also the quota STORAGE, addressed with the caller's own
 * bearer: there is no service credential and no second backend. NodeSend resolves
 * the configuration, the per-user limit and the usage row, keeps the period
 * arithmetic, and writes the counter itself. The counter is reserved BEFORE the
 * provider is contacted; a denial or unreadable/unwritable quota returns 429/503
 * and the provider is not called. Missing, duplicate or malformed quota rows fail
 * CLOSED (503) — the count is never guessed and never defaulted to "unlimited".
 *
 * One logical AI decision costs at most one call: `x-ai-decision-key` is an
 * idempotency key held against a reservation ledger, durable when
 * AI_QUOTA_RESERVATION_TABLE is configured. The key is a billing label — never
 * authentication, never identity.
 *
 * This correctness depends on there being EXACTLY ONE replica of this process:
 * NCB offers no atomic increment and no compare-and-swap, so two replicas reading,
 * then writing the same row lose updates. Multi-replica quota counting is
 * unsupported. GET /health reports this as `quota.replicas`.
 *
 * GET|PUT /ai/quota/config additionally require the validated session's admin
 * role and are applied here: an ordinary user gets 403 before any NCB call, a
 * rejected write is never reported as saved, and no backend detail is returned.
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
// `x-quota-reservation` is exposed so a browser can read whether its call was charged or
// deduplicated. allowedHeaders is deliberately NOT narrowed: cors() reflects whatever the
// preflight asks about, which is what lets a caller send `x-ai-decision-key` at all, and
// listing a fixed set here would break any client that sends a header this file doesn't know.
app.use(cors({ exposedHeaders: ["X-Request-Id", "Server-Timing", "x-quota-reservation"] }));
app.use(express.json({ limit: "1mb" }));

const PORT = Number(process.env.PORT || 3001);
const BRIDGE_API_KEY = process.env.BRIDGE_API_KEY || "";
const ROCKETCHAT_WEBHOOK_URL = process.env.ROCKETCHAT_WEBHOOK_URL || "";
const OPENAI_BASE_URL = "https://api.openai.com/v1";
// v9 = NodeSend is the only quota backend. The decision algorithm that used to sit behind
// an external HTTPS service now runs in this process and reads and writes the quota tables
// in NCB directly with the caller's own bearer, so the external reserve/status/config hop
// and the variable that configured it are gone. `/ai/chat` still reserves before it
// dispatches and is still charged however the provider call turns out, and the caller's
// `x-ai-decision-key` header is still the idempotency key that makes one logical decision
// cost one call however many times a transport retries it. What did NOT move: session
// authentication, the decision contract the caller sees, fail-closed behaviour, and the
// provider dispatch order. One authoritative version constant — `/`, `/health` and every
// gate read it, so an operator can confirm from outside which build is answering.
const NODESEND_VERSION = "bridge-nodesend-quota-v9";
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
// This is the ONLY NCB access in this file: NCB owns the application data, and
// quota is decided by the BridgeMind quota service, not by a read here.
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

// NCB is called with the caller's own session token, exactly as the BridgeMind Express
// proxy used to do. That one helper now serves everything NCB-side: the session lookup and
// the quota reads and writes. No service credential is invented here — which is also why
// the counting is only correct while this process is the only one doing it: every call is
// authorised as the caller, so a request that never arrives cannot be counted.
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
      reservation = await reserveAiCall(req, res);
      if (!reservation.allowed) {
        const status = reservation.reason === "quota_service_unavailable" || reservation.reason === "auth_required"
          ? 503 : 429;
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
      // Whether this call was charged or an earlier one was reused is a header, never a
      // body field: the provider body stays byte-identical and clients that ignore
      // headers are unaffected. Absent on a request that carries no decision key,
      // because then there is nothing to distinguish.
      if (reservation.reservation) res.setHeader("x-quota-reservation", reservation.reservation);
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

// ── NODESEND QUOTA AUTHORITY (sole backend, NCB storage) ──────────────────
// Architecture, corrected 2026-10-04. NodeSend is the ONLY per-user quota authority:
// it decides, it stores, and it answers. NCB holds the state; BridgeMind is a static
// frontend that calls these routes and nothing else. The retired design forwarded every
// decision to an external service over a configured URL — that hop is gone, along with its
// endpoint builder, its remote state probe, its response allowlist and the environment
// variable that configured it. There is no second quota implementation here, and nothing in
// this file calls another backend for quota.
//
// SEMANTICS PORTED FROM the proven BridgeMind authority (server/quotaApi.js), kept
// deliberately identical so one rule set governs billing wherever it runs:
//   • identity comes ONLY from the validated session bearer (req.bridgeUser), never from
//     a body, query or header-supplied user id;
//   • global config -> per-user override -> usage for the current UTC period;
//   • quota_enabled false = unlimited and nothing is written;
//   • missing/duplicate/malformed config, override or usage rows fail CLOSED as 503 —
//     never a fabricated allowance, and never a `limit=1` that hides a duplicate;
//   • the reservation claim is taken BEFORE the counter is touched and released on every
//     failure exit, so a decision that was not billed is never left looking prepaid;
//   • a retry of an already-billed decision is allowed even at the cap;
//   • the caller's decision key travels in a request header and never in a body, because
//     buildProviderBody forwards every unrecognised body field straight to the provider.
//
// ONE REPLICA, STATED NOT CLAIMED. The NCB runtime Data API offers no atomic increment,
// no conditional arithmetic, no upsert, no SQL/RPC and no aggregation, so the counter is
// read-check-written here and `userLocks` is an in-memory Map. Two NodeSend replicas
// would each hold their own mutex, lose increments and silently exceed the cap. This is
// a deployment constraint the code cannot enforce — it is printed at startup and
// reported by /health so the assumption is never buried.
const QUOTA_TABLES = {
  config: String(process.env.AI_QUOTA_CONFIG_TABLE || "ai_quota_config").trim(),
  override: String(process.env.AI_QUOTA_USER_OVERRIDE_TABLE || "ai_quota_user_override").trim(),
  usage: String(process.env.AI_QUOTA_USAGE_TABLE || "ai_quota_usage").trim(),
  // The one table that may legitimately be switched OFF, so "set to empty" must not be
  // silently re-defaulted the way the other three are: `env || fallback` treats an empty
  // string as absent, which would make the process-only branch unreachable by
  // configuration and leave the startup warning dead. Unset therefore means the production
  // table (durable), and AI_QUOTA_RESERVATION_TABLE= means "no ledger, process-only".
  reservation: String(
    process.env.AI_QUOTA_RESERVATION_TABLE === undefined
      ? "ai_quota_reservation" : process.env.AI_QUOTA_RESERVATION_TABLE
  ).trim()
};
const QUOTA_ADMIN_ROLES = ["admin", "administrator"];
const QUOTA_LIMIT_MIN = 1;
const QUOTA_LIMIT_MAX = 100000;
const QUOTA_PERIOD_TYPE = "monthly";
const QUOTA_CONFIG_FIELDS = ["quota_enabled", "default_call_limit", "period_type"];
const QUOTA_UNAVAILABLE = "quota_service_unavailable";
const DECISION_KEY_HEADER = "x-ai-decision-key";
const DECISION_KEY_MAX_LENGTH = 128;
const DECISION_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9 ._:#+-]{0,127}$/u;
// Refused as "no usable key" rather than trusted as one: a client that stringifies a
// missing value sends these words, and accepting them would make every one of that
// client's decisions share one key — the ledger would then report "already billed" for
// genuinely new work. Dropping a key costs a dedupe; it never buys a free call.
const DECISION_KEY_UNSET_WORDS = /^(?:undefined|null|nan|\{\}|object|string)$/iu;
/* Which AI configuration is paying for this call, as a HEADER — like the decision key, and
   for the same mechanical reason: `buildProviderBody` removes only `provider` and `config`
   and forwards everything else to the provider, so a marker in the body would be sent to
   Alibaba/OpenAI as a parameter.

   DIAGNOSTIC ONLY, WITH ZERO BILLING AUTHORITY. Whether this account is governed by the
   System AI quota is decided server-side from `user_settings.ai_source`, resolved for the
   user id the SESSION authenticated (`resolveUserAiSource`), and by nothing else on this
   request: not this header, not a body field, not a credential, not a claimed role. That is
   the whole reason it cannot be decisional — the party that benefits from claiming "user"
   is the party writing the request.

   A value that disagrees with the stored source is logged as `ai_source_claim_mismatch` in
   BOTH directions and acted on in NEITHER. Forged values can therefore neither waive a
   charge nor impose one. Absent or unrecognised means "system", which is both BridgeMind's
   own default for an unset preference and the conservative answer for money: an old client
   keeps being billed rather than quietly escaping the counter.

   BridgeMind's current source no longer sends this header at all; a previously deployed
   build may still send one, and it is treated exactly like any other forged value — logged,
   never believed. */
const BILLING_SOURCE_HEADER = "x-ai-billing-source";
const BILLING_SOURCE_SYSTEM = "system";
const BILLING_SOURCE_USER = "user";

function requestBillingSource(req) {
  const raw = String(req.get(BILLING_SOURCE_HEADER) ?? "").trim().toLowerCase();
  return raw === BILLING_SOURCE_USER ? BILLING_SOURCE_USER : BILLING_SOURCE_SYSTEM;
}

const QUOTA_PROCESS_LEDGER_LIMIT = 5000;
const QUOTA_WRITE_METHODS = { create: "POST", update: "PUT", remove: "DELETE" };
// The deployment requirement, named once. NCB gives this process no atomic increment and no
// compare-and-swap, so the counter is only correct while exactly one replica runs it. Two
// replicas reading then writing the same row lose updates, and nothing in this file can
// detect a second replica — which is why the invariant is PRINTED (root, /health, startup)
// rather than merely asserted in code.
const QUOTA_SINGLE_REPLICA_INVARIANT = "exactly-one-quota-service-replica";

function isQuotaAdministratorRole(role) {
  return QUOTA_ADMIN_ROLES.includes(String(role ?? "").trim().toLowerCase());
}

// UTC calendar period key ("2026-10") and the first instant of the next UTC month.
// Both computed from an injected clock so the boundaries are testable, exactly as the
// ported implementation does.
function quotaPeriodKey(now = new Date()) {
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  return `${y}-${m}`;
}

function quotaPeriodReset(periodKey) {
  const parts = String(periodKey).split("-").map(Number);
  return new Date(Date.UTC(parts[0], parts[1], 1)).toISOString();
}

function quotaSqlDate(value) {
  return String(value).replace("T", " ").slice(0, 19);
}

function sanitizeDecisionKey(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > DECISION_KEY_MAX_LENGTH) return null;
  if (DECISION_KEY_UNSET_WORDS.test(trimmed)) return null;
  return DECISION_KEY_PATTERN.test(trimmed) ? trimmed : null;
}

function decisionKeyValue(req) {
  return sanitizeDecisionKey(typeof req?.get === "function" ? req.get(DECISION_KEY_HEADER) : null);
}

// NCB hands MySQL numerics back as strings and flags as 0/1 or true/false depending on
// the driver. Both are accepted; anything else is a malformed row, not a default.
function storedFlag(value) {
  if (typeof value === "boolean") return value ? 1 : 0;
  if (value === 0 || value === 1) return value;
  if (value === "0" || value === "1") return Number(value);
  return null;
}

function storedCount(value) {
  if (typeof value === "number" && Number.isInteger(value) && value >= 0) return value;
  if (typeof value === "string" && /^\d+$/.test(value.trim())) return Number(value.trim());
  return null;
}

// Strict on purpose: no coercion of "true" or "1". A client sending the wrong type is a
// bug that must answer 400 rather than silently write a flag.
function bodyFlag(value) {
  return typeof value === "boolean" ? (value ? 1 : 0) : null;
}

function bodyLimit(value) {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

// The measured NCB envelope is { status: "success", data: [...], metadata: {...} }.
// A status that contradicts a 2xx is refused rather than read as an empty table, which
// is what would otherwise turn a storage error into a fabricated allowance.
function envelopeRows(result) {
  if (!result?.ok) return { ok: false, reason: result?.reason || QUOTA_UNAVAILABLE };
  const payload = result.payload;
  if (payload && typeof payload === "object" && "status" in payload && payload.status !== "success") {
    return { ok: false, reason: "malformed_envelope" };
  }
  const rows = Array.isArray(payload?.data) ? payload.data : null;
  if (rows === null) return { ok: false, reason: "malformed_envelope" };
  return { ok: true, rows };
}

// ── the NCB data layer, called with the caller's own session bearer ────────
// Same transport, same proxy, same Instance parameter and the same caller token that
// /auth/get-session already uses — no service credential is invented and no second auth
// path exists. Table names and filters are the only additions, and the filter spelling is
// the one every working read in this application already uses.
async function quotaRead(req, path) {
  try {
    const response = await ncbRequest(req, path);
    if (!response?.ok) return { ok: false, reason: QUOTA_UNAVAILABLE };
    const payload = await response.json().catch(() => null);
    return payload === null ? { ok: false, reason: QUOTA_UNAVAILABLE } : { ok: true, payload };
  } catch {
    return { ok: false, reason: QUOTA_UNAVAILABLE };
  }
}

// The refusal reason is supplied by the operation, not invented here: "the counter row
// could not be created" and "the claim could not be recorded" are different facts, and an
// operator reading a quota_ audit line has to be able to tell them apart.
async function quotaWrite(req, method, path, body, failedReason) {
  try {
    const response = await ncbRequest(req, path, { method, body: JSON.stringify(body) });
    return response?.ok ? { ok: true } : { ok: false, reason: failedReason };
  } catch {
    return { ok: false, reason: failedReason };
  }
}

function quotaFilter(params) {
  return Object.keys(params)
    .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(params[key])}`)
    .join("&");
}

const quotaStore = {
  readConfig: (req) => quotaRead(req, `/data/read/${QUOTA_TABLES.config}`),
  readOverride: (req, userId) => quotaRead(req,
    `/data/read/${QUOTA_TABLES.override}?${quotaFilter({ user_id: userId })}`),
  // The override WRITE side, added for the administrator per-user limit route. Same
  // transport, same envelope, same absolute-value semantics as the counter write:
  // there is no increment here to lose, and a rejected write is reported, never
  // retried blind. `create`/`update` are chosen by whether a row already exists,
  // which the caller learns from `readOverride` in the same critical section.
  createOverride: (req, row) => quotaWrite(req, QUOTA_WRITE_METHODS.create,
    `/data/create/${QUOTA_TABLES.override}`, row, "override_create_failed"),
  updateOverride: (req, id, patch) => quotaWrite(req, QUOTA_WRITE_METHODS.update,
    `/data/update/${QUOTA_TABLES.override}/${encodeURIComponent(id)}`, patch, "override_update_failed"),
  readUsage: (req, userId, periodKey) => quotaRead(req,
    `/data/read/${QUOTA_TABLES.usage}?${quotaFilter({ user_id: userId, period_key: periodKey })}`),
  createUsage: (req, row) => quotaWrite(req, QUOTA_WRITE_METHODS.create,
    `/data/create/${QUOTA_TABLES.usage}`, row, "create_failed"),
  updateUsage: (req, id, patch) => quotaWrite(req, QUOTA_WRITE_METHODS.update,
    `/data/update/${QUOTA_TABLES.usage}/${encodeURIComponent(id)}`, patch, "update_failed"),
  updateConfig: (req, id, patch) => quotaWrite(req, QUOTA_WRITE_METHODS.update,
    `/data/update/${QUOTA_TABLES.config}/${encodeURIComponent(id)}`, patch, "update_failed"),
  // Existence-based lookup that also returns the row id, because a claim that has to be
  // withdrawn is deleted by id. Duplicate rows for one decision key are tolerated here:
  // two rows mean "already billed", which is a correct answer, not an integrity fault.
  findReservation: async (req, identity) => {
    const result = await quotaRead(req, `/data/read/${QUOTA_TABLES.reservation}?${quotaFilter({
      user_id: identity.userId, period_key: identity.periodKey, decision_key: identity.decisionKey
    })}`);
    if (!result.ok) return result;
    const rows = Array.isArray(result.payload?.data) ? result.payload.data : null;
    if (rows === null) return { ok: false, reason: "malformed_envelope" };
    if (rows.length === 0) return { ok: true, found: false, rowId: null };
    const rowId = rows[0]?.id;
    return { ok: true, found: true, rowId: rowId === undefined || rowId === null ? null : rowId };
  },
  createReservation: async (req, identity) => {
    const result = await quotaWrite(req, QUOTA_WRITE_METHODS.create,
      `/data/create/${QUOTA_TABLES.reservation}`, {
        user_id: identity.userId,
        period_key: identity.periodKey,
        decision_key: identity.decisionKey,
        created_at: quotaSqlDate(new Date().toISOString())
      }, "record_failed");
    // A rejected create is not an error yet: the caller re-reads the exact tuple to find
    // out whether someone else already holds this claim, so the response body is not
    // trusted to say which. The id of a row this request did create is passed back when
    // the surface happens to give one, and null otherwise.
    return result.ok ? { ok: true, rowId: result.rowId ?? null } : result;
  },
  deleteReservation: (req, rowId) => quotaWrite(req, QUOTA_WRITE_METHODS.remove,
    `/data/delete/${QUOTA_TABLES.reservation}/${encodeURIComponent(rowId)}`, undefined, "release_failed")
};

// Capability is all-or-nothing. A ledger that can be created but not deleted cannot
// support a rollback, so it is treated as no ledger at all rather than as half of one.
const quotaLedgerDurable = typeof quotaStore.findReservation === "function"
  && typeof quotaStore.createReservation === "function"
  && typeof quotaStore.deleteReservation === "function"
  && QUOTA_TABLES.reservation !== "";
const QUOTA_IDEMPOTENCY_MODE = quotaLedgerDurable ? "durable" : "process-only";

function quotaLedgerState() {
  return {
    authority: "nodesend", storage: "ncb",
    idempotency: QUOTA_IDEMPOTENCY_MODE,
    replicas: QUOTA_SINGLE_REPLICA_INVARIANT,
    note: "multi-replica quota counting unsupported"
  };
}

// The same facts under the field names an operator greps for, so /health and the startup
// line are readable without unfolding an object.
function quotaLedgerFields() {
  return {
    quotaAuthority: "nodesend",
    quotaStorage: "ncb",
    quotaIdempotency: QUOTA_IDEMPOTENCY_MODE,
    quotaReplicas: QUOTA_SINGLE_REPLICA_INVARIANT,
    quotaMultiReplica: "unsupported"
  };
}

// Audit lines carry a fixed label and a reason code only: never a bearer, a table name,
// a row id, a decision key or an NCB response.
function quotaAudit(event, detail) {
  safeEvent(`quota_${event}`, { reason: String(detail?.reason ?? "unknown") });
}

async function resolveQuotaConfig(req) {
  const resolved = envelopeRows(await quotaStore.readConfig(req));
  if (!resolved.ok) return resolved;
  const rows = resolved.rows;
  if (rows.length === 0) return { ok: false, reason: "config_missing" };
  if (rows.length > 1) return { ok: false, reason: "config_duplicate" };
  const row = rows[0] || {};
  const enabled = storedFlag(row.quota_enabled);
  if (enabled === null) return { ok: false, reason: "malformed_flag" };
  const limit = storedCount(row.default_call_limit);
  if (limit === null || limit < QUOTA_LIMIT_MIN || limit > QUOTA_LIMIT_MAX) {
    return { ok: false, reason: "malformed_limit" };
  }
  if (String(row.period_type ?? QUOTA_PERIOD_TYPE) !== QUOTA_PERIOD_TYPE) {
    return { ok: false, reason: "unsupported_period" };
  }
  return {
    ok: true, rowId: row.id,
    config: {
      quota_enabled: enabled === 1,
      default_call_limit: limit,
      period_type: QUOTA_PERIOD_TYPE,
      updated_at: row.updated_at ?? null
    }
  };
}

async function resolveQuotaLimit(req, userId, config) {
  const resolved = envelopeRows(await quotaStore.readOverride(req, userId));
  if (!resolved.ok) return resolved;
  const rows = resolved.rows;
  if (rows.length === 0) return { ok: true, limit: config.default_call_limit, source: "default" };
  if (rows.length > 1) return { ok: false, reason: "override_duplicate" };
  const row = rows[0] || {};
  const enabled = storedFlag(row.enabled);
  if (enabled === null) return { ok: false, reason: "malformed_flag" };
  if (enabled === 0) return { ok: true, limit: config.default_call_limit, source: "default" };
  const limit = storedCount(row.call_limit);
  if (limit === null || limit < QUOTA_LIMIT_MIN || limit > QUOTA_LIMIT_MAX) {
    return { ok: false, reason: "malformed_limit" };
  }
  return { ok: true, limit, source: "override" };
}

// One usage row per (user, period) is required. Duplicates are reported, never resolved
// by picking the first row, because silently billing one of two rows is exactly the
// defect a guard must refuse to hide.
// ── AUTHORITATIVE AI SOURCE: who is paying for this account's AI ───────────
// SECURITY: the System-AI quota may only ever be waived on the strength of THIS
// lookup. A client-supplied header, body field, credential or role is a HINT with
// zero billing authority, because the party that benefits from being marked "own AI"
// is the party writing the request. A forged `x-ai-billing-source: user` while still
// using the System's credential must therefore be billed anyway — that is the whole
// reason this function exists and the reason it is read here rather than trusted
// from the request.
//
// The authority is the same column the app itself uses: `user_settings.ai_source`,
// written as the literal 'user' only when the player chose their own AI
// (settingsService.js:49) and read back the same way (:72). So the semantics are
// the app's, not invented here: literal 'user' ⇒ Own AI; everything else, including
// no row, an unrecognised value, a malformed row or a failed read, ⇒ System AI.
//
// Every ambiguity resolves toward BILLING, never toward free usage:
//   read failure        → system   (the quota still applies)
//   no settings row     → system   (an account that never chose has the app default)
//   unrecognised value  → system
//   duplicate rows      → system   (never exempt on an ambiguous record; and unlike
//                                   config/override duplicates this cannot 503 a chat,
//                                   because refusing a call that was perfectly payable
//                                   would be a worse answer than charging it)
// This adds NO new transport call site: the lookup goes through the same read-only
// `quotaRead` the config, override and usage reads already use, so the relay still has
// exactly three awaited `ncbRequest` sites (session, read, write) — now over a fifth
// table. `verify-session-quota.mjs` pins that count and additionally pins that
// `user_settings` is only ever READ, never written, from this process.
const USER_SETTINGS_TABLE = "user_settings";
const AI_SOURCE_SYSTEM = "system";
const AI_SOURCE_OWN = "user";
const AI_SOURCE_CACHE_TTL_MS = 45000;     // in-range: 30–60s, so an admin/user change lands quickly
const AI_SOURCE_FAILURE_CACHE_TTL_MS = 5000; // a blip must not stick for a whole TTL
const aiSourceCache = new Map();
const aiSourceInFlight = new Map();

function aiSourceFromRows(rows) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return { aiSource: AI_SOURCE_SYSTEM, cached: true, reason: "no_settings_row" };
  }
  if (rows.length > 1) {
    return { aiSource: AI_SOURCE_SYSTEM, cached: true, reason: "settings_duplicate" };
  }
  const raw = rows[0]?.ai_source;
  if (raw === undefined || raw === null || raw === "") {
    return { aiSource: AI_SOURCE_SYSTEM, cached: true, reason: "no_settings_row" };
  }
  const value = typeof raw === "string" ? raw.trim().toLowerCase() : raw;
  if (value === AI_SOURCE_OWN) return { aiSource: AI_SOURCE_OWN, cached: true, reason: null };
  if (value === AI_SOURCE_SYSTEM) return { aiSource: AI_SOURCE_SYSTEM, cached: true, reason: null };
  return { aiSource: AI_SOURCE_SYSTEM, cached: true, reason: "unrecognised_value" };
}

// The lookup itself, with no cache, so the cache can be tested against it.
async function readUserAiSource(req, userId) {
  const result = await quotaRead(req,
    `/data/read/${USER_SETTINGS_TABLE}?${quotaFilter({ user_id: userId })}`);
  if (!result.ok) return { aiSource: AI_SOURCE_SYSTEM, cached: false, reason: result.reason || QUOTA_UNAVAILABLE };
  const resolved = envelopeRows(result);
  if (!resolved.ok) return { aiSource: AI_SOURCE_SYSTEM, cached: false, reason: resolved.reason };
  return aiSourceFromRows(resolved.rows);
}

async function resolveUserAiSource(req, userId, { force = false } = {}) {
  const key = userId == null ? "" : String(userId).trim();
  // No identity, no exemption. Every caller of this is on a path that has already
  // authenticated, so this branch is a guard against a future misuse rather than a
  // live route, and it answers System AI for the same reason everything else does.
  if (!key) return { aiSource: AI_SOURCE_SYSTEM, cached: false, reason: "no_identity" };
  const now = Date.now();
  if (!force) {
    const hit = aiSourceCache.get(key);
    if (hit && hit.expiresAt > now) return { aiSource: hit.aiSource, cached: true, reason: hit.reason ?? null };
  }
  // One read per user across concurrent requests: the cache is the point, and N
  // simultaneous calls without a join would be N reads that all answer the same.
  const pending = aiSourceInFlight.get(key);
  if (pending) return pending;
  const run = (async () => {
    const outcome = await readUserAiSource(req, key);
    // A failure is remembered only briefly, and never as an exemption: the cached
    // value on a failed read is System AI, so the worst a blip can do is keep
    // charging an account for a few more seconds.
    aiSourceCache.set(key, {
      aiSource: outcome.aiSource,
      expiresAt: now + (outcome.cached ? AI_SOURCE_CACHE_TTL_MS : AI_SOURCE_FAILURE_CACHE_TTL_MS),
      reason: outcome.reason ?? null
    });
    return { aiSource: outcome.aiSource, cached: outcome.cached, reason: outcome.reason ?? null };
  })().finally(() => {
    aiSourceInFlight.delete(key);
  });
  aiSourceInFlight.set(key, run);
  return run;
}

// The exemption test, spelled once so no call site can "forget" the authority and
// read a header instead.
async function quotaIsApplicableToUser(req, userId) {
  const resolved = await resolveUserAiSource(req, userId);
  return { quotaApplies: resolved.aiSource !== AI_SOURCE_OWN, resolved };
}

// Test seam, and the hook a future settings-write notification would use. Dropping one
// entry is enough for the next request to re-read, which is how a change made through
// a path this relay can observe would propagate without waiting out the TTL.
function resetAiSourceCache(userId) {
  if (userId === undefined || userId === null || userId === "") {
    aiSourceCache.clear();
    aiSourceInFlight.clear();
    return 0;
  }
  const key = String(userId).trim();
  const had = aiSourceCache.delete(key);
  aiSourceInFlight.delete(key);
  return had ? 1 : 0;
}

async function resolveQuotaUsage(req, userId, periodKey) {
  const resolved = envelopeRows(await quotaStore.readUsage(req, userId, periodKey));
  if (!resolved.ok) return resolved;
  const rows = resolved.rows;
  if (rows.length === 0) return { ok: true, row: null, used: 0 };
  if (rows.length > 1) return { ok: false, reason: "usage_duplicate" };
  const used = storedCount(rows[0]?.calls_used);
  if (used === null) return { ok: false, reason: "malformed_usage" };
  const rowId = rows[0]?.id;
  if (rowId === undefined || rowId === null || rowId === "") {
    return { ok: false, reason: "usage_unaddressable" };
  }
  return { ok: true, row: rows[0], rowId, used };
}

function quotaView(fields) {
  const period = quotaPeriodKey();
  return {
    enabled: fields.enabled, unlimited: fields.unlimited, used: fields.used,
    limit: fields.limit, remaining: fields.remaining, percentage: fields.percentage,
    period, resetAt: quotaPeriodReset(period)
  };
}

function quotaDisabledView() {
  return quotaView({ enabled: false, unlimited: true, used: 0, limit: null, remaining: null, percentage: 0 });
}

/* The System AI quota bounds what the SYSTEM pays for. A call the account funds with its
   own provider key is outside that ledger entirely, so it is none of: "0 used", "not
   exhausted", or "unlimited" — each of those is a statement about a counter this request
   never touched. Every figure is null, exactly as an unreadable counter reports itself,
   and the single positive fact carried is the reason. `allowed` is true because nothing
   about the call is refused; the quota simply does not apply to it. */
function quotaNotApplicableView() {
  return {
    allowed: true,
    quota_applies: false,
    reason: "billing_source_own_ai",
    enabled: false,
    unlimited: false,
    used: null,
    limit: null,
    remaining: null,
    percentage: null,
    period: null,
    resetAt: null
  };
}

function quotaBoundedView(used, limit) {
  return quotaView({
    enabled: true, unlimited: false, used, limit,
    remaining: Math.max(0, limit - used),
    percentage: limit > 0 ? Math.round((used / limit) * 100) : 0
  });
}

// An outage carries no numbers at all, so nothing can be read as headroom. It also
// carries no bespoke cause: a reason the caller does not know would be coerced into
// exhaustion and tell a user they ran out when our own storage is unreachable.
function quotaUnavailable() {
  return { allowed: false, reason: QUOTA_UNAVAILABLE };
}

// The ONLY mutex over the quota ledger, and the only writer of ai_quota_usage.
const userLocks = new Map();

async function withUserLock(userId, run) {
  while (userLocks.has(userId)) {
    await userLocks.get(userId);
  }
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  userLocks.set(userId, pending);
  try {
    return await run();
  } finally {
    userLocks.delete(userId);
    release();
  }
}

const processLedger = new Map();
const ledgerEntry = (userId, period, key) => `${userId}\u0000${period}\u0000${key}`;

// Introspection for the harness only — no route reads or clears these. A gate must be able
// to start a scenario from an empty ledger, and no HTTP route can reset process state.
// userLockCount is how a gate proves the mutex is one lock per user, not a queue per
// request: two concurrent calls for the same user never show depth two at once. The locks
// map is deliberately NOT clearable: a lock is held only for the duration of one decision,
// so clearing it could only ever corrupt a running process.
function resetQuotaProcessLedger() {
  processLedger.clear();
}
function quotaProcessLedgerSize() {
  return processLedger.size;
}
function userLockCount() {
  return userLocks.size;
}

async function findReservation(req, userId, period, key) {
  if (!key) return { ok: true, found: false, rowId: null };
  if (quotaLedgerDurable) {
    const result = await quotaStore.findReservation(req, { userId, periodKey: period, decisionKey: key });
    if (!result?.ok) return { ok: false, reason: result?.reason || QUOTA_UNAVAILABLE };
    return { ok: true, found: result.found === true, rowId: result.rowId ?? null };
  }
  const entry = processLedger.get(ledgerEntry(userId, period, key));
  return { ok: true, found: entry !== undefined, rowId: entry ?? null };
}

// Takes the claim before anything touches the counter. It never increments, never
// creates a usage row and never decides the limit. A rejected create is not an error yet:
// it may mean another request holds this exact tuple, so the tuple is re-read and a found
// row becomes REUSED rather than a charge.
async function claimReservation(req, userId, period, key) {
  if (!key) return { ok: true, claimed: false, rowId: null, reason: "no_key" };
  if (quotaLedgerDurable) {
    const created = await quotaStore.createReservation(req, { userId, periodKey: period, decisionKey: key });
    if (created?.ok) return { ok: true, claimed: true, rowId: created.rowId ?? null, reason: null };
    const after = await findReservation(req, userId, period, key);
    if (!after.ok) return { ok: false, claimed: false, rowId: null, reason: after.reason };
    return after.found
      ? { ok: true, claimed: false, rowId: after.rowId, reason: "already_claimed" }
      : { ok: false, claimed: false, rowId: null, reason: created?.reason || "record_failed" };
  }
  const entry = ledgerEntry(userId, period, key);
  if (processLedger.has(entry)) return { ok: true, claimed: false, rowId: entry, reason: "already_claimed" };
  if (processLedger.size >= QUOTA_PROCESS_LEDGER_LIMIT) {
    processLedger.delete(processLedger.keys().next().value);
  }
  processLedger.set(entry, entry);
  return { ok: true, claimed: true, rowId: entry, reason: null };
}

// Withdraws a claim whose charge did not land. A claim surviving an unbilled decision is
// the one outcome that must never be silent, so a failed release is reported to the
// caller as release_refused and logged; the request still answers with the real failure.
async function releaseReservation(req, userId, period, key, claim) {
  if (!claim?.claimed) return { ok: true, released: false, reason: "nothing_claimed" };
  if (!quotaLedgerDurable) {
    if (claim.rowId) processLedger.delete(claim.rowId);
    return { ok: true, released: true, reason: null };
  }
  // The id is resolved on this rare path rather than paid for on every successful
  // reservation: a create normally hands no id back.
  let rowId = claim.rowId;
  if (rowId === null || rowId === undefined || rowId === "") {
    const located = await quotaStore.findReservation(req, { userId, periodKey: period, decisionKey: key });
    if (!located?.ok) return { ok: false, released: false, reason: located?.reason || "release_unaddressable" };
    if (located.found !== true) return { ok: true, released: false, reason: "already_gone" };
    rowId = located.rowId ?? null;
    if (rowId === null) return { ok: false, released: false, reason: "claim_unaddressable" };
  }
  const deleted = await quotaStore.deleteReservation(req, rowId);
  return deleted?.ok
    ? { ok: true, released: true, reason: null }
    : { ok: false, released: false, reason: deleted?.reason || "release_failed" };
}

// One logical AI decision spends at most one unit. The request BODY is never read for
// identity, so a user_id planted in it cannot impersonate anybody, and a malformed key is
// validated to nothing rather than trusted. Outcomes (`reservation`, `claim`) live on the
// result object only, never in a response body.
async function reserveQuotaDecision(req, user) {
  const key = decisionKeyValue(req);
  // Own-key accounts stop here, BEFORE any storage read: no config read, no override
  // read, no reservation, no increment. A request that is not spending the System's
  // money must not touch the System's ledger even to discover it is exempt.
  //
  // SECURITY: the exemption is granted ONLY by `resolveUserAiSource`, which reads
  // user_settings.ai_source for the id the SESSION resolved. Nothing on this request —
  // not a header, not a body field, not a credential, not a claimed role — can move
  // this decision, because the party that benefits from claiming "own AI" is the party
  // writing the request. A forged header is at most a log line (see below).
  const applicability = await quotaIsApplicableToUser(req, user?.id);
  const authoritative = applicability.resolved.aiSource;
  const claimed = requestBillingSource(req);
  // Diagnostic, in BOTH directions, and never decisional. The interesting case is
  // `claimed=user` with `authoritative=system`: somebody trying to step outside the
  // quota while still spending the System's credential. Recording it is worth one
  // line; acting on it would hand the attacker the switch.
  if (claimed !== authoritative) {
    quotaAudit("ai_source_claim_mismatch", { userId: user?.id ?? null, claimed, authoritative });
  }
  if (!applicability.quotaApplies) {
    quotaAudit("reserve_not_applicable", { userId: user?.id ?? null, key: key ?? null });
    return { status: 200, body: quotaNotApplicableView(), reservation: "unbilled" };
  }
  const config = await resolveQuotaConfig(req);
  if (!config.ok) {
    quotaAudit("reserve_refused", config);
    return { status: 503, body: quotaUnavailable(), cause: config.reason };
  }
  if (!config.config.quota_enabled) {
    return { status: 200, body: { allowed: true, ...quotaDisabledView() }, reservation: "unbilled" };
  }
  const limit = await resolveQuotaLimit(req, user.id, config.config);
  if (!limit.ok) {
    quotaAudit("reserve_refused", limit);
    return { status: 503, body: quotaUnavailable(), cause: limit.reason };
  }
  const period = quotaPeriodKey();
  // Lookup, claim, cap test, read and write all sit inside one per-user lock, and the
  // claim precedes the charge. Charge-then-claim left a crash window in which a billed
  // decision had no record, so a restart charged the same decision twice.
  const answer = await withUserLock(user.id, async () => {
    const prior = await findReservation(req, user.id, period, key);
    if (!prior.ok) return { status: 503, body: quotaUnavailable(), cause: prior.reason };
    if (prior.found) return reusedQuotaAnswer(req, user.id, period, limit.limit);

    const claim = await claimReservation(req, user.id, period, key);
    if (!claim.ok) {
      quotaAudit("claim_refused", claim);
      return { status: 503, body: quotaUnavailable(), cause: claim.reason, claim: "none" };
    }
    if (claim.reason === "already_claimed") return reusedQuotaAnswer(req, user.id, period, limit.limit);

    const release = async () => {
      const back = await releaseReservation(req, user.id, period, key, claim);
      if (!back.ok) {
        quotaAudit("claim_release_refused", back);
        return "release_refused";
      }
      return back.released ? "released" : "none";
    };

    const usage = await resolveQuotaUsage(req, user.id, period);
    if (!usage.ok) {
      const claimState = await release();
      return { status: 503, body: quotaUnavailable(), cause: usage.reason, claim: claimState };
    }
    if (usage.used >= limit.limit) {
      const claimState = await release();
      return {
        status: 429,
        body: { allowed: false, reason: "quota_exhausted", ...quotaBoundedView(usage.used, limit.limit) },
        reservation: "unreserved", claim: claimState
      };
    }

    let used = null;
    if (usage.row === null) {
      const created = await quotaStore.createUsage(req, {
        user_id: user.id, period_key: period, calls_used: 1, applied_limit: limit.limit
      });
      if (!created?.ok) {
        const claimState = await release();
        return {
          status: 503, body: quotaUnavailable(),
          cause: created?.reason || "create_failed", claim: claimState
        };
      }
      used = 1;
    } else {
      const next = usage.used + 1;
      const updated = await quotaStore.updateUsage(req, usage.rowId, {
        calls_used: next, applied_limit: limit.limit,
        updated_at: quotaSqlDate(new Date().toISOString())
      });
      if (!updated?.ok) {
        const claimState = await release();
        return {
          status: 503, body: quotaUnavailable(),
          cause: updated?.reason || "update_failed", claim: claimState
        };
      }
      used = next;
    }

    return {
      status: 200, body: { allowed: true, ...quotaBoundedView(used, limit.limit) },
      reservation: key ? "created" : "charged", claim: key ? "held" : "none"
    };
  });
  if (answer.cause) quotaAudit("reserve_refused", { reason: answer.cause });
  return answer;
}

// Already claimed means already billed: the counter is READ, never written, and the call
// is allowed even at the cap — refusing now would discard paid-for work and punish the
// retry the transport is obliged to make.
async function reusedQuotaAnswer(req, userId, period, limit) {
  const current = await resolveQuotaUsage(req, userId, period);
  if (!current.ok) return { status: 503, body: quotaUnavailable(), cause: current.reason };
  return {
    status: 200, body: { allowed: true, ...quotaBoundedView(current.used, limit) },
    reservation: "reused", claim: "none"
  };
}

async function quotaStatusDecision(req, user) {
  const config = await resolveQuotaConfig(req);
  if (!config.ok) {
    quotaAudit("status_refused", config);
    return { status: 503, body: quotaUnavailable(), cause: config.reason };
  }
  if (!config.config.quota_enabled) {
    return { status: 200, body: { allowed: true, ...quotaDisabledView() } };
  }
  const limit = await resolveQuotaLimit(req, user.id, config.config);
  if (!limit.ok) {
    quotaAudit("status_refused", limit);
    return { status: 503, body: quotaUnavailable(), cause: limit.reason };
  }
  const usage = await resolveQuotaUsage(req, user.id, quotaPeriodKey());
  if (!usage.ok) {
    quotaAudit("status_refused", usage);
    return { status: 503, body: quotaUnavailable(), cause: usage.reason };
  }
  return {
    status: 200,
    body: { allowed: usage.used < limit.limit, ...quotaBoundedView(usage.used, limit.limit) }
  };
}

async function quotaConfigReadDecision(req, user) {
  if (!user) return { status: 401, body: { error: "Authentication required" } };
  if (!isQuotaAdministratorRole(user.role)) return { status: 403, body: { error: "Admin access required" } };
  const config = await resolveQuotaConfig(req);
  if (!config.ok) {
    quotaAudit("config_read_refused", config);
    return { status: 503, body: quotaUnavailable(), cause: config.reason };
  }
  return { status: 200, body: config.config };
}

// Partial update: an absent field keeps its stored value, so flipping the switch cannot
// silently reset the cap. An unrecognised field answers 400 instead of being dropped, and
// the stored row is read back and compared before anything is reported as saved.
async function quotaConfigWriteDecision(req, user, requestBody) {
  if (!user) return { status: 401, body: { error: "Authentication required" } };
  if (!isQuotaAdministratorRole(user.role)) return { status: 403, body: { error: "Admin access required" } };
  const body = requestBody && typeof requestBody === "object" && !Array.isArray(requestBody) ? requestBody : {};
  const keys = Object.keys(body).filter((key) => body[key] !== undefined);
  if (keys.some((key) => !QUOTA_CONFIG_FIELDS.includes(key))) {
    return { status: 400, body: { error: "Unrecognised quota config field" } };
  }
  const current = await resolveQuotaConfig(req);
  if (!current.ok) {
    quotaAudit("config_write_refused", current);
    return { status: 503, body: quotaUnavailable(), cause: current.reason };
  }
  const next = { ...current.config };
  if (keys.includes("quota_enabled")) {
    const flag = bodyFlag(body.quota_enabled);
    if (flag === null) return { status: 400, body: { error: "quota_enabled must be a boolean" } };
    next.quota_enabled = flag === 1;
  }
  if (keys.includes("default_call_limit")) {
    const value = bodyLimit(body.default_call_limit);
    if (value === null || value < QUOTA_LIMIT_MIN || value > QUOTA_LIMIT_MAX) {
      return { status: 400, body: { error: "default_call_limit must be an integer between 1 and 100000" } };
    }
    next.default_call_limit = value;
  }
  if (keys.includes("period_type")) {
    if (body.period_type !== QUOTA_PERIOD_TYPE) {
      return { status: 400, body: { error: "period_type supports monthly only" } };
    }
    next.period_type = QUOTA_PERIOD_TYPE;
  }
  const written = await quotaStore.updateConfig(req, current.rowId, {
    quota_enabled: next.quota_enabled ? 1 : 0,
    default_call_limit: next.default_call_limit,
    period_type: next.period_type,
    updated_at: quotaSqlDate(new Date().toISOString())
  });
  if (!written?.ok) {
    quotaAudit("config_write_refused", { reason: written?.reason || "update_failed" });
    return { status: 503, body: quotaUnavailable(), cause: written?.reason || "update_failed" };
  }
  const readBack = await resolveQuotaConfig(req);
  if (!readBack.ok) {
    quotaAudit("config_readback_refused", readBack);
    return { status: 503, body: quotaUnavailable(), cause: readBack.reason };
  }
  if (readBack.config.quota_enabled !== next.quota_enabled
    || readBack.config.default_call_limit !== next.default_call_limit
    || readBack.config.period_type !== next.period_type) {
    quotaAudit("config_write_refused", { reason: "readback_mismatch" });
    return { status: 503, body: quotaUnavailable(), cause: "readback_mismatch" };
  }
  return { status: 200, body: readBack.config };
}

// ── route-facing adapters ─────────────────────────────────────────────────
// Names and return shapes are the ones relayAI and the routes already used, so the
// provider-dispatch ordering did not change with the storage: only the inside moved.
// Called BEFORE provider dispatch; a denial must never reach a provider.
async function reserveAiCall(req, res) {
  if (!req.bridgeUser?.id) return { allowed: false, reason: "auth_required", quota: null };
  const decision = await reserveQuotaDecision(req, req.bridgeUser);
  const body = decision.body || {};
  if (body.allowed === true) {
    const { allowed, reason, ...summary } = body;
    return {
      allowed: true, reason: summary.unlimited === true ? "quota_disabled" : null, quota: summary,
      // Kept out of the JSON body — the ledger is a server-side concern — and reported to
      // the caller as `x-quota-reservation` so it can tell a charge from a reuse.
      reservation: decision.reservation ?? null, claim: decision.claim ?? null
    };
  }
  const reason = body.reason === "quota_exhausted" ? "quota_exhausted" : QUOTA_UNAVAILABLE;
  const { allowed, reason: _reason, ...summary } = body;
  return {
    allowed: false,
    reason,
    // An outage reports no figures at all, so a failure can never be drawn as headroom.
    quota: reason === "quota_exhausted" ? summary : null
  };
}

async function getQuotaStatus(req, res) {
  if (!req.bridgeUser?.id) return { enabled: false, unlimited: false, error: "auth_required" };
  const decision = await quotaStatusDecision(req, req.bridgeUser);
  const body = decision.body || {};
  if (decision.status === 503) {
    return {
      enabled: true, unlimited: false, error: QUOTA_UNAVAILABLE,
      used: null, limit: null, remaining: null, percentage: null
    };
  }
  const { allowed, ...summary } = body;
  return summary;
}

// ── ADMIN QUOTA CONFIG (owned here, role-gated on the validated session) ───
// An ordinary user is refused before any NCB call is made, so a denied admin action
// cannot cost a read or a write.
// The role still comes from the validated session only, and both spellings the
// app's own isAdministrator() accepts are honoured, so a user the admin UI shows
// as an administrator is never locked out of the panel.
// ── ADMIN PER-USER QUOTA: authoritative view, and the custom limit ──────────
// Both decisions take the TARGET user id from the route and the CALLER's right to ask
// from the validated session role (`requireBridgeAdmin` runs before either handler).
// The target's AI source is resolved from `user_settings` here — never from the
// frontend's label, which is a display value the browser chose, and never from a
// header. A non-admin therefore cannot enumerate anybody's quota, and an admin cannot
// be talked into editing a limit that the quota will never consult.
async function quotaOverrideRow(req, userId) {
  const resolved = envelopeRows(await quotaStore.readOverride(req, userId));
  if (!resolved.ok) return resolved;
  const rows = resolved.rows;
  if (rows.length === 0) return { ok: true, row: null };
  // Duplicates are reported, never resolved by taking the first: `resolveQuotaLimit`
  // already refuses to bill against an ambiguous override, so the admin view must
  // refuse to describe one too.
  if (rows.length > 1) return { ok: false, reason: "override_duplicate" };
  const row = rows[0] || {};
  return {
    ok: true,
    row: {
      id: row.id ?? null,
      enabled: storedFlag(row.enabled),
      callLimit: storedCount(row.call_limit)
    }
  };
}

async function quotaAdminStatusDecision(req, targetUserId) {
  const userId = String(targetUserId ?? "").trim();
  if (!userId) return { status: 400, body: { error: "user_id is required" } };
  const source = await resolveUserAiSource(req, userId, { force: true });
  const base = { userId, aiSource: source.aiSource, sourceReason: source.reason ?? null };
  const override = await quotaOverrideRow(req, userId);
  if (!override.ok) return { status: 503, body: { error: QUOTA_UNAVAILABLE, reason: override.reason } };

  if (source.aiSource === AI_SOURCE_OWN) {
    // No System figures exist for this account, so none are invented. The stored
    // override is still reported — that is how an admin sees that a limit survived
    // the switch to personal AI and will apply again if the account returns.
    return {
      status: 200,
      body: {
        ...base,
        quotaApplies: false,
        period: null,
        globalLimit: null,
        used: null,
        overrideEnabled: override.row ? override.row.enabled : null,
        overrideLimit: override.row ? override.row.callLimit : null,
        effectiveLimit: null,
        remaining: null,
        percentage: null,
        dormantOverride: Boolean(override.row && override.row.enabled === 1)
      }
    };
  }

  const config = await resolveQuotaConfig(req);
  if (!config.ok) return { status: 503, body: { error: QUOTA_UNAVAILABLE, reason: config.reason } };
  const limit = await resolveQuotaLimit(req, userId, config.config);
  if (!limit.ok) return { status: 503, body: { error: QUOTA_UNAVAILABLE, reason: limit.reason } };
  const usage = await resolveQuotaUsage(req, userId, quotaPeriodKey());
  if (!usage.ok) return { status: 503, body: { error: QUOTA_UNAVAILABLE, reason: usage.reason } };
  const used = usage.used ?? 0;
  const effective = limit.limit;
  return {
    status: 200,
    body: {
      ...base,
      quotaApplies: true,
      period: quotaPeriodKey(),
      globalLimit: config.config.default_call_limit,
      used,
      overrideEnabled: override.row ? override.row.enabled : null,
      overrideLimit: override.row ? override.row.callLimit : null,
      // `source` is 'override' | 'default' straight from the resolver the counter uses,
      // so the number an admin reads here is computed by the same code that decides
      // whether a call is exhausted — not by a second calculation that could drift.
      effectiveLimit: effective,
      limitSource: limit.source,
      remaining: Math.max(0, effective - used),
      percentage: effective > 0 ? Math.round((used / effective) * 100) : 0,
      dormantOverride: false
    }
  };
}

/* Write (or clear) one account's custom limit.
   Ordering matters: the authoritative source check happens BEFORE any mutation, so a
   request aimed at an Own-AI account cannot reach storage at all — the answer is a
   409 that names why, not a row that silently does nothing. `enabled` is the flag the
   existing resolver already honours (`resolveQuotaLimit` returns the global default for
   enabled = 0), so "return to global" is written the same way the quota reads it, and
   no delete verb is invented to get there. The usage counter is never touched. */
async function quotaAdminLimitDecision(req, targetUserId, body) {
  const userId = String(targetUserId ?? "").trim();
  if (!userId) return { status: 400, body: { error: "user_id is required" } };
  const enabled = bodyFlag(body?.enabled);
  if (enabled === null) return { status: 400, body: { error: "enabled must be a boolean" } };
  let callLimit = null;
  if (enabled === 1) {
    callLimit = bodyLimit(body?.call_limit);
    if (callLimit === null || callLimit < QUOTA_LIMIT_MIN || callLimit > QUOTA_LIMIT_MAX) {
      return { status: 400, body: { error: "call_limit must be an integer within the allowed range" } };
    }
  }
  const source = await resolveUserAiSource(req, userId, { force: true });
  if (source.aiSource !== AI_SOURCE_SYSTEM) {
    return { status: 409, body: { reason: "user_not_using_system_ai", aiSource: source.aiSource } };
  }
  const existing = await quotaOverrideRow(req, userId);
  if (!existing.ok) {
    return { status: 503, body: { error: QUOTA_UNAVAILABLE, reason: existing.reason } };
  }
  const row = existing.row;
  const patch = { enabled, call_limit: enabled === 1 ? callLimit : 0 };
  const written = row && row.id !== null && row.id !== undefined
    ? await quotaStore.updateOverride(req, row.id, patch)
    : await quotaStore.createOverride(req, { user_id: userId, ...patch });
  if (!written.ok) {
    return { status: 503, body: { error: QUOTA_UNAVAILABLE, reason: written.reason || "write_failed" } };
  }
  // Read back and compare, exactly as the global config write does: a stored value
  // that differs from what was sent is an outage-shaped answer, not a success.
  const after = await quotaOverrideRow(req, userId);
  if (!after.ok) return { status: 503, body: { error: QUOTA_UNAVAILABLE, reason: after.reason } };
  const storedEnabled = after.row ? after.row.enabled : null;
  const storedLimit = after.row ? after.row.callLimit : null;
  const matches = storedEnabled === enabled
    && (enabled === 0 || storedLimit === callLimit);
  if (!matches) {
    return { status: 503, body: { error: QUOTA_UNAVAILABLE, reason: "readback_mismatch" } };
  }
  const config = await resolveQuotaConfig(req);
  if (!config.ok) return { status: 503, body: { error: QUOTA_UNAVAILABLE, reason: config.reason } };
  const effective = await resolveQuotaLimit(req, userId, config.config);
  if (!effective.ok) return { status: 503, body: { error: QUOTA_UNAVAILABLE, reason: effective.reason } };
  return {
    status: 200,
    body: {
      userId,
      aiSource: AI_SOURCE_SYSTEM,
      quotaApplies: true,
      overrideEnabled: enabled,
      overrideLimit: enabled === 1 ? callLimit : null,
      globalLimit: config.config.default_call_limit,
      effectiveLimit: effective.limit,
      limitSource: effective.source
    }
  };
}

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

// Thin HTTP wrappers over the two config decisions above: authenticate from the session,
// run the decision, send its status and its bounded body. The storage is never described
// to the caller — no row id, no table name, no NCB response, no free-text database error.
async function readQuotaConfigHandler(req, res) {
  const requestId = req.nodeSendRequestId || requestIdentity(req, res);
  const decision = await quotaConfigReadDecision(req, req.bridgeUser);
  if (decision.status !== 200) {
    safeEvent("quota_configuration_unavailable", { requestId, status: decision.status });
    return res.status(decision.status).json({
      success: false, status: decision.status === 503 ? QUOTA_UNAVAILABLE : "forbidden",
      error: decision.body?.error || "Quota configuration unavailable", requestId
    });
  }
  safeEvent("quota_configuration_served", { requestId, userId: req.bridgeUser?.id ?? null });
  return res.status(200).json({ success: true, ...decision.body, requestId });
}

async function writeQuotaConfigHandler(req, res) {
  const requestId = req.nodeSendRequestId || requestIdentity(req, res);
  const decision = await quotaConfigWriteDecision(req, req.bridgeUser, req.body);
  if (decision.status !== 200) {
    // The status and a stable code tell an admin the truth — the write was refused — and
    // the reason stays in the log. A validation refusal must never be reported as saved.
    safeEvent("quota_configuration_rejected", {
      requestId, status: decision.status, reason: String(decision.cause ?? decision.body?.error ?? "rejected")
    });
    return res.status(decision.status).json({
      success: false, status: decision.status === 400 ? "invalid_quota_configuration"
        : decision.status === 503 ? QUOTA_UNAVAILABLE : "forbidden",
      error: decision.body?.error || "Quota configuration could not be saved", requestId
    });
  }
  safeEvent("quota_configuration_updated", {
    requestId, userId: req.bridgeUser?.id ?? null,
    quota_enabled: typeof decision.body.quota_enabled === "boolean" ? decision.body.quota_enabled : null,
    default_call_limit: Number.isFinite(Number(decision.body.default_call_limit))
      ? Number(decision.body.default_call_limit) : null
  });
  return res.status(200).json({ success: true, ...decision.body, requestId });
}

// The two administrator per-user quota routes. `requireBridgeAdmin` runs before these,
// so a denied caller is refused before any NCB read — enumeration costs nothing without
// the role. The TARGET id is read here and nowhere else: it names whose quota to look
// at, it is never whose quota to BILL (that stays `req.bridgeUser.id`), and it is never
// taken from a chat request at all.
async function quotaAdminStatusHandler(req, res) {
  const requestId = req.nodeSendRequestId || requestIdentity(req, res);
  const decision = await quotaAdminStatusDecision(req, req.query?.user_id);
  if (decision.status !== 200) {
    safeEvent("quota_admin_status_unavailable", {
      requestId, target: String(req.query?.user_id ?? "").slice(0, 64), status: decision.status,
      reason: String(decision.body?.reason ?? decision.body?.error ?? "unavailable")
    });
    return res.status(decision.status).json({
      success: false, status: decision.status === 400 ? "invalid_user" : QUOTA_UNAVAILABLE,
      // The stable reason travels to the admin as well as to the log: "the override
      // row is duplicated" and "storage did not answer" are different things to
      // investigate, and an admin looking at a 503 should not have to guess which.
      reason: decision.body?.reason ?? null,
      error: decision.body?.error || "Quota status unavailable", requestId
    });
  }
  safeEvent("quota_admin_status_served", {
    requestId, userId: req.bridgeUser?.id ?? null,
    target: decision.body.userId, aiSource: decision.body.aiSource, quotaApplies: decision.body.quotaApplies
  });
  return res.status(200).json({ success: true, status: "success", ...decision.body, requestId });
}

async function quotaAdminLimitHandler(req, res) {
  const requestId = req.nodeSendRequestId || requestIdentity(req, res);
  const decision = await quotaAdminLimitDecision(req, req.body?.user_id, req.body);
  if (decision.status === 409) {
    safeEvent("quota_admin_limit_refused", {
      requestId, target: decision.body.userId, reason: decision.body.reason, aiSource: decision.body.aiSource
    });
    // The reason is a stable code, not prose: the admin UI explains WHY the limit was
    // not set, and an Own-AI account is told it is not governed by this quota.
    return res.status(409).json({
      success: false, status: "conflict", reason: decision.body.reason,
      aiSource: decision.body.aiSource, error: "This account is not using System AI, so its System AI limit does not apply.",
      requestId
    });
  }
  if (decision.status !== 200) {
    safeEvent("quota_admin_limit_failed", {
      requestId, status: decision.status, reason: String(decision.body?.reason ?? decision.body?.error ?? "failed")
    });
    return res.status(decision.status).json({
      success: false, status: decision.status === 400 ? "invalid_limit" : QUOTA_UNAVAILABLE,
      error: decision.body?.error || "Quota limit could not be saved",
      reason: decision.body?.reason ?? null, requestId
    });
  }
  safeEvent("quota_admin_limit_updated", {
    requestId, userId: req.bridgeUser?.id ?? null, target: decision.body.userId,
    overrideEnabled: decision.body.overrideEnabled, effectiveLimit: decision.body.effectiveLimit
  });
  return res.status(200).json({ success: true, status: "success", ...decision.body, requestId });
}

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
  quota: quotaLedgerState(),
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
  // Per-user quota is decided here, on NCB, with the caller's own session bearer. There is
  // no second quota service to report the state of, so this is the real configuration of
  // the authority — including whether the idempotency ledger is durable. `quotaConfigured`
  // above is the unrelated generic server-account /quota adapter.
  //
  // `replicas` is a deployment requirement, not a status: the reservation ledger has no
  // compare-and-swap, so counting is correct for one replica only. Running two of these
  // makes the count wrong — multi-replica quota counting is unsupported.
  ...quotaLedgerFields(),
  quota: quotaLedgerState(),
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

// AI endpoints authenticate the BridgeMind Bearer session and enforce per-user quota
// here, because a static frontend has no trusted server of its own and no secret to
// read quota with. NodeSend now MAKES that decision rather than asking for it: it owns
// the session check, the counting, the idempotency ledger and the admin gate, and the
// quota tables in NCB are the only storage. There is exactly one such authority — a
// second process counting the same tables would count wrong, see GET /health `quota`.
// /send, /rocketchat and the generic /quota adapter keep requireApiKey: they are
// server-to-server surfaces with no BridgeMind session behind them.
app.post("/ai/models", requireBridgeSession, (req, res) => relayAI(req, res, "models"));
app.post("/ai/test", requireBridgeSession, (req, res) => relayAI(req, res, "test"));
app.post("/ai/chat", requireBridgeSession, (req, res) => relayAI(req, res, "chat"));
app.get("/ai/quota", requireBridgeSession, async (req, res) => {
  const requestId = requestIdentity(req, res);
  try {
    const status = await getQuotaStatus(req, res);
    if (status?.error === "quota_service_unavailable" || status?.error === "auth_required") {
      // Fail closed on the read surface too: an unverifiable quota is reported
      // as unavailable rather than as a clean 0 / limit.
      safeEvent("quota_status_unavailable", { requestId, userId: req.bridgeUser?.id, reason: status.error });
      return res.status(status.error === "auth_required" ? 401 : 503).json({ ...status, requestId });
    }
    safeEvent("quota_status_served", { requestId, userId: req.bridgeUser?.id, period: status.period || null });
    return res.json({ ...status, requestId });
  } catch {
    // Logged defensively: a throw inside this catch block would become an unhandled
    // rejection and take the whole relay down, so nothing here assumes the session
    // middleware attached anything.
    safeEvent("quota_status_unavailable", { requestId, userId: req.bridgeUser?.id ?? null, reason: "exception" });
    return res.status(503).json({
      success: false, error: "quota_service_unavailable",
      enabled: true, unlimited: false, used: null, limit: null,
      remaining: null, percentage: null, requestId
    });
  }
});
// Admin quota configuration is a third surface: session-authenticated AND role-gated
// here, then applied straight to the configuration row. An ordinary user gets 403
// before any NCB call is made.
app.get("/ai/quota/config", requireBridgeSession, requireBridgeAdmin, readQuotaConfigHandler);
app.put("/ai/quota/config", requireBridgeSession, requireBridgeAdmin, writeQuotaConfigHandler);
// Per-account quota, administrator-only, and authoritative about the target's AI
// source. The routes sit beside the config pair because they share its guard: session
// first, role second, refusal before any storage call.
app.get("/ai/quota/status", requireBridgeSession, requireBridgeAdmin, quotaAdminStatusHandler);
app.put("/ai/quota/user", requireBridgeSession, requireBridgeAdmin, quotaAdminLimitHandler);
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
      ...quotaLedgerFields()
    });
  });
  // No quota probe at boot, deliberately. Every quota decision is made as the caller, with
  // the caller's own session bearer, so at startup there is no identity to ask with and a
  // probe would require exactly the service credential this architecture refuses to hold.
  // Nothing is reported as "degraded" either: with NCB_PROXY_BASE set the authority is
  // ready, and the first real request proves the storage reachable.
  //
  // What DOES deserve a warning is the ledger. Without AI_QUOTA_RESERVATION_TABLE an
  // idempotency key is remembered in this process only, so a restart inside a retry window
  // can charge one logical decision twice — the deployment asked for that trade-off, so it
  // is stated out loud rather than left as a config comment.
  if (!quotaLedgerDurable) {
    process.emitWarning(
      "NodeSend quota idempotency is process-only: AI_QUOTA_RESERVATION_TABLE is unset, so "
      + "a decision key is remembered in this process and a restart can charge the same "
      + "logical AI decision twice. Set AI_QUOTA_RESERVATION_TABLE to an NCB table with a "
      + "UNIQUE(user_id, period_key, decision_key) index for durable deduplication.",
      "NodeSendQuotaIdempotencyProcessOnly"
    );
  }
}

// Exported to permit local mock-provider/disconnect tests without binding a port.
// The quota authority's own parts are exported so a harness exercises the real storage
// calls, the real mutex, the real key rule and the real view clamps instead of copies —
// and because the ledger must be resettable between scenarios, which no HTTP route can do.
module.exports = {
  app, requestLifecycle, timeHeader, isAllowedAlibabaBaseUrl,
  buildProviderBody, NODESEND_VERSION,
  QUOTA_TABLES, QUOTA_IDEMPOTENCY_MODE, quotaLedgerDurable,
  QUOTA_SINGLE_REPLICA_INVARIANT, quotaLedgerState, quotaLedgerFields,
  DECISION_KEY_HEADER, DECISION_KEY_MAX_LENGTH, sanitizeDecisionKey, decisionKeyValue,
  resolveQuotaLimit, quotaBoundedView, quotaUnavailable,
  quotaStore, withUserLock, userLockCount, resetQuotaProcessLedger, quotaProcessLedgerSize,
  QUOTA_PROCESS_LEDGER_LIMIT, reserveQuotaDecision, getQuotaStatus, reserveAiCall,
  findReservation, claimReservation, releaseReservation,
  quotaConfigReadDecision, quotaConfigWriteDecision,
  // The AI-source authority, exported for the same reason the other predicates are:
  // the harness tests the real lookup, the real cache and the real admin decisions,
  // not a copy of them. `resetAiSourceCache` is the seam that makes cache expiry and
  // in-flight deduplication observable rather than inferred.
  resolveUserAiSource, resetAiSourceCache, aiSourceFromRows, quotaIsApplicableToUser,
  AI_SOURCE_SYSTEM, AI_SOURCE_OWN, AI_SOURCE_CACHE_TTL_MS, AI_SOURCE_FAILURE_CACHE_TTL_MS,
  USER_SETTINGS_TABLE, quotaAdminStatusDecision, quotaAdminLimitDecision,
  quotaNotApplicableView, requestBillingSource, BILLING_SOURCE_HEADER,
  // The Trickster gateway's own rules, exported so the harness can test the real
  // predicates instead of a copy of them. The routes themselves are exercised over
  // HTTP through `app`, which is what proves the session guard is attached.
  TRICKSTER_UPSTREAMS, TRICKSTER_RESPONSE_SHAPES, tricksterBaseUrl, tricksterTimeoutMs,
  tricksterUpstreamHeaders, tricksterSafeError, tricksterShapeOk, tricksterConfiguredState,
  isBridgeAdminRole
};
