/** ========================================================================
 * Cloudflare Worker (Modules) — JWT-only auth, CSRF allowlist via Origin/Referer
 * - POST /api/token  -> mints short-lived JWT (10 min)
 * - POST /api/chat   -> requires Bearer JWT + X-Session-Id
 * - CSRF: only allow requests from PAGES_ORIGIN (by Origin or Referer)
 * - Edge-cache safe GETs: /api/models, /api/config, /api/health
 * - In-memory sessions: per-session daily cap (10), reset at UTC midnight
 *
 * REQUIRED SECRETS:
 *   - GROQ_API_KEY
 *   - JWT_SECRET (32+ chars)
 *

 * ======================================================================
 * IMPORTANT!!! Update PAGES_ORIGIN with your own pages address (avoid using trailing slash)
 * ======================================================================
 */

const MODEL_ID = "llama-3.1-8b-instant";
const TEMPERATURE = 0.6;
const TOP_P = 0.95;
const MAX_COMPLETION_TOKENS = 4096;

/* ======================= CORS ORIGIN  =======================
  */
const PAGES_ORIGIN = "https://your-project-name.pages.dev"; //avoid using trailing slash in URL

/* ============================== CORS =============================== */
function corsPreflight() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": PAGES_ORIGIN, 
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Session-Id",
      "Access-Control-Max-Age": "86400",
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Expose-Headers": "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-Session-Id",
      "Vary": "Origin",
    },
  });
}
function withCorsHeaders(headers = {}) {
  return {
    ...headers,
    "Access-Control-Allow-Origin": PAGES_ORIGIN, // ← exact match
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Expose-Headers": "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-Session-Id",
    "Vary": "Origin",
  };
}

/* ===================== CSRF allowlist ======================
   Normalize Origin/Referer to compare without trailing slash.
*/
function _normalizeOrigin(u) {
  try {
    if (!u) return "";
    const url = new URL(u);
    return `${url.protocol}//${url.host}`; // no trailing slash, no path
  } catch {
    return "";
  }
}
/** Accept requests only if they come from your Pages app. */
function isFromPages(request) {
  const originHdr = request.headers.get("Origin") || "";
  const refererHdr = request.headers.get("Referer") || "";
  const reqOrigin = _normalizeOrigin(originHdr);
  const refOrigin = _normalizeOrigin(refererHdr);
  const allowed = _normalizeOrigin(PAGES_ORIGIN);
  if (reqOrigin && reqOrigin === allowed) return true;
  if (refOrigin && refOrigin === allowed) return true;
  return false;
}
function csrfGuard(request) {
  if (isFromPages(request)) return null;
  return new Response(JSON.stringify({ error: "csrf_invalid" }), {
    status: 403,
    headers: withCorsHeaders({ "Content-Type": "application/json; charset=utf-8" }),
  });
}

/* ======================= Cache API helpers ======================== */
async function cachedJSON(request, buildData, opts = {}) {
  const { sMaxAge = 300, maxAge = 60, etag, cacheTag } = opts;
  const cache = caches.default;

  let res = await cache.match(request);
  if (res) {
    const h = new Headers(res.headers);
    h.set("Access-Control-Allow-Origin", PAGES_ORIGIN);
    h.set("Access-Control-Allow-Credentials", "true");
    h.set("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-Session-Id");
    h.append("Vary", "Origin");
    return new Response(res.body, { status: res.status, headers: h });
  }

  const payload = await buildData();
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": `public, max-age=${maxAge}, s-maxage=${sMaxAge}`,
    "Access-Control-Allow-Origin": PAGES_ORIGIN,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Expose-Headers": "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, X-Session-Id",
    "Vary": "Origin",
  });
  if (etag) headers.set("ETag", etag);
  if (cacheTag) headers.set("Cache-Tag", cacheTag);

  res = new Response(JSON.stringify(payload), { status: 200, headers });
  await cache.put(request, res.clone());
  return res;
}

/* =================== Sessions & rate limiting ===================== */
const DAILY_LIMIT = 10; // per session per UTC day
const SESSIONS = new Map(); // Map<key, { count, day }>

function utcDateStr(d = new Date()) {
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}
function secondsUntilNextUtcMidnight() {
  const now = new Date();
  const next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 0, 0));
  return Math.max(0, Math.floor((next - now) / 1000));
}
function parseCookies(hdr) {
  const map = new Map();
  if (!hdr) return map;
  for (const part of hdr.split(/; */)) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    const k = decodeURIComponent(part.slice(0, i).trim());
    const v = decodeURIComponent(part.slice(i + 1).trim());
    map.set(k, v);
  }
  return map;
}
function cookieString(name, value, opts = {}) {
  const segs = [`${encodeURIComponent(name)}=${encodeURIComponent(value)}`];
  if (opts.maxAge) segs.push(`Max-Age=${opts.maxAge}`);
  if (opts.path) segs.push(`Path=${opts.path}`);
  if (opts.domain) segs.push(`Domain=${opts.domain}`);
  if (opts.sameSite) segs.push(`SameSite=${opts.sameSite}`);
  if (opts.secure) segs.push(`Secure`);
  if (opts.httpOnly) segs.push(`HttpOnly`);
  return segs.join("; ");
}
function identifySession(request) {
  const cookies = parseCookies(request.headers.get("Cookie"));
  const sidCookie = cookies.get("sid");
  const headerSid = request.headers.get("X-Session-Id");
  const ip = request.headers.get("CF-Connecting-IP") || "";
  const ua = request.headers.get("User-Agent") || "";

  if (sidCookie) return { key: `sid:${sidCookie}`, sid: sidCookie, setCookie: null };
  if (headerSid) return { key: `hdr:${headerSid}`, sid: headerSid, setCookie: null };

  const uuid = crypto.randomUUID();
  const setCookie = cookieString("sid", uuid, {
    path: "/",
    maxAge: 60 * 60 * 24 * 30,
    sameSite: "None",
    secure: true,
    httpOnly: false,
  });
  const fallbackKey = `ipua:${ip}|${ua}`;
  return { key: fallbackKey, sid: uuid, setCookie };
}
function getBucket(sessionKey) {
  const today = utcDateStr();
  let b = SESSIONS.get(sessionKey);
  if (!b || b.day !== today) {
    b = { count: 0, day: today };
    SESSIONS.set(sessionKey, b);
  }
  return b;
}

/* ===================== JWT (HS256) utilities ===================== */
async function sha256Hex(str) {
  const data = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}
function b64urlFromBytes(bytes) {
  let binary = ""; for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  const b64 = btoa(binary); return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlFromString(str) { return b64urlFromBytes(new TextEncoder().encode(str)); }
function bytesFromB64url(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  const bin = atob(b64); const len = bin.length; const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return new Uint8Array(sig);
}
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false; let res = 0;
  for (let i = 0; i < a.length; i++) res |= a[i] ^ b[i]; return res === 0;
}
async function signJWT(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const encHeader = b64urlFromString(JSON.stringify(header));
  const encPayload = b64urlFromString(JSON.stringify(payload));
  const unsigned = `${encHeader}.${encPayload}`;
  const sig = await hmacSign(secret, unsigned);
  return `${unsigned}.${b64urlFromBytes(sig)}`;
}
async function verifyJWT(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, err: "format" };
  const [encHeader, encPayload, encSig] = parts;
  let header, payload;
  try {
    header = JSON.parse(new TextDecoder().decode(bytesFromB64url(encHeader)));
    payload = JSON.parse(new TextDecoder().decode(bytesFromB64url(encPayload)));
  } catch { return { ok: false, err: "decode" }; }
  if (!header || header.alg !== "HS256") return { ok: false, err: "alg" };
  const unsigned = `${encHeader}.${encPayload}`;
  const sigExpected = await hmacSign(secret, unsigned);
  const sigGiven = bytesFromB64url(encSig);
  if (!constantTimeEqual(sigExpected, sigGiven)) return { ok: false, err: "sig" };
  if (typeof payload.exp === "number" && Date.now() / 1000 > payload.exp) return { ok: false, err: "exp" };
  return { ok: true, payload };
}

/* ================================ Worker =============================== */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method === "OPTIONS") return corsPreflight();

    // ---------- Cacheable GETs ----------
    if (request.method === "GET") {
      if (pathname === "/api/models") {
        const csrf = csrfGuard(request); if (csrf) return csrf;
        return cachedJSON(
          request,
          async () => ({
            models: [
              { id: "llama-3.1-8b-instant", label: "Llama 3.1 8B Instant", provider: "Groq" },
              { id: "llama-3.3-70b-versatile", label: "Llama 3.3 70B Versatile", provider: "Groq", available: false },
              { id: "gemma2-9b-it", label: "Gemma 2 9B Instruct", provider: "Groq", available: false },
            ],
            default: MODEL_ID,
            updated_at: "static",
          }),
          { sMaxAge: 600, maxAge: 60, etag: 'W/"models-v1"', cacheTag: "models" }
        );
      }
      if (pathname === "/api/config") {
        const csrf = csrfGuard(request); if (csrf) return csrf;
        return cachedJSON(
          request,
          async () => ({
            model: MODEL_ID,
            temperature: TEMPERATURE,
            top_p: TOP_P,
            max_completion_tokens: MAX_COMPLETION_TOKENS,
          }),
          { sMaxAge: 600, maxAge: 120, etag: 'W/"config-v1"', cacheTag: "config" }
        );
      }
      if (pathname === "/api/health") {
        return cachedJSON(
          request,
          async () => ({ status: "ok", cached_at_utc: new Date().toISOString() }),
          { sMaxAge: 30, maxAge: 0, cacheTag: "health" }
        );
      }
    }

    // ---------- JWT mint ----------
    if (pathname === "/api/token" && request.method === "POST") {
      const csrf = csrfGuard(request); if (csrf) return csrf;

      if (!env.JWT_SECRET) {
        return new Response("Missing JWT_SECRET", {
          status: 500,
          headers: withCorsHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
        });
      }

      const ident = identifySession(request); // may set cookie
      const ua = request.headers.get("User-Agent") || "";
      const uaHash = b64urlFromBytes(new TextEncoder().encode(await sha256Hex(ua)));

      const now = Math.floor(Date.now() / 1000);
      const exp = now + 10 * 60; // 10 minutes
      const payload = { sid: ident.sid, ori: PAGES_ORIGIN, ua: uaHash, iat: now, exp };
      const token = await signJWT(payload, env.JWT_SECRET);

      const headers = new Headers(withCorsHeaders({ "Content-Type": "application/json; charset=utf-8" }));
      headers.set("X-Session-Id", ident.sid);
      if (ident.setCookie) headers.append("Set-Cookie", ident.setCookie);

      return new Response(JSON.stringify({ token, sid: ident.sid, exp }), { status: 200, headers });
    }

    // ---------- Protected chat ----------
    if (pathname === "/api/chat" && request.method === "POST") {
      const csrf = csrfGuard(request); if (csrf) return csrf;

      if (!env.GROQ_API_KEY) {
        return new Response("Missing GROQ_API_KEY", {
          status: 500,
          headers: withCorsHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
        });
      }
      if (!env.JWT_SECRET) {
        return new Response("Missing JWT_SECRET", {
          status: 500,
          headers: withCorsHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
        });
      }

      const auth = request.headers.get("Authorization") || "";
      const m = auth.match(/^Bearer\s+(.+)$/i);
      if (!m) {
        return new Response("Unauthorized (missing bearer token)", {
          status: 401,
          headers: withCorsHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
        });
      }
      const ver = await verifyJWT(m[1], env.JWT_SECRET);
      if (!ver.ok) {
        return new Response(`Unauthorized (invalid token: ${ver.err})`, {
          status: 401,
          headers: withCorsHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
        });
      }
      const payload = ver.payload;
      const ua = request.headers.get("User-Agent") || "";
      const uaHash = b64urlFromBytes(new TextEncoder().encode(await sha256Hex(ua)));
      if (payload.ori !== PAGES_ORIGIN || payload.ua !== uaHash) {
        return new Response("Unauthorized (context mismatch)", {
          status: 401,
          headers: withCorsHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
        });
      }
      const clientSid = request.headers.get("X-Session-Id") || "";
      if (!clientSid || clientSid !== payload.sid) {
        return new Response("Unauthorized (session mismatch)", {
          status: 401,
          headers: withCorsHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
        });
      }

      // RL bucket
      const ident = identifySession(request);
      const bucket = getBucket(ident.key);
      const limit = DAILY_LIMIT;
      const remainingBefore = Math.max(0, limit - bucket.count);
      const resetSec = secondsUntilNextUtcMidnight();
      if (bucket.count >= limit) {
        const headers = new Headers(withCorsHeaders({
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store",
          "X-RateLimit-Limit": String(limit),
          "X-RateLimit-Remaining": "0",
          "X-RateLimit-Reset": String(resetSec),
          "X-Session-Id": payload.sid,
        }));
        if (ident.setCookie) headers.append("Set-Cookie", ident.setCookie);
        return new Response("Daily limit reached. Please try again after UTC midnight.", { status: 429, headers });
      }

      // Parse body
      let body;
      try { body = await request.json(); } catch { body = {}; }
      const userText = (body?.message ?? "").toString().trim();
      if (!userText) {
        const headers = new Headers(withCorsHeaders({
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store",
          "X-RateLimit-Limit": String(limit),
          "X-RateLimit-Remaining": String(remainingBefore),
          "X-RateLimit-Reset": String(resetSec),
          "X-Session-Id": payload.sid,
        }));
        if (ident.setCookie) headers.append("Set-Cookie", ident.setCookie);
        return new Response("Missing 'message'", { status: 400, headers });
      }

      // Upstream Groq call (streaming)
      const messages = [
        { role: "system", content: "You are a concise, helpful coding assistant. Prefer runnable examples and clear answers." },
        { role: "user", content: userText },
      ];

      let upstream;
      try {
        upstream = await fetch("https://api.groq.com/openai/v1/chat/completions", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${env.GROQ_API_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: MODEL_ID,
            messages,
            temperature: TEMPERATURE,
            max_completion_tokens: MAX_COMPLETION_TOKENS,
            top_p: TOP_P,
            stream: true,
          }),
        });
      } catch (e) {
        const headers = new Headers(withCorsHeaders({
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store",
          "X-RateLimit-Limit": String(limit),
          "X-RateLimit-Remaining": String(remainingBefore),
          "X-RateLimit-Reset": String(resetSec),
          "X-Session-Id": payload.sid,
        }));
        if (ident.setCookie) headers.append("Set-Cookie", ident.setCookie);
        return new Response(`Upstream network error: ${String(e)}`, { status: 502, headers });
      }

      if (!upstream.ok || !upstream.body) {
        const text = await upstream.text().catch(() => "");
        const headers = new Headers(withCorsHeaders({
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store",
          "X-RateLimit-Limit": String(limit),
          "X-RateLimit-Remaining": String(remainingBefore),
          "X-RateLimit-Reset": String(resetSec),
          "X-Session-Id": payload.sid,
        }));
        if (ident.setCookie) headers.append("Set-Cookie", ident.setCookie);
        return new Response(`Upstream error (${upstream.status} ${upstream.statusText}): ${text || "no body"}`, { status: 502, headers });
      }

      let gotTokens = false;
      const enc = new TextEncoder();
      const dec = new TextDecoder();
      const stream = new ReadableStream({
        async start(controller) {
          const reader = upstream.body.getReader();
          let buf = "";
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              buf += dec.decode(value, { stream: true });
              let idx;
              while ((idx = buf.indexOf("\n\n")) !== -1) {
                const event = buf.slice(0, idx).trim();
                buf = buf.slice(idx + 2);
                if (!event) continue;
                for (const line of event.split("\n")) {
                  if (!line.startsWith("data:")) continue;
                  const data = line.slice(5).trim();
                  if (data === "[DONE]") break;
                  try {
                    const json = JSON.parse(data);
                    const token = json?.choices?.[0]?.delta?.content || "";
                    if (token) { gotTokens = true; controller.enqueue(enc.encode(token)); }
                  } catch {}
                }
              }
            }
          } finally { controller.close(); }
        }
      });

      const headers = new Headers(withCorsHeaders({
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-store",
        "X-RateLimit-Limit": String(limit),
        "X-RateLimit-Remaining": String(remainingBefore),
        "X-RateLimit-Reset": String(resetSec),
        "X-Session-Id": payload.sid,
      }));
      if (ident.setCookie) headers.append("Set-Cookie", ident.setCookie);

      // Increment AFTER a successful stream
      Promise.resolve().then(() => {
        if (gotTokens) {
          const b = getBucket(ident.key);
          b.count = Math.min(limit, b.count + 1);
          SESSIONS.set(ident.key, b);
        }
      });

      return new Response(stream, { headers });
    }

    // Fallback
    return new Response("Not Found", {
      status: 404,
      headers: withCorsHeaders({ "Content-Type": "text/plain; charset=utf-8" }),
    });
  },
};
