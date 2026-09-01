
/*
 * Authentication Core for Cloudflare Workers + D1
 *
 * No secrets are embedded in this file.
 * External integrations are adapter based and fail closed when disabled/missing.
 */

const CONFIG = {
  DB_BINDING: "DB",
  COOKIE_NAME: "__Host-auth_session",
  CSRF_COOKIE: "__Host-auth_csrf",
  SESSION_TTL_SECONDS: 604800,
  OTP_TTL_SECONDS: 180,
  OTP_MAX_ATTEMPTS: 5,
  PBKDF2_ITERATIONS: 310000,
  PASSWORD_MIN_LENGTH: 10,
  PASSWORD_MAX_LENGTH: 256,
  USERNAME_MAX_LENGTH: 64,
  EMAIL_MAX_LENGTH: 254,
  MOBILE_MAX_LENGTH: 32,
  VERIFICATION_TTL_SECONDS: 900,
  PASSWORD_RESET_TTL_SECONDS: 900,
  OIDC_TRANSACTION_TTL_SECONDS: 300,
  CSRF_TTL_SECONDS: 3600,
  LOGIN_MAX_FAILURES: 8,
  LOGIN_LOCK_SECONDS: 300,
  RATE_WINDOW_SECONDS: 60,
  RATE_MAX_PER_IP: 30,
  RATE_MAX_LOGIN_PER_IP: 10,
  RATE_MAX_REGISTER_PER_IP: 5,
  RATE_MAX_OTP_REQUEST_PER_IP: 5,
  RATE_MAX_OTP_VERIFY_PER_IP: 15,
  RATE_MAX_PASSWORD_RESET_PER_IP: 5,
  APP_NAME: "Authentication Core",
  LOGIN_SUCCESS_REDIRECT: "/dashboard.html",
  ALLOWED_ORIGINS: [],
  COOKIE_SAMESITE: "Lax"
};

const enc = new TextEncoder();
const dec = new TextDecoder();

function now() { return new Date().toISOString(); }
function future(seconds) { return new Date(Date.now() + Number(seconds) * 1000).toISOString(); }
function uuid() { return crypto.randomUUID(); }
function bytes(n) { const a = new Uint8Array(n); crypto.getRandomValues(a); return a; }
function b64u(input) {
  const a = input instanceof Uint8Array ? input : new Uint8Array(input);
  let s = "";
  for (const b of a) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromB64u(value) {
  let s = String(value).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
function randomToken(size = 32) { return b64u(bytes(size)); }
async function sha256(value) {
  const data = typeof value === "string" ? enc.encode(value) : value;
  return b64u(await crypto.subtle.digest("SHA-256", data));
}
async function hmac(secret, value) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", key, enc.encode(value)));
}
function safeEqual(a, b) {
  const x = typeof a === "string" ? enc.encode(a) : a;
  const y = typeof b === "string" ? enc.encode(b) : b;
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
function parseCookies(request) {
  const out = {};
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i < 1) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    try { out[k] = decodeURIComponent(v); } catch { out[k] = v; }
  }
  return out;
}
function getOrigin(request) { return request.headers.get("Origin") || ""; }
function getIP(request) { return request.headers.get("CF-Connecting-IP") || "0.0.0.0"; }
function getUA(request) { return request.headers.get("User-Agent") || ""; }
function bool(v, fallback = false) {
  if (v === undefined || v === null || v === "") return fallback;
  return v === true || String(v).toLowerCase() === "true" || v === 1 || String(v) === "1";
}
function num(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}
function list(v) { return String(v || "").split(",").map(x => x.trim()).filter(Boolean); }
function config(env) {
  return {
    appName: env.APP_NAME || CONFIG.APP_NAME,
    successRedirect: env.LOGIN_SUCCESS_REDIRECT || CONFIG.LOGIN_SUCCESS_REDIRECT,
    cookieName: env.COOKIE_NAME || CONFIG.COOKIE_NAME,
    sessionTtl: num(env.SESSION_TTL_SECONDS, CONFIG.SESSION_TTL_SECONDS),
    otpTtl: num(env.OTP_TTL_SECONDS, CONFIG.OTP_TTL_SECONDS),
    otpMaxAttempts: num(env.OTP_MAX_ATTEMPTS, CONFIG.OTP_MAX_ATTEMPTS),
    pbkdf2Iterations: num(env.PBKDF2_ITERATIONS, CONFIG.PBKDF2_ITERATIONS),
    passwordMin: num(env.PASSWORD_MIN_LENGTH, CONFIG.PASSWORD_MIN_LENGTH),
    passwordMax: num(env.PASSWORD_MAX_LENGTH, CONFIG.PASSWORD_MAX_LENGTH),
    registrationEnabled: bool(env.REGISTRATION_ENABLED, true),
    requireEmail: bool(env.REQUIRE_EMAIL, true),
    requireUsername: bool(env.REQUIRE_USERNAME, false),
    requireMobile: bool(env.REQUIRE_MOBILE, false),
    requireEmailVerification: bool(env.REQUIRE_EMAIL_VERIFICATION, false),
    requireMobileVerification: bool(env.REQUIRE_MOBILE_VERIFICATION, false),
    autoLogin: bool(env.AUTO_LOGIN_AFTER_REGISTRATION, false),
    loginPage: env.LOGIN_PAGE || "/login.html",
    verificationTtl: num(env.VERIFICATION_TTL_SECONDS, CONFIG.VERIFICATION_TTL_SECONDS),
    passwordResetTtl: num(env.PASSWORD_RESET_TTL_SECONDS, CONFIG.PASSWORD_RESET_TTL_SECONDS),
    smsEnabled: bool(env.SMS_ENABLED, false),
    smsProvider: env.SMS_PROVIDER || "REPLACE_ME",
    oidcEnabled: bool(env.OIDC_ENABLED, false),
    oidcIssuer: env.OIDC_ISSUER || "",
    oidcClientId: env.OIDC_CLIENT_ID || "",
    oidcRedirectUri: env.OIDC_REDIRECT_URI || "",
    oidcTokenAuthMethod: env.OIDC_TOKEN_AUTH_METHOD || "client_secret_post",
    allowedOrigins: list(env.ALLOWED_ORIGINS),
    sameSite: String(env.COOKIE_SAMESITE || CONFIG.COOKIE_SAMESITE),
    debug: bool(env.AUTH_DEBUG, false)
  };
}
function publicConfig(env) {
  const c = config(env);
  return {
    appName: c.appName,
    successRedirect: c.successRedirect,
    registrationEnabled: c.registrationEnabled,
    requireEmail: c.requireEmail,
    requireUsername: c.requireUsername,
    requireMobile: c.requireMobile,
    smsEnabled: c.smsEnabled,
    oidcEnabled: c.oidcEnabled,
    oidcProviderConfigured: c.oidcEnabled && !!c.oidcIssuer && !!c.oidcClientId && !!c.oidcRedirectUri
  };
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers }
  });
}
function success(data, requestId, status = 200) {
  return json({ success: true, data, error: null, requestId }, status);
}
function failure(code, message, requestId, status = 400, details = undefined) {
  return json({
    success: false,
    data: null,
    error: { code, message, ...(details ? { details } : {}) },
    requestId
  }, status);
}
function securityHeaders() {
  return {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-site",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
  };
}
function withHeaders(response, extra = {}) {
  const h = new Headers(response.headers);
  for (const [k, v] of Object.entries(securityHeaders())) h.set(k, v);
  for (const [k, v] of Object.entries(extra)) h.set(k, v);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: h });
}
function cookie(name, value, maxAge, { httpOnly = true, sameSite = "Lax", secure = true } = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Max-Age=${Math.max(0, Math.floor(maxAge))}`, "Path=/"];
  if (secure) parts.push("Secure");
  if (httpOnly) parts.push("HttpOnly");
  parts.push(`SameSite=${sameSite}`);
  return parts.join("; ");
}
function corsHeaders(request, env) {
  const origin = getOrigin(request);
  if (!origin) return {};
  if (!config(env).allowedOrigins.includes(origin)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Vary": "Origin"
  };
}
function originAllowed(request, env) {
  const origin = getOrigin(request);
  if (!origin) return true;
  return config(env).allowedOrigins.includes(origin);
}

async function audit(env, request, requestId, eventType, successFlag, userId = null, metadata = {}) {
  try {
    const secret = env.AUDIT_HASH_SECRET || env.SESSION_AUDIT_SECRET;
    const ipHash = secret ? await hmac(secret, getIP(request)) : null;
    const uaHash = secret ? await hmac(secret, getUA(request)) : null;
    await env.DB.prepare(`
      INSERT INTO audit_logs(id,user_id,event_type,success,request_id,ip_hash,user_agent_hash,metadata_json,created_at)
      VALUES(?,?,?,?,?,?,?,?,?)
    `).bind(uuid(), userId, eventType, successFlag ? 1 : 0, requestId, ipHash, uaHash, JSON.stringify(metadata), now()).run();
  } catch (e) {
    console.error("audit_write_failed", requestId, e?.message || e);
  }
}
async function securityHash(env, value) {
  const secret = env.AUDIT_HASH_SECRET || env.SESSION_AUDIT_SECRET;
  return secret ? hmac(secret, value) : sha256(value);
}

async function rateLimit(env, request, bucket, max, windowSeconds = CONFIG.RATE_WINDOW_SECONDS) {
  // Preferred: Cloudflare Rate Limiting binding. Configure AUTH_RATE_LIMIT in Wrangler.
  if (env.AUTH_RATE_LIMIT && typeof env.AUTH_RATE_LIMIT.limit === "function") {
    try {
      const result = await env.AUTH_RATE_LIMIT.limit({ key: bucket });
      return !!result.success;
    } catch (e) {
      console.error("cloudflare_rate_limit_failed", e?.message || e);
      // Fail closed for authentication/registration abuse controls.
      return false;
    }
  }

  // D1 fallback. Suitable for low/medium traffic; not a replacement for the
  // distributed Cloudflare Rate Limiting API at high scale.
  const current = Math.floor(Date.now() / 1000);
  const windowStart = current - (current % windowSeconds);
  const updated = now();
  try {
    await env.DB.prepare(`
      INSERT INTO rate_limits(bucket_key,window_start,count,updated_at)
      VALUES(?,?,1,?)
      ON CONFLICT(bucket_key) DO UPDATE SET
        count = CASE WHEN rate_limits.window_start = excluded.window_start
          THEN rate_limits.count + 1 ELSE 1 END,
        window_start = excluded.window_start,
        updated_at = excluded.updated_at
    `).bind(bucket, windowStart, updated).run();
    const row = await env.DB.prepare(`SELECT count FROM rate_limits WHERE bucket_key=? LIMIT 1`).bind(bucket).first();
    return Number(row?.count || 0) <= max;
  } catch (e) {
    console.error("d1_rate_limit_failed", e?.message || e);
    return false;
  }
}

function normalizeEmail(value) { return String(value || "").trim().toLowerCase(); }
function normalizeUsername(value) { return String(value || "").trim().toLowerCase(); }
function normalizeMobile(value) {
  let s = String(value || "").trim().replace(/[\s().-]/g, "");
  if (s.startsWith("00")) s = "+" + s.slice(2);
  if (!s.startsWith("+")) s = "+" + s.replace(/^0+/, "");
  return s;
}
function validEmail(v) { return typeof v === "string" && v.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function validUsername(v) { return typeof v === "string" && v.length >= 3 && v.length <= 64 && /^[a-z0-9_]+$/.test(v); }
function validMobile(v) { return typeof v === "string" && /^\+[1-9][0-9]{7,14}$/.test(v); }
function validPassword(v, c) {
  return typeof v === "string" && v.length >= c.passwordMin && v.length <= c.passwordMax;
}
function passwordPolicy(v) {
  if (/^\s+$/.test(v)) return false;
  if (v.includes("\u0000")) return false;
  return true;
}
function safeJson(request) { return request.json().catch(() => null); }

async function passwordHash(password, saltB64, iterations) {
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: fromB64u(saltB64),
    iterations,
    hash: "SHA-256"
  }, baseKey, 256);
  return b64u(bits);
}
async function createPasswordRecord(password, iterations) {
  const salt = b64u(bytes(16));
  return {
    salt,
    hash: await passwordHash(password, salt, iterations),
    iterations
  };
}

async function getUserByIdentifier(db, identifier) {
  const email = normalizeEmail(identifier);
  const username = normalizeUsername(identifier);
  return db.prepare(`
    SELECT u.* FROM users u
    JOIN user_identifiers i ON i.user_id=u.id
    WHERE i.type IN ('EMAIL','USERNAME') AND i.normalized_value IN (?,?)
    LIMIT 1
  `).bind(email, username).first();
}
async function getUserByMobile(db, mobile) {
  return db.prepare(`
    SELECT u.* FROM users u
    JOIN user_identifiers i ON i.user_id=u.id
    WHERE i.type='MOBILE' AND i.normalized_value=? LIMIT 1
  `).bind(normalizeMobile(mobile)).first();
}
async function getCredential(db, userId) {
  return db.prepare(`SELECT * FROM user_credentials WHERE user_id=? AND type='PASSWORD' LIMIT 1`).bind(userId).first();
}
async function createSession(env, request, userId) {
  const c = config(env);
  const rawToken = randomToken(32);
  const hash = await sha256(rawToken);
  const created = now();
  const expires = future(c.sessionTtl);
  await env.DB.prepare(`
    INSERT INTO sessions(id,user_id,token_hash,created_at,expires_at,last_seen_at,ip_hash,user_agent_hash)
    VALUES(?,?,?,?,?,?,?,?)
  `).bind(
    uuid(), userId, hash, created, expires, created,
    await securityHash(env, getIP(request)),
    await securityHash(env, getUA(request))
  ).run();
  return { token: rawToken, expiresAt: expires };
}
async function currentSession(env, request) {
  const c = config(env);
  const token = parseCookies(request)[c.cookieName];
  if (!token) return null;
  const hash = await sha256(token);
  const session = await env.DB.prepare(`
    SELECT s.*,u.status FROM sessions s
    JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.status='ACTIVE'
    LIMIT 1
  `).bind(hash, now()).first();
  if (!session) return null;
  await env.DB.prepare(`UPDATE sessions SET last_seen_at=? WHERE id=?`).bind(now(), session.id).run();
  return session;
}
async function revokeAllSessions(env, userId) {
  await env.DB.prepare(`UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`).bind(now(), userId).run();
}

async function issueCsrf(env, request, requestId) {
  const token = randomToken(32);
  const c = config(env);
  await audit(env, request, requestId, "CSRF_ISSUED", true, null, {});
  return withHeaders(success({ csrfToken: token, config: publicConfig(env) }, requestId), {
    "Set-Cookie": cookie(CONFIG.CSRF_COOKIE, token, CONFIG.CSRF_TTL_SECONDS, { httpOnly: false, sameSite: c.sameSite }),
    ...corsHeaders(request, env)
  });
}
function csrfValid(request, env) {
  if (["GET", "HEAD", "OPTIONS"].includes(request.method)) return true;
  if (!originAllowed(request, env)) return false;
  const cookies = parseCookies(request);
  const cookieToken = cookies[CONFIG.CSRF_COOKIE];
  const headerToken = request.headers.get("X-CSRF-Token");
  return !!cookieToken && !!headerToken && safeEqual(cookieToken, headerToken);
}

async function loginPassword(request, env, requestId) {
  if (!csrfValid(request, env)) {
    await audit(env, request, requestId, "LOGIN_CSRF_FAILED", false);
    return withHeaders(failure("CSRF_FAILED", "درخواست نامعتبر است.", requestId, 403), corsHeaders(request, env));
  }
  const ipKey = `password-login:ip:${await securityHash(env, getIP(request))}`;
  if (!(await rateLimit(env, request, ipKey, CONFIG.RATE_MAX_LOGIN_PER_IP))) {
    await audit(env, request, requestId, "LOGIN_RATE_LIMITED", false);
    return withHeaders(failure("RATE_LIMITED", "تعداد درخواست‌ها بیش از حد مجاز است.", requestId, 429), corsHeaders(request, env));
  }

  const body = await safeJson(request);
  const identifier = String(body?.identifier || "").trim();
  const password = body?.password;
  const genericError = failure("AUTHENTICATION_FAILED", "نام کاربری یا رمز عبور صحیح نیست.", requestId, 401);
  const user = await getUserByIdentifier(env.DB, identifier);
  if (!user || !validPassword(password, config(env))) {
    await audit(env, request, requestId, "LOGIN_FAILED", false, user?.id || null, { reason: "generic" });
    return withHeaders(genericError, corsHeaders(request, env));
  }

  const locked = user.locked_until && user.locked_until > now();
  const credential = await getCredential(env.DB, user.id);
  let valid = false;
  if (!locked && credential) {
    const derived = await passwordHash(password, credential.password_salt, Number(credential.hash_iterations));
    valid = safeEqual(derived, credential.password_hash);
  }

  await env.DB.prepare(`
    INSERT INTO login_attempts(id,user_id,identifier_hash,method,success,ip_hash,created_at)
    VALUES(?,?,?,?,?,?,?)
  `).bind(
    uuid(), user.id, await securityHash(env, normalizeEmail(identifier)), "PASSWORD", valid ? 1 : 0,
    await securityHash(env, getIP(request)), now()
  ).run();

  if (!valid) {
    const failures = Number(user.failed_login_count || 0) + 1;
    const lockUntil = failures >= CONFIG.LOGIN_MAX_FAILURES ? future(CONFIG.LOGIN_LOCK_SECONDS) : null;
    await env.DB.prepare(`UPDATE users SET failed_login_count=?,locked_until=?,updated_at=? WHERE id=?`)
      .bind(failures, lockUntil, now(), user.id).run();
    await audit(env, request, requestId, "LOGIN_FAILED", false, user.id, { reason: "generic" });
    return withHeaders(genericError, corsHeaders(request, env));
  }

  if (user.status !== "ACTIVE") {
    await audit(env, request, requestId, "LOGIN_BLOCKED_ACCOUNT_STATE", false, user.id, { status: user.status });
    return withHeaders(failure("ACCOUNT_UNAVAILABLE", "حساب کاربری در حال حاضر قابل استفاده نیست.", requestId, 403), corsHeaders(request, env));
  }

  await env.DB.prepare(`UPDATE users SET failed_login_count=0,locked_until=NULL,last_login_at=?,updated_at=? WHERE id=?`)
    .bind(now(), now(), user.id).run();
  const session = await createSession(env, request, user.id);
  await audit(env, request, requestId, "LOGIN_SUCCESS", true, user.id, {});
  const c = config(env);
  return withHeaders(success({ redirect: c.successRedirect, expiresAt: session.expiresAt }, requestId), {
    "Set-Cookie": cookie(c.cookieName, session.token, c.sessionTtl, { httpOnly: true, sameSite: c.sameSite }),
    ...corsHeaders(request, env)
  });
}

function otpCode() {
  const n = new DataView(bytes(4).buffer).getUint32(0) % 1000000;
  return String(n).padStart(6, "0");
}
async function sendSmsOTP(env, mobile, code) {
  // REQUIRED EXTERNAL ADAPTER. No fake provider is used.
  if (!config(env).smsEnabled) throw new Error("SMS_DISABLED");
  if (!env.SMS_API_KEY) throw new Error("SMS_API_KEY_MISSING");
  throw new Error("SMS_PROVIDER_ADAPTER_NOT_IMPLEMENTED");
}
async function requestOtp(request, env, requestId, purpose = "LOGIN") {
  if (!csrfValid(request, env)) return withHeaders(failure("CSRF_FAILED", "درخواست نامعتبر است.", requestId, 403), corsHeaders(request, env));
  const c = config(env);
  if (!c.smsEnabled) return withHeaders(failure("FEATURE_DISABLED", "ورود پیامکی فعال نیست.", requestId, 503), corsHeaders(request, env));
  const ipKey = `otp-request:ip:${await securityHash(env, getIP(request))}`;
  if (!(await rateLimit(env, request, ipKey, CONFIG.RATE_MAX_OTP_REQUEST_PER_IP))) {
    await audit(env, request, requestId, "OTP_REQUEST_RATE_LIMITED", false);
    return withHeaders(failure("RATE_LIMITED", "تعداد درخواست‌ها بیش از حد مجاز است.", requestId, 429), corsHeaders(request, env));
  }
  const body = await safeJson(request);
  const mobile = normalizeMobile(body?.mobile);
  if (!validMobile(mobile)) return withHeaders(failure("INVALID_INPUT", "شماره موبایل معتبر نیست.", requestId, 400), corsHeaders(request, env));

  const mobileHash = await securityHash(env, mobile);
  const recent = await env.DB.prepare(`
    SELECT id FROM otp_challenges
    WHERE mobile_hash=? AND purpose=? AND created_at>? AND consumed_at IS NULL
    LIMIT 1
  `).bind(mobileHash, purpose, new Date(Date.now() - 60000).toISOString()).first();
  if (recent) return withHeaders(success({ accepted: true }, requestId), corsHeaders(request, env));

  const user = await getUserByMobile(env.DB, mobile);
  const code = otpCode();
  const otpHash = await sha256(code);
  const id = uuid();
  await env.DB.prepare(`
    INSERT INTO otp_challenges(id,purpose,user_id,mobile_hash,otp_hash,created_at,expires_at,attempts,max_attempts,ip_hash)
    VALUES(?,?,?,?,?,?,?,?,?,?)
  `).bind(
    id, purpose, user?.id || null, mobileHash, otpHash, now(), future(c.otpTtl), 0,
    c.otpMaxAttempts, await securityHash(env, getIP(request))
  ).run();

  try {
    await sendSmsOTP(env, mobile, code);
  } catch (e) {
    await env.DB.prepare(`DELETE FROM otp_challenges WHERE id=?`).bind(id).run();
    await audit(env, request, requestId, "OTP_PROVIDER_FAILURE", false, user?.id || null, { provider: c.smsProvider });
    return withHeaders(failure("PROVIDER_UNAVAILABLE", "سرویس پیامک در دسترس نیست.", requestId, 503), corsHeaders(request, env));
  }

  await audit(env, request, requestId, "OTP_REQUESTED", true, user?.id || null, { purpose });
  // Never return the OTP or whether the mobile exists.
  return withHeaders(success({ accepted: true, expiresIn: c.otpTtl }, requestId), corsHeaders(request, env));
}
async function verifyOtp(request, env, requestId, purpose = "LOGIN") {
  if (!csrfValid(request, env)) return withHeaders(failure("CSRF_FAILED", "درخواست نامعتبر است.", requestId, 403), corsHeaders(request, env));
  const ipKey = `otp-verify:ip:${await securityHash(env, getIP(request))}`;
  if (!(await rateLimit(env, request, ipKey, CONFIG.RATE_MAX_OTP_VERIFY_PER_IP))) {
    return withHeaders(failure("RATE_LIMITED", "تعداد درخواست‌ها بیش از حد مجاز است.", requestId, 429), corsHeaders(request, env));
  }
  const body = await safeJson(request);
  const mobile = normalizeMobile(body?.mobile);
  const otp = String(body?.otp || "").trim();
  if (!validMobile(mobile) || !/^\d{6}$/.test(otp)) return withHeaders(failure("INVALID_INPUT", "اطلاعات واردشده معتبر نیست.", requestId, 400), corsHeaders(request, env));
  const mobileHash = await securityHash(env, mobile);
  const challenge = await env.DB.prepare(`
    SELECT * FROM otp_challenges
    WHERE mobile_hash=? AND purpose=? AND consumed_at IS NULL AND expires_at>?
    ORDER BY created_at DESC LIMIT 1
  `).bind(mobileHash, purpose, now()).first();
  if (!challenge || Number(challenge.attempts) >= Number(challenge.max_attempts)) {
    await audit(env, request, requestId, "OTP_FAILED", false, challenge?.user_id || null, { reason: "generic" });
    return withHeaders(failure("OTP_INVALID", "کد واردشده معتبر نیست.", requestId, 401), corsHeaders(request, env));
  }
  await env.DB.prepare(`UPDATE otp_challenges SET attempts=attempts+1 WHERE id=?`).bind(challenge.id).run();
  const valid = safeEqual(await sha256(otp), challenge.otp_hash);
  if (!valid) {
    await audit(env, request, requestId, "OTP_FAILED", false, challenge.user_id || null, { reason: "generic" });
    return withHeaders(failure("OTP_INVALID", "کد واردشده معتبر نیست.", requestId, 401), corsHeaders(request, env));
  }
  await env.DB.prepare(`UPDATE otp_challenges SET consumed_at=? WHERE id=? AND consumed_at IS NULL`).bind(now(), challenge.id).run();
  const user = await getUserByMobile(env.DB, mobile);
  if (!user || user.status !== "ACTIVE") {
    await audit(env, request, requestId, "OTP_VERIFIED_NO_ACTIVE_USER", true, user?.id || null, {});
    return withHeaders(failure("AUTHENTICATION_FAILED", "ورود امکان‌پذیر نیست.", requestId, 401), corsHeaders(request, env));
  }
  const session = await createSession(env, request, user.id);
  await audit(env, request, requestId, "OTP_VERIFIED", true, user.id, { purpose });
  const c = config(env);
  return withHeaders(success({ redirect: c.successRedirect, expiresAt: session.expiresAt }, requestId), {
    "Set-Cookie": cookie(c.cookieName, session.token, c.sessionTtl, { httpOnly: true, sameSite: c.sameSite }),
    ...corsHeaders(request, env)
  });
}

async function registration(request, env, requestId) {
  if (!csrfValid(request, env)) return withHeaders(failure("CSRF_FAILED", "درخواست نامعتبر است.", requestId, 403), corsHeaders(request, env));
  const c = config(env);
  if (!c.registrationEnabled) return withHeaders(failure("FEATURE_DISABLED", "ثبت‌نام فعال نیست.", requestId, 503), corsHeaders(request, env));
  const ipKey = `register:ip:${await securityHash(env, getIP(request))}`;
  if (!(await rateLimit(env, request, ipKey, CONFIG.RATE_MAX_REGISTER_PER_IP))) {
    await audit(env, request, requestId, "REGISTRATION_RATE_LIMITED", false);
    return withHeaders(failure("RATE_LIMITED", "تعداد درخواست‌ها بیش از حد مجاز است.", requestId, 429), corsHeaders(request, env));
  }
  const body = await safeJson(request);
  const email = normalizeEmail(body?.email);
  const username = normalizeUsername(body?.username);
  const mobile = normalizeMobile(body?.mobile);
  const password = body?.password;
  const confirmation = body?.passwordConfirmation;

  if (c.requireEmail && !validEmail(email)) return withHeaders(failure("INVALID_INPUT", "ایمیل معتبر نیست.", requestId, 400), corsHeaders(request, env));
  if (username && !validUsername(username)) return withHeaders(failure("INVALID_INPUT", "نام کاربری معتبر نیست.", requestId, 400), corsHeaders(request, env));
  if (c.requireUsername && !username) return withHeaders(failure("INVALID_INPUT", "نام کاربری الزامی است.", requestId, 400), corsHeaders(request, env));
  if (mobile && !validMobile(mobile)) return withHeaders(failure("INVALID_INPUT", "شماره موبایل معتبر نیست.", requestId, 400), corsHeaders(request, env));
  if (c.requireMobile && !validMobile(mobile)) return withHeaders(failure("INVALID_INPUT", "شماره موبایل الزامی است.", requestId, 400), corsHeaders(request, env));
  if (!validPassword(password, c) || !passwordPolicy(password)) return withHeaders(failure("WEAK_PASSWORD", "رمز عبور با سیاست امنیتی سازگار نیست.", requestId, 400), corsHeaders(request, env));
  if (password !== confirmation) return withHeaders(failure("PASSWORD_MISMATCH", "تکرار رمز عبور صحیح نیست.", requestId, 400), corsHeaders(request, env));

  const identifiers = [];
  if (email) identifiers.push(["EMAIL", email]);
  if (username) identifiers.push(["USERNAME", username]);
  if (mobile) identifiers.push(["MOBILE", mobile]);
  for (const [type, value] of identifiers) {
    const existing = await env.DB.prepare(`SELECT id FROM user_identifiers WHERE type=? AND normalized_value=? LIMIT 1`).bind(type, value).first();
    if (existing) {
      await audit(env, request, requestId, "REGISTRATION_DUPLICATE", false, null, { type });
      // Do not reveal which identifier exists.
      return withHeaders(failure("REGISTRATION_UNAVAILABLE", "ثبت‌نام با این اطلاعات امکان‌پذیر نیست.", requestId, 409), corsHeaders(request, env));
    }
  }

  const userId = uuid();
  const created = now();
  const pw = await createPasswordRecord(password, c.pbkdf2Iterations);
  const status = c.requireEmailVerification || c.requireMobileVerification ? "PENDING" : "ACTIVE";

  try {
    await env.DB.prepare(`INSERT INTO users(id,status,failed_login_count,created_at,updated_at) VALUES(?,?,0,?,?)`)
      .bind(userId, status, created, created).run();
    await env.DB.prepare(`
      INSERT INTO user_credentials(id,user_id,type,password_hash,password_salt,hash_algorithm,hash_iterations,created_at,updated_at)
      VALUES(?,?,?,?,?,?,?,?,?)
    `).bind(uuid(), userId, "PASSWORD", pw.hash, pw.salt, "PBKDF2-HMAC-SHA-256", pw.iterations, created, created).run();
    for (const [type, value] of identifiers) {
      await env.DB.prepare(`
        INSERT INTO user_identifiers(id,user_id,type,value,normalized_value,is_primary,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,?)
      `).bind(uuid(), userId, type, value, value, type === "EMAIL" ? 1 : 0, created, created).run();
    }
    if (status === "ACTIVE") {
      await env.DB.prepare(`INSERT OR IGNORE INTO user_roles(user_id,role_id,created_at) VALUES(?,?,?)`).bind(userId, "role-user", created).run();
    }
  } catch (e) {

    console.error(
        "REGISTRATION_DATABASE_ERROR",
        requestId,
        {
            name: e?.name || "Error",
            message: e?.message || String(e),
            stack: e?.stack || null
        }
    );

    await audit(
        env,
        request,
        requestId,
        "REGISTRATION_FAILED",
        false,
        null,
        {
            reason: "database",
            error: e?.message || String(e)
        }
    );

    return withHeaders(
        failure(
            "REGISTRATION_FAILED",
            "ثبت‌نام انجام نشد.",
            requestId,
            500
        ),
        corsHeaders(request, env)
    );
}

  if (c.requireEmailVerification && email) {
    const token = randomToken(32);
    await env.DB.prepare(`
      INSERT INTO verification_tokens(id,user_id,type,token_hash,created_at,expires_at)
      VALUES(?,?,?,?,?,?)
    `).bind(uuid(), userId, "EMAIL", await sha256(token), created, future(c.verificationTtl)).run();
    try {
      await sendVerificationEmail(env, email, token, request);
    } catch (e) {
      await audit(env, request, requestId, "EMAIL_VERIFICATION_PROVIDER_FAILURE", false, userId, {});
      // Account remains PENDING. Do not expose provider internals.
    }
  }

  if (c.requireMobileVerification && mobile) {
    // Mobile verification uses the same OTP core. A real SMS provider is required.
    // We intentionally do not silently activate the account when SMS is unavailable.
    try {
      await createRegistrationMobileChallenge(env, request, userId, mobile, requestId);
    } catch (e) {
      await audit(env, request, requestId, "MOBILE_VERIFICATION_PROVIDER_FAILURE", false, userId, {});
    }
  }

  await audit(env, request, requestId, "REGISTRATION_SUCCESS", true, userId, { pending: status === "PENDING" });
  return withHeaders(success({
    registered: true,
    verificationRequired: status === "PENDING",
    next: status === "PENDING" ? "VERIFY" : "LOGIN"
  }, requestId), corsHeaders(request, env));
}

async function sendVerificationEmail(env, email, token, request) {
  // REQUIRED EXTERNAL ADAPTER. No fake provider is used.
  if (!env.EMAIL_API_KEY) throw new Error("EMAIL_API_KEY_MISSING");
  throw new Error("EMAIL_PROVIDER_ADAPTER_NOT_IMPLEMENTED");
}
async function createRegistrationMobileChallenge(env, request, userId, mobile, requestId) {
  const c = config(env);
  if (!c.smsEnabled || !env.SMS_API_KEY) throw new Error("SMS_PROVIDER_NOT_CONFIGURED");
  const code = otpCode();
  const id = uuid();
  await env.DB.prepare(`
    INSERT INTO otp_challenges(id,purpose,user_id,mobile_hash,otp_hash,created_at,expires_at,attempts,max_attempts,ip_hash)
    VALUES(?,?,?,?,?,?,?,?,?,?)
  `).bind(id, "MOBILE_VERIFICATION", userId, await securityHash(env, mobile), await sha256(code), now(), future(c.otpTtl), 0, c.otpMaxAttempts, await securityHash(env, getIP(request))).run();
  await sendSmsOTP(env, mobile, code);
  await audit(env, request, requestId, "MOBILE_VERIFICATION_REQUESTED", true, userId, {});
}


async function verifyMobileRegistration(request, env, requestId) {
  if (!csrfValid(request, env)) return withHeaders(failure("CSRF_FAILED", "درخواست نامعتبر است.", requestId, 403), corsHeaders(request, env));
  const body = await safeJson(request);
  const mobile = normalizeMobile(body?.mobile);
  const otp = String(body?.otp || "").trim();
  if (!validMobile(mobile) || !/^\d{6}$/.test(otp)) return withHeaders(failure("INVALID_INPUT", "اطلاعات واردشده معتبر نیست.", requestId, 400), corsHeaders(request, env));
  const row = await env.DB.prepare(`SELECT * FROM otp_challenges WHERE mobile_hash=? AND purpose='MOBILE_VERIFICATION' AND consumed_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 1`)
    .bind(await securityHash(env, mobile), now()).first();
  if (!row || Number(row.attempts) >= Number(row.max_attempts)) return withHeaders(failure("OTP_INVALID", "کد واردشده معتبر نیست.", requestId, 401), corsHeaders(request, env));
  await env.DB.prepare(`UPDATE otp_challenges SET attempts=attempts+1 WHERE id=?`).bind(row.id).run();
  if (!safeEqual(await sha256(otp), row.otp_hash)) return withHeaders(failure("OTP_INVALID", "کد واردشده معتبر نیست.", requestId, 401), corsHeaders(request, env));
  await env.DB.prepare(`UPDATE otp_challenges SET consumed_at=? WHERE id=? AND consumed_at IS NULL`).bind(now(), row.id).run();
  await env.DB.prepare(`UPDATE user_identifiers SET verified_at=?,updated_at=? WHERE user_id=? AND type='MOBILE'`).bind(now(), now(), row.user_id).run();
  const emailRequired = config(env).requireEmailVerification;
  const emailRow = await env.DB.prepare(`SELECT verified_at FROM user_identifiers WHERE user_id=? AND type='EMAIL' LIMIT 1`).bind(row.user_id).first();
  if (!emailRequired || emailRow?.verified_at) {
    await env.DB.prepare(`UPDATE users SET status='ACTIVE',updated_at=? WHERE id=? AND status='PENDING'`).bind(now(), row.user_id).run();
    await env.DB.prepare(`INSERT OR IGNORE INTO user_roles(user_id,role_id,created_at) VALUES(?,?,?)`).bind(row.user_id, "role-user", now()).run();
    await audit(env, request, requestId, "ACCOUNT_ACTIVATED", true, row.user_id, { source: "mobile" });
  }
  await audit(env, request, requestId, "MOBILE_VERIFIED", true, row.user_id, {});
  return withHeaders(success({ verified: true, next: "LOGIN" }, requestId), corsHeaders(request, env));
}

async function resendEmailVerification(request, env, requestId) {
  if (!csrfValid(request, env)) return withHeaders(failure("CSRF_FAILED", "درخواست نامعتبر است.", requestId, 403), corsHeaders(request, env));
  if (!(await rateLimit(env, request, `email-verification:ip:${await securityHash(env, getIP(request))}`, 5))) return withHeaders(failure("RATE_LIMITED", "تعداد درخواست‌ها بیش از حد مجاز است.", requestId, 429), corsHeaders(request, env));
  const body = await safeJson(request);
  const email = normalizeEmail(body?.email);
  const user = validEmail(email) ? await env.DB.prepare(`SELECT u.* FROM users u JOIN user_identifiers i ON i.user_id=u.id WHERE i.type='EMAIL' AND i.normalized_value=? LIMIT 1`).bind(email).first() : null;
  if (user && user.status === "PENDING" && config(env).requireEmailVerification) {
    const token = randomToken(32);
    await env.DB.prepare(`INSERT INTO verification_tokens(id,user_id,type,token_hash,created_at,expires_at) VALUES(?,?,?,?,?,?)`).bind(uuid(), user.id, "EMAIL", await sha256(token), now(), future(config(env).verificationTtl)).run();
    try { await sendVerificationEmail(env, email, token, request); } catch {}
    await audit(env, request, requestId, "EMAIL_VERIFICATION_REQUESTED", true, user.id, {});
  }
  return withHeaders(success({ accepted: true }, requestId), corsHeaders(request, env));
}

async function resendMobileVerification(request, env, requestId) {
  if (!csrfValid(request, env)) return withHeaders(failure("CSRF_FAILED", "درخواست نامعتبر است.", requestId, 403), corsHeaders(request, env));
  if (!(await rateLimit(env, request, `mobile-verification:ip:${await securityHash(env, getIP(request))}`, 5))) return withHeaders(failure("RATE_LIMITED", "تعداد درخواست‌ها بیش از حد مجاز است.", requestId, 429), corsHeaders(request, env));
  const body = await safeJson(request);
  const mobile = normalizeMobile(body?.mobile);
  const user = validMobile(mobile) ? await getUserByMobile(env.DB, mobile) : null;
  if (user && user.status === "PENDING" && config(env).requireMobileVerification) {
    try { await createRegistrationMobileChallenge(env, request, user.id, mobile, requestId); } catch {}
  }
  return withHeaders(success({ accepted: true }, requestId), corsHeaders(request, env));
}

async function verifyEmail(request, env, requestId) {
  if (!csrfValid(request, env)) return withHeaders(failure("CSRF_FAILED", "درخواست نامعتبر است.", requestId, 403), corsHeaders(request, env));
  const body = await safeJson(request);
  const token = String(body?.token || "");
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(token)) return withHeaders(failure("INVALID_TOKEN", "لینک تأیید معتبر نیست.", requestId, 400), corsHeaders(request, env));
  const row = await env.DB.prepare(`SELECT * FROM verification_tokens WHERE token_hash=? AND type='EMAIL' AND consumed_at IS NULL AND expires_at>? LIMIT 1`)
    .bind(await sha256(token), now()).first();
  if (!row) {
    await audit(env, request, requestId, "EMAIL_VERIFICATION_FAILED", false, null, {});
    return withHeaders(failure("INVALID_TOKEN", "لینک تأیید معتبر نیست یا منقضی شده است.", requestId, 400), corsHeaders(request, env));
  }
  await env.DB.prepare(`UPDATE verification_tokens SET consumed_at=? WHERE id=? AND consumed_at IS NULL`).bind(now(), row.id).run();
  await env.DB.prepare(`UPDATE user_identifiers SET verified_at=?,updated_at=? WHERE user_id=? AND type='EMAIL'`).bind(now(), now(), row.user_id).run();
  const c = config(env);
  if (!c.requireMobileVerification) {
    await env.DB.prepare(`UPDATE users SET status='ACTIVE',updated_at=? WHERE id=? AND status='PENDING'`).bind(now(), row.user_id).run();
    await env.DB.prepare(`INSERT OR IGNORE INTO user_roles(user_id,role_id,created_at) VALUES(?,?,?)`).bind(row.user_id, "role-user", now()).run();
    await audit(env, request, requestId, "ACCOUNT_ACTIVATED", true, row.user_id, { source: "email" });
  }
  await audit(env, request, requestId, "EMAIL_VERIFIED", true, row.user_id, {});
  return withHeaders(success({ verified: true, next: "LOGIN" }, requestId), corsHeaders(request, env));
}

async function logout(request, env, requestId) {
  if (!csrfValid(request, env)) return withHeaders(failure("CSRF_FAILED", "درخواست نامعتبر است.", requestId, 403), corsHeaders(request, env));
  const session = await currentSession(env, request);
  if (session) {
    await env.DB.prepare(`UPDATE sessions SET revoked_at=? WHERE id=?`).bind(now(), session.id).run();
    await audit(env, request, requestId, "LOGOUT", true, session.user_id, {});
  }
  const c = config(env);
  return withHeaders(success({ loggedOut: true }, requestId), {
    "Set-Cookie": cookie(c.cookieName, "", 0, { httpOnly: true, sameSite: c.sameSite }),
    ...corsHeaders(request, env)
  });
}

async function sessionInfo(request, env, requestId) {
  const session = await currentSession(env, request);
  if (!session) return withHeaders(success({ authenticated: false }, requestId), corsHeaders(request, env));
  const user = await env.DB.prepare(`SELECT id,status,created_at,last_login_at FROM users WHERE id=? LIMIT 1`).bind(session.user_id).first();
  const identifiers = await env.DB.prepare(`SELECT type,value,verified_at,is_primary FROM user_identifiers WHERE user_id=?`).bind(session.user_id).all();
  const roles = await env.DB.prepare(`SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=?`).bind(session.user_id).all();
  return withHeaders(success({
    authenticated: true,
    user: { id: user.id, status: user.status, identifiers: identifiers.results || [], roles: (roles.results || []).map(r => r.name) },
    expiresAt: session.expires_at
  }, requestId), corsHeaders(request, env));
}

async function refreshSession(request, env, requestId) {
  const session = await currentSession(env, request);
  if (!session) return withHeaders(failure("UNAUTHENTICATED", "نشست معتبر نیست.", requestId, 401), corsHeaders(request, env));
  if (!csrfValid(request, env)) return withHeaders(failure("CSRF_FAILED", "درخواست نامعتبر است.", requestId, 403), corsHeaders(request, env));
  await env.DB.prepare(`UPDATE sessions SET revoked_at=? WHERE id=?`).bind(now(), session.id).run();
  const next = await createSession(env, request, session.user_id);
  const c = config(env);
  await audit(env, request, requestId, "SESSION_ROTATED", true, session.user_id, {});
  return withHeaders(success({ expiresAt: next.expiresAt }, requestId), {
    "Set-Cookie": cookie(c.cookieName, next.token, c.sessionTtl, { httpOnly: true, sameSite: c.sameSite }),
    ...corsHeaders(request, env)
  });
}

async function deriveAesKey(secret) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(secret));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function encryptText(secret, plaintext) {
  const iv = bytes(12);
  const key = await deriveAesKey(secret);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  const combined = new Uint8Array(iv.length + ct.byteLength);
  combined.set(iv, 0); combined.set(new Uint8Array(ct), iv.length);
  return b64u(combined);
}
async function decryptText(secret, encoded) {
  const combined = fromB64u(encoded);
  const iv = combined.slice(0, 12);
  const ct = combined.slice(12);
  const key = await deriveAesKey(secret);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return dec.decode(plain);
}
function base64UrlJson(value) { return b64u(enc.encode(JSON.stringify(value))); }
function parseJwt(token) {
  const parts = String(token).split(".");
  if (parts.length !== 3) throw new Error("INVALID_JWT");
  return { header: JSON.parse(dec.decode(fromB64u(parts[0]))), payload: JSON.parse(dec.decode(fromB64u(parts[1]))), signingInput: `${parts[0]}.${parts[1]}`, signature: fromB64u(parts[2]) };
}
async function oidcDiscovery(env) {
  const issuer = config(env).oidcIssuer.replace(/\/$/, "");
  if (!issuer) throw new Error("OIDC_ISSUER_MISSING");
  const response = await fetch(`${issuer}/.well-known/openid-configuration`, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error("OIDC_DISCOVERY_FAILED");
  const doc = await response.json();
  if (String(doc.issuer || "").replace(/\/$/, "") !== issuer) throw new Error("OIDC_ISSUER_MISMATCH");
  return doc;
}
async function oidcStart(request, env, requestId) {
  if (!config(env).oidcEnabled) return withHeaders(failure("FEATURE_DISABLED", "ورود با OpenID فعال نیست.", requestId, 503), corsHeaders(request, env));
  if (!config(env).oidcIssuer || !config(env).oidcClientId || !config(env).oidcRedirectUri || !env.OIDC_CLIENT_SECRET || !env.OIDC_STATE_SECRET) {
    return withHeaders(failure("PROVIDER_NOT_CONFIGURED", "ورود با OpenID هنوز پیکربندی نشده است.", requestId, 503), corsHeaders(request, env));
  }
  const discovery = await oidcDiscovery(env);
  const state = randomToken(32);
  const nonce = randomToken(32);
  const verifier = randomToken(32);
  const challenge = b64u(await crypto.subtle.digest("SHA-256", enc.encode(verifier)));
  const redirectUri = config(env).oidcRedirectUri;
  const stateHash = await sha256(state);
  const nonceHash = await sha256(nonce);
  const encryptedVerifier = await encryptText(env.OIDC_STATE_SECRET, verifier);
  await env.DB.prepare(`
    INSERT INTO oidc_transactions(id,state_hash,nonce_hash,nonce_ciphertext,code_verifier_ciphertext,redirect_uri,created_at,expires_at)
    VALUES(?,?,?,?,?,?,?,?)
  `).bind(uuid(), stateHash, nonceHash, await encryptText(env.OIDC_STATE_SECRET, nonce), encryptedVerifier, redirectUri, now(), future(CONFIG.OIDC_TRANSACTION_TTL_SECONDS)).run();
  const u = new URL(discovery.authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", config(env).oidcClientId);
  u.searchParams.set("redirect_uri", redirectUri);
  u.searchParams.set("scope", "openid email profile");
  u.searchParams.set("state", state);
  u.searchParams.set("nonce", nonce);
  u.searchParams.set("code_challenge", challenge);
  u.searchParams.set("code_challenge_method", "S256");
  await audit(env, request, requestId, "OIDC_START", true, null, {});
  return withHeaders(new Response(null, { status: 302, headers: { Location: u.toString(), ...corsHeaders(request, env) } }));
}
async function verifyJwtSignature(jwt, jwks) {
  const alg = jwt.header?.alg;
  const jwk = (jwks.keys || []).find(k => k.kid === jwt.header?.kid && k.alg === alg) || (jwks.keys || []).find(k => k.kid === jwt.header?.kid);
  if (!jwk) return false;
  let algorithm;
  if (alg === "RS256") algorithm = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  else if (alg === "ES256") algorithm = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
  else return false;
  const key = await crypto.subtle.importKey("jwk", jwk, algorithm, false, ["verify"]);
  return crypto.subtle.verify(algorithm, key, jwt.signature, enc.encode(jwt.signingInput));
}
async function validateIdToken(env, idToken, expectedNonce, discovery) {
  const jwt = parseJwt(idToken);
  const verified = await verifyJwtSignature(jwt, await (async () => {
    const r = await fetch(discovery.jwks_uri, { headers: { Accept: "application/json" } });
    if (!r.ok) throw new Error("OIDC_JWKS_FAILED");
    return r.json();
  })());
  if (!verified) throw new Error("OIDC_SIGNATURE_INVALID");
  const p = jwt.payload;
  const issuer = config(env).oidcIssuer.replace(/\/$/, "");
  const audOk = Array.isArray(p.aud) ? p.aud.includes(config(env).oidcClientId) : p.aud === config(env).oidcClientId;
  const nowSec = Math.floor(Date.now() / 1000);
  const expOk = Number(p.exp) > nowSec;
  const iatOk = Number(p.iat || 0) <= nowSec + 60;
  const nonceOk = safeEqual(await sha256(String(p.nonce || "")), await sha256(expectedNonce));
  if (p.iss !== issuer || !audOk || !expOk || !iatOk || !nonceOk || !p.sub) throw new Error("OIDC_CLAIMS_INVALID");
  return p;
}
async function oidcCallback(request, env, requestId) {
  const c = config(env);
  if (!c.oidcEnabled) return failure("FEATURE_DISABLED", "ورود با OpenID فعال نیست.", requestId, 503);
  const url = new URL(request.url);
  const errorParam = url.searchParams.get("error");
  if (errorParam) return redirectLoginWithError(c, "ورود با OpenID لغو یا رد شد.");
  const state = url.searchParams.get("state") || "";
  const code = url.searchParams.get("code") || "";
  if (!state || !code) return redirectLoginWithError(c, "پاسخ OpenID معتبر نیست.");
  const tx = await env.DB.prepare(`SELECT * FROM oidc_transactions WHERE state_hash=? AND consumed_at IS NULL AND expires_at>? LIMIT 1`).bind(await sha256(state), now()).first();
  if (!tx) {
    await audit(env, request, requestId, "OIDC_INVALID_STATE", false, null, {});
    return redirectLoginWithError(c, "درخواست OpenID منقضی یا نامعتبر است.");
  }
  if (tx.redirect_uri !== c.oidcRedirectUri || c.oidcRedirectUri !== url.origin + url.pathname) {
    await audit(env, request, requestId, "OIDC_INVALID_REDIRECT", false, null, {});
    return redirectLoginWithError(c, "آدرس بازگشت OpenID معتبر نیست.");
  }
  const discovery = await oidcDiscovery(env);
  const verifier = await decryptText(env.OIDC_STATE_SECRET, tx.code_verifier_ciphertext);
  const form = new URLSearchParams();
  form.set("grant_type", "authorization_code");
  form.set("code", code);
  form.set("redirect_uri", c.oidcRedirectUri);
  form.set("code_verifier", verifier);
  const tokenHeaders = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };
  if (c.oidcTokenAuthMethod === "client_secret_basic") {
    tokenHeaders.Authorization = "Basic " + btoa(`${c.oidcClientId}:${env.OIDC_CLIENT_SECRET}`);
  } else {
    form.set("client_id", c.oidcClientId);
    form.set("client_secret", env.OIDC_CLIENT_SECRET);
  }
  const tokenResponse = await fetch(discovery.token_endpoint, { method: "POST", headers: tokenHeaders, body: form.toString() });
  if (!tokenResponse.ok) {
    await audit(env, request, requestId, "OIDC_TOKEN_EXCHANGE_FAILED", false, null, {});
    return redirectLoginWithError(c, "ورود با OpenID انجام نشد.");
  }
  const tokenData = await tokenResponse.json();
  if (!tokenData.id_token) return redirectLoginWithError(c, "پاسخ OpenID ناقص است.");
  const nonce = await decryptText(env.OIDC_STATE_SECRET, tx.nonce_ciphertext);
  const claims = await validateIdToken(env, tokenData.id_token, nonce, discovery);
  await env.DB.prepare(`UPDATE oidc_transactions SET consumed_at=? WHERE id=? AND consumed_at IS NULL`).bind(now(), tx.id).run();

  let identity = await env.DB.prepare(`SELECT * FROM oidc_identities WHERE issuer=? AND subject=? LIMIT 1`).bind(claims.iss, claims.sub).first();
  let user;
  if (identity) {
    user = await env.DB.prepare(`SELECT * FROM users WHERE id=? LIMIT 1`).bind(identity.user_id).first();
  } else {
    const email = normalizeEmail(claims.email || "");
    if (!email) return redirectLoginWithError(c, "ارائه‌دهنده OpenID ایمیل معتبر ارائه نکرد.");
    const identifier = await env.DB.prepare(`SELECT user_id FROM user_identifiers WHERE type='EMAIL' AND normalized_value=? LIMIT 1`).bind(email).first();
    if (identifier) {
      user = await env.DB.prepare(`SELECT * FROM users WHERE id=? LIMIT 1`).bind(identifier.user_id).first();
    } else {
      user = { id: uuid(), status: "ACTIVE" };
      await env.DB.prepare(`INSERT INTO users(id,status,failed_login_count,created_at,updated_at) VALUES(?,?,0,?,?)`).bind(user.id, "ACTIVE", now(), now()).run();
      await env.DB.prepare(`INSERT INTO user_identifiers(id,user_id,type,value,normalized_value,verified_at,is_primary,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`)
        .bind(uuid(), user.id, "EMAIL", email, email, now(), 1, now(), now()).run();
      await env.DB.prepare(`INSERT OR IGNORE INTO user_roles(user_id,role_id,created_at) VALUES(?,?,?)`).bind(user.id, "role-user", now()).run();
    }
    await env.DB.prepare(`INSERT INTO oidc_identities(id,user_id,issuer,subject,email_snapshot,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`)
      .bind(uuid(), user.id, claims.iss, claims.sub, email || null, now(), now()).run();
  }
  if (!user || user.status !== "ACTIVE") return redirectLoginWithError(c, "حساب کاربری قابل استفاده نیست.");
  const session = await createSession(env, request, user.id);
  await audit(env, request, requestId, "OIDC_LOGIN", true, user.id, { issuer: claims.iss });
  return withHeaders(new Response(null, {
    status: 302,
    headers: {
      Location: c.successRedirect,
      "Set-Cookie": cookie(c.cookieName, session.token, c.sessionTtl, { httpOnly: true, sameSite: c.sameSite })
    }
  }));
}
function redirectLoginWithError(c, message) {
  const u = new URL(c.loginPage || "/login.html", "https://invalid.example");
  u.searchParams.set("error", message);
  return new Response(null, { status: 302, headers: { Location: u.toString() } });
}

async function forgotPassword(request, env, requestId) {
  if (!csrfValid(request, env)) return withHeaders(failure("CSRF_FAILED", "درخواست نامعتبر است.", requestId, 403), corsHeaders(request, env));
  if (!(await rateLimit(env, request, `password-reset:ip:${await securityHash(env, getIP(request))}`, CONFIG.RATE_MAX_PASSWORD_RESET_PER_IP))) {
    return withHeaders(failure("RATE_LIMITED", "تعداد درخواست‌ها بیش از حد مجاز است.", requestId, 429), corsHeaders(request, env));
  }
  const body = await safeJson(request);
  const identifier = normalizeEmail(body?.identifier);
  const user = validEmail(identifier) ? await env.DB.prepare(`
    SELECT u.* FROM users u JOIN user_identifiers i ON i.user_id=u.id
    WHERE i.type='EMAIL' AND i.normalized_value=? LIMIT 1
  `).bind(identifier).first() : null;
  if (user) {
    const token = randomToken(32);
    await env.DB.prepare(`INSERT INTO password_reset_tokens(id,user_id,token_hash,created_at,expires_at) VALUES(?,?,?,?,?)`)
      .bind(uuid(), user.id, await sha256(token), now(), future(config(env).passwordResetTtl)).run();
    try { await sendPasswordResetEmail(env, identifier, token, request); } catch {}
    await audit(env, request, requestId, "PASSWORD_RESET_REQUESTED", true, user.id, {});
  }
  // Always generic to prevent enumeration.
  return withHeaders(success({ accepted: true }, requestId), corsHeaders(request, env));
}
async function sendPasswordResetEmail(env, email, token, request) {
  if (!env.EMAIL_API_KEY) throw new Error("EMAIL_API_KEY_MISSING");
  throw new Error("EMAIL_PROVIDER_ADAPTER_NOT_IMPLEMENTED");
}
async function resetPassword(request, env, requestId) {
  if (!csrfValid(request, env)) return withHeaders(failure("CSRF_FAILED", "درخواست نامعتبر است.", requestId, 403), corsHeaders(request, env));
  const body = await safeJson(request);
  const token = String(body?.token || "");
  const password = body?.password;
  const confirmation = body?.passwordConfirmation;
  if (!validPassword(password, config(env)) || password !== confirmation) return withHeaders(failure("INVALID_INPUT", "رمز عبور معتبر نیست.", requestId, 400), corsHeaders(request, env));
  const row = await env.DB.prepare(`SELECT * FROM password_reset_tokens WHERE token_hash=? AND consumed_at IS NULL AND expires_at>? LIMIT 1`).bind(await sha256(token), now()).first();
  if (!row) return withHeaders(failure("INVALID_TOKEN", "توکن بازیابی معتبر نیست.", requestId, 400), corsHeaders(request, env));
  const pw = await createPasswordRecord(password, config(env).pbkdf2Iterations);
  await env.DB.prepare(`UPDATE user_credentials SET password_hash=?,password_salt=?,hash_iterations=?,updated_at=? WHERE user_id=? AND type='PASSWORD'`)
    .bind(pw.hash, pw.salt, pw.iterations, now(), row.user_id).run();
  await env.DB.prepare(`UPDATE password_reset_tokens SET consumed_at=? WHERE id=?`).bind(now(), row.id).run();
  await revokeAllSessions(env, row.user_id);
  await audit(env, request, requestId, "PASSWORD_RESET_SUCCESS", true, row.user_id, {});
  return withHeaders(success({ reset: true }, requestId), corsHeaders(request, env));
}

async function protectedDashboard(request, env, requestId) {
  // Only works when the Worker is the origin for the protected page.
  const session = await currentSession(env, request);
  if (!session) return new Response("Unauthorized", { status: 401, headers: securityHeaders() });
  return success({ authenticated: true }, requestId);
}

async function router(request, env, requestId) {
  const url = new URL(request.url);
  const p = url.pathname;
  const m = request.method;

  if (p === "/api/auth/config" && m === "GET") return withHeaders(success(publicConfig(env), requestId), corsHeaders(request, env));
  if (p === "/api/auth/csrf" && m === "GET") return issueCsrf(env, request, requestId);
  if (p === "/api/auth/login/password" && m === "POST") return loginPassword(request, env, requestId);
  if (p === "/api/auth/login/sms/request" && m === "POST") return requestOtp(request, env, requestId, "LOGIN");
  if (p === "/api/auth/login/sms/verify" && m === "POST") return verifyOtp(request, env, requestId, "LOGIN");
  if (p === "/api/auth/oidc/start" && m === "GET") return oidcStart(request, env, requestId);
  if (p === "/api/auth/oidc/callback" && m === "GET") return oidcCallback(request, env, requestId);
  if (p === "/api/auth/session" && m === "GET") return sessionInfo(request, env, requestId);
  if (p === "/api/auth/refresh" && m === "POST") return refreshSession(request, env, requestId);
  if (p === "/api/auth/logout" && m === "POST") return logout(request, env, requestId);
  if (p === "/api/auth/register" && m === "POST") return registration(request, env, requestId);
  if (p === "/api/auth/register/verify-email" && m === "POST") return verifyEmail(request, env, requestId);
  if (p === "/api/auth/register/resend-verification" && m === "POST") return resendEmailVerification(request, env, requestId);
  if (p === "/api/auth/register/verify-mobile" && m === "POST") return verifyMobileRegistration(request, env, requestId);
  if (p === "/api/auth/register/resend-mobile-verification" && m === "POST") return resendMobileVerification(request, env, requestId);
  if (p === "/api/auth/password/forgot" && m === "POST") return forgotPassword(request, env, requestId);
  if (p === "/api/auth/password/reset" && m === "POST") return resetPassword(request, env, requestId);
  if (p === "/api/auth/dashboard-check" && m === "GET") return protectedDashboard(request, env, requestId);

  return null;
}

export default {
  async fetch(request, env) {
    const requestId = uuid();
    try {
      if (request.method === "OPTIONS") {
        if (!originAllowed(request, env)) return withHeaders(new Response(null, { status: 403 }));
        return withHeaders(new Response(null, { status: 204, headers: corsHeaders(request, env) }));
      }
      if (!originAllowed(request, env)) {
        await audit(env, request, requestId, "ORIGIN_DENIED", false, null, {});
        return withHeaders(failure("ORIGIN_DENIED", "درخواست نامعتبر است.", requestId, 403));
      }
      const response = await router(request, env, requestId);
      if (response) return withHeaders(response, corsHeaders(request, env));
      return withHeaders(new Response("Not Found", { status: 404 }));
    } catch (e) {
      console.error("AUTH_INTERNAL_ERROR", requestId, e?.message || e);
      await audit(env, request, requestId, "INTERNAL_ERROR", false, null, { type: e?.name || "Error" });
      return withHeaders(failure("INTERNAL_ERROR", "خطای داخلی رخ داد.", requestId, 500));
    }
  }
};
