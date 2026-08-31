/* Reusable Authentication Core for Cloudflare Workers + D1.
 * External integrations intentionally use adapters. No secrets belong here.
 */
const CONFIG = {
  APP_NAME: "Authentication Core",
  DB_BINDING: "DB",
  ASSETS_BINDING: "ASSETS",
  COOKIE_NAME: "__Host-auth_session",
  CSRF_COOKIE: "__Host-auth_csrf",
  SESSION_TTL_SECONDS: 60 * 60 * 24 * 7,
  OTP_TTL_SECONDS: 180,
  OTP_MAX_ATTEMPTS: 5,
  OIDC_TX_TTL_SECONDS: 300,
  PBKDF2_ITERATIONS: 310000,
  PASSWORD_MIN_LENGTH: 10,
  MAX_PASSWORD_LENGTH: 256,
  MAX_USERNAME_LENGTH: 100,
  MAX_EMAIL_LENGTH: 254,
  MAX_PHONE_LENGTH: 32,
  LOGIN_MAX_FAILURES: 8,
  LOGIN_LOCK_SECONDS: 300,
  CSRF_TTL_SECONDS: 3600,
  ALLOWED_ORIGINS: [],
  LOGIN_SUCCESS_REDIRECT: "/dashboard.html",
  OIDC: {
    ENABLED: false,
    PROVIDER_NAME: "default",
    ISSUER: "",
    CLIENT_ID: "",
    REDIRECT_URI: "",
    SCOPES: "openid profile email"
  },
  SMS: { ENABLED: false, PROVIDER_NAME: "REPLACE_ME" }
};

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function nowIso() { return new Date().toISOString(); }
function addSeconds(sec) { return new Date(Date.now() + sec * 1000).toISOString(); }
function b64u(bytes) { let s = ""; for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b); return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,""); }
function fromB64u(s) { s = s.replace(/-/g,"+").replace(/_/g,"/"); while (s.length % 4) s += "="; const bin = atob(s); const a = new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) a[i]=bin.charCodeAt(i); return a; }
function randomBytes(n=32) { const a=new Uint8Array(n); crypto.getRandomValues(a); return a; }
function randomToken(n=32) { return b64u(randomBytes(n)); }
function uuid() { return crypto.randomUUID(); }
async function sha256(value) { return b64u(await crypto.subtle.digest("SHA-256", typeof value === "string" ? textEncoder.encode(value) : value)); }
async function hmacSha256(secret, value) { const key=await crypto.subtle.importKey("raw",textEncoder.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]); return b64u(await crypto.subtle.sign("HMAC",key,textEncoder.encode(value))); }
function safeEqual(a,b){ if(typeof a!=="string"||typeof b!=="string")return false; const x=textEncoder.encode(a),y=textEncoder.encode(b); if(x.length!==y.length)return false; let d=0; for(let i=0;i<x.length;i++)d|=x[i]^y[i]; return d===0; }
function json(data,status=200,headers={}){ return new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8",...headers}}); }
function api(ok,data,error,requestId,status=200){ return json({success:ok,data:ok?data:null,error:ok?null:error,requestId},status); }
function error(code,message,status){ return {code,message,status}; }

function publicConfig(env){ return {appName: env.APP_NAME || CONFIG.APP_NAME, successRedirect: env.LOGIN_SUCCESS_REDIRECT || CONFIG.LOGIN_SUCCESS_REDIRECT, oidcEnabled: env.OIDC_ENABLED === true || env.OIDC_ENABLED === "true", smsEnabled: env.SMS_ENABLED === true || env.SMS_ENABLED === "true"}; }
function allowedOrigins(env){ const raw=env.ALLOWED_ORIGINS || ""; return raw.split(",").map(x=>x.trim()).filter(Boolean); }
function requestOrigin(request){ return request.headers.get("Origin") || ""; }
function isAllowedOrigin(request,env){ const origin=requestOrigin(request); const allowed=allowedOrigins(env); if(!origin) return true; return allowed.length===0 ? origin===new URL(request.url).origin : allowed.includes(origin); }
function clientIp(request){ return request.headers.get("CF-Connecting-IP") || "0.0.0.0"; }
function userAgent(request){ return request.headers.get("User-Agent") || ""; }
function cookieMap(request){ const out={}; const raw=request.headers.get("Cookie")||""; for(const part of raw.split(";")){const i=part.indexOf("=");if(i>0)out[part.slice(0,i).trim()]=decodeURIComponent(part.slice(i+1).trim());} return out; }
function cookie(name,value,maxAge,secure=true,httpOnly=false,sameSite="Lax"){ return `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; ${secure?"Secure; ":""}${httpOnly?"HttpOnly; ":""}SameSite=${sameSite}`; }
function securityHeaders(){ return {"Content-Security-Policy":"default-src 'self'; script-src 'self' 'sha256-dULPQ0E07U6QJ0+tZGPhJGRstcPb+jjUL/pYF5WM7Cs='; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'","X-Content-Type-Options":"nosniff","Referrer-Policy":"strict-origin-when-cross-origin","Permissions-Policy":"camera=(), microphone=(), geolocation=()","X-Frame-Options":"DENY"}; }
function withSecurity(response,extra={}){ const h=new Headers(response.headers); for(const [k,v] of Object.entries(securityHeaders()))h.set(k,v); for(const [k,v] of Object.entries(extra))h.set(k,v); return new Response(response.body,{status:response.status,statusText:response.statusText,headers:h}); }
function csrfRequired(request,env){ if(request.method==="GET"||request.method==="HEAD"||request.method==="OPTIONS")return true; if(!isAllowedOrigin(request,env))return false; const cookies=cookieMap(request), c=cookies[CONFIG.CSRF_COOKIE], h=request.headers.get("X-CSRF-Token"); return !!c && !!h && safeEqual(c,h); }

function normalizeIdentifier(v){ return String(v||"").trim().toLowerCase(); }
function normalizePhone(v){ return String(v||"").replace(/[\s()-]/g,"").trim(); }
function validEmail(v){ return typeof v==="string" && v.length<=CONFIG.MAX_EMAIL_LENGTH && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function validUsername(v){ return typeof v==="string" && v.length>=3 && v.length<=CONFIG.MAX_USERNAME_LENGTH && /^[A-Za-z0-9._-]+$/.test(v); }
function validPhone(v){ return typeof v==="string" && v.length>=8 && v.length<=CONFIG.MAX_PHONE_LENGTH && /^\+?[1-9][0-9]{7,14}$/.test(v); }
function validPassword(v){ return typeof v==="string" && v.length>=CONFIG.PASSWORD_MIN_LENGTH && v.length<=CONFIG.MAX_PASSWORD_LENGTH; }
function validOtp(v){ return typeof v==="string" && /^\d{6}$/.test(v); }

async function passwordHash(password,saltB64,iterations){ const salt=fromB64u(saltB64); const key=await crypto.subtle.importKey("raw",textEncoder.encode(password),"PBKDF2",false,["deriveBits"]); const bits=await crypto.subtle.deriveBits({name:"PBKDF2",salt,iterations,hash:"SHA-256"},key,256); return b64u(bits); }
async function createPasswordHash(password,env){ const salt=b64u(randomBytes(16)); const iterations=Number(env.PBKDF2_ITERATIONS||CONFIG.PBKDF2_ITERATIONS); return {salt,hash:await passwordHash(password,salt,iterations),iterations}; }

async function secretKey(secret){ return crypto.subtle.importKey("raw",await crypto.subtle.digest("SHA-256",textEncoder.encode(secret)),"AES-GCM",false,["encrypt","decrypt"]); }
async function encryptText(secret,plaintext){ const key=await secretKey(secret),iv=randomBytes(12); const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,textEncoder.encode(plaintext)); const out=new Uint8Array(iv.length+ct.byteLength);out.set(iv);out.set(new Uint8Array(ct),iv.length);return b64u(out); }
async function decryptText(secret,cipher){ const all=fromB64u(cipher),iv=all.slice(0,12),ct=all.slice(12),key=await secretKey(secret); const p=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,ct); return textDecoder.decode(p); }

async function hashContext(env,value){ const secret=env.AUDIT_HASH_SECRET || env.SESSION_SECRET; if(!secret) throw new Error("Missing AUDIT_HASH_SECRET/SESSION_SECRET"); return hmacSha256(secret,value); }
async function audit(env,{userId=null,eventType,success=true,requestId,request}){ try{ const db=env.DB; const ip=await hashContext(env,clientIp(request)), ua=await hashContext(env,userAgent(request)); const meta=JSON.stringify({method:request.method,path:new URL(request.url).pathname}); await db.prepare(`INSERT INTO audit_logs(id,user_id,event_type,success,ip_hash,user_agent_hash,request_id,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)`).bind(uuid(),userId,eventType,success?1:0,ip,ua,requestId,meta,nowIso()).run(); }catch(e){ console.error("audit_write_failed",requestId,e?.message); } }
async function logAttempt(env,{userId=null,identifier="",method,success,reason,request}){ try{const idh=identifier?await hashContext(env,normalizeIdentifier(identifier)):null; const iph=await hashContext(env,clientIp(request)),uah=await hashContext(env,userAgent(request)); await env.DB.prepare(`INSERT INTO login_attempts(id,user_id,identifier_hash,method,success,reason_code,ip_hash,user_agent_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?)`).bind(uuid(),userId,idh,method,success?1:0,reason||null,iph,uah,nowIso()).run();}catch(e){console.error("attempt_log_failed",e?.message);} }

async function rateLimit(env,key,bindingName="AUTH_RATE_LIMIT"){ const limiter=env[bindingName]; if(!limiter)return true; try{const r=await limiter.limit({key});return !!r.success;}catch(e){console.error("rate_limit_error",bindingName,e?.message);return true;} }
async function randomOtp(){ const max=4294967296,limit=max-(max%900000); while(true){const n=crypto.getRandomValues(new Uint32Array(1))[0];if(n<limit)return String(100000+(n%900000)).padStart(6,"0");} }
async function issueCsrf(request,env){ const token=randomToken(32); const response=api(true,{csrfToken:token,config:publicConfig(env)},null,crypto.randomUUID(),200); return withSecurity(response,{"Set-Cookie":cookie(CONFIG.CSRF_COOKIE,token,CONFIG.CSRF_TTL_SECONDS,true,false,"Lax"),"Cache-Control":"no-store"}); }

async function createSession(env,userId,request){ if(!env.SESSION_SECRET) throw new Error("SESSION_SECRET is required"); const token=randomToken(32),hash=await sha256(token),id=uuid(),now=nowIso(),exp=addSeconds(Number(env.SESSION_TTL_SECONDS||CONFIG.SESSION_TTL_SECONDS)); const iph=await hashContext(env,clientIp(request)),uah=await hashContext(env,userAgent(request)); await env.DB.prepare(`INSERT INTO sessions(id,user_id,token_hash,created_at,expires_at,last_seen_at,ip_hash,user_agent_hash) VALUES(?,?,?,?,?,?,?,?)`).bind(id,userId,hash,now,exp,now,iph,uah).run(); return {token,id,expiresAt:exp}; }
async function getSession(env,request){ const token=cookieMap(request)[CONFIG.COOKIE_NAME]; if(!token)return null; const hash=await sha256(token); const row=await env.DB.prepare(`SELECT s.*,u.status,u.username,u.email,u.phone FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.status='active' LIMIT 1`).bind(hash,nowIso()).first(); if(!row)return null; await env.DB.prepare(`UPDATE sessions SET last_seen_at=? WHERE id=?`).bind(nowIso(),row.id).run(); return row; }
async function revokeSession(env,request){ const token=cookieMap(request)[CONFIG.COOKIE_NAME]; if(!token)return; const hash=await sha256(token); await env.DB.prepare(`UPDATE sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL`).bind(nowIso(),hash).run(); }
function sessionCookie(token,maxAge,sameSite="Lax"){ return cookie(CONFIG.COOKIE_NAME,token,maxAge,true,true,sameSite); }
function clearSessionCookie(){ return `${CONFIG.COOKIE_NAME}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`; }

async function findUserByIdentifier(db,identifier){ const n=normalizeIdentifier(identifier); return db.prepare(`SELECT * FROM users WHERE (username IS NOT NULL AND lower(username)=?) OR (email IS NOT NULL AND lower(email)=?) LIMIT 1`).bind(n,n).first(); }
async function findUserByPhone(db,phone){ return db.prepare(`SELECT * FROM users WHERE phone=? LIMIT 1`).bind(phone).first(); }
async function updateLoginFailure(env,user){ const count=Number(user.failed_login_count||0)+1; const lock=count>=CONFIG.LOGIN_MAX_FAILURES?addSeconds(CONFIG.LOGIN_LOCK_SECONDS):null; await env.DB.prepare(`UPDATE users SET failed_login_count=?,locked_until=?,updated_at=? WHERE id=?`).bind(count,lock,nowIso(),user.id).run(); }
async function clearLoginFailure(env,userId){ await env.DB.prepare(`UPDATE users SET failed_login_count=0,locked_until=NULL,last_login_at=?,updated_at=? WHERE id=?`).bind(nowIso(),nowIso(),userId).run(); }

async function passwordLogin(request,env,requestId){ if(!csrfRequired(request,env))return api(false,null,error("CSRF_FAILED","درخواست نامعتبر است.",403),requestId,403); if(!(await rateLimit(env,`password:ip:${clientIp(request)}`,"AUTH_RATE_LIMIT")))return api(false,null,error("RATE_LIMITED","تعداد درخواست‌ها بیش از حد مجاز است.",429),requestId,429); const body=await request.json().catch(()=>null); const identifier=String(body?.identifier||"").trim(),password=body?.password; if(identifier && !(await rateLimit(env,`password:id:${await hashContext(env,normalizeIdentifier(identifier))}`,"AUTH_RATE_LIMIT")))return api(false,null,error("RATE_LIMITED","تعداد درخواست‌ها بیش از حد مجاز است.",429),requestId,429); if(identifier.length>CONFIG.MAX_EMAIL_LENGTH+CONFIG.MAX_USERNAME_LENGTH||!validPassword(password))return api(false,null,error("AUTHENTICATION_FAILED","نام کاربری یا رمز عبور صحیح نیست",401),requestId,401); const user=await findUserByIdentifier(env.DB,identifier); let valid=false; if(user){ const cred=await env.DB.prepare(`SELECT * FROM user_credentials WHERE user_id=?`).bind(user.id).first(); const locked=user.locked_until && user.locked_until>nowIso(); if(cred&&!locked){ const hash=await passwordHash(password,cred.password_salt,Number(cred.hash_iterations)); valid=safeEqual(hash,cred.password_hash); } }
 await logAttempt(env,{userId:user?.id||null,identifier,method:"password",success:valid,reason:valid?null:"invalid_credentials",request});
 if(!valid){ if(user)await updateLoginFailure(env,user); await audit(env,{userId:user?.id||null,eventType:"LOGIN_FAILED",success:false,requestId,request}); return api(false,null,error("AUTHENTICATION_FAILED","نام کاربری یا رمز عبور صحیح نیست",401),requestId,401); }
 await clearLoginFailure(env,user.id); const session=await createSession(env,user.id,request); await audit(env,{userId:user.id,eventType:"LOGIN_SUCCESS",success:true,requestId,request}); const sameSite=env.COOKIE_SAMESITE||"Lax"; const headers={"Set-Cookie":sessionCookie(session.token,Number(env.SESSION_TTL_SECONDS||CONFIG.SESSION_TTL_SECONDS),sameSite),"Cache-Control":"no-store"}; return withHeaders(headers)(api(true,{redirect:env.LOGIN_SUCCESS_REDIRECT||CONFIG.LOGIN_SUCCESS_REDIRECT,expiresAt:session.expiresAt},null,requestId,200));
}
function withHeaders(headers){ return response=>{const h=new Headers(response.headers);for(const[k,v]of Object.entries(headers))h.append(k,v);return new Response(response.body,{status:response.status,headers:h});}; }

async function sendSmsPlaceholder(){ throw new Error("SMS provider is not configured. Implement SMSAdapter before enabling SMS in production."); }
async function requestSms(request,env,requestId){ if(!csrfRequired(request,env))return api(false,null,error("CSRF_FAILED","درخواست نامعتبر است.",403),requestId,403); if(env.SMS_ENABLED!==true&&env.SMS_ENABLED!=="true")return api(false,null,error("FEATURE_DISABLED","ورود پیامکی فعال نیست.",404),requestId,404); const body=await request.json().catch(()=>null),phone=normalizePhone(body?.phone); if(!validPhone(phone))return api(false,null,error("INVALID_INPUT","اطلاعات واردشده معتبر نیست.",400),requestId,400); if(!(await rateLimit(env,`sms-ip:${clientIp(request)}`,"SMS_RATE_LIMIT"))||!(await rateLimit(env,`sms-phone:${phone}`,"SMS_RATE_LIMIT")))return api(false,null,error("RATE_LIMITED","لطفاً کمی بعد دوباره تلاش کنید.",429),requestId,429); const recent=await env.DB.prepare(`SELECT id FROM otp_challenges WHERE phone=? AND created_at>? AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1`).bind(phone,new Date(Date.now()-60000).toISOString()).first(); if(recent)return api(true,{message:"اگر شماره قابل استفاده باشد، کد ارسال خواهد شد."},null,requestId,200); const otp=await randomOtp(); const otpHash=await hmacSha256(env.SESSION_SECRET||"",otp); const user=await findUserByPhone(env.DB,phone); const id=uuid(),now=nowIso(),exp=addSeconds(Number(env.OTP_TTL_SECONDS||CONFIG.OTP_TTL_SECONDS)); await env.DB.prepare(`INSERT INTO otp_challenges(id,user_id,phone,otp_hash,purpose,attempts,max_attempts,created_at,expires_at,request_ip_hash) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(id,user?.id||null,phone,otpHash,"login",0,Number(env.OTP_MAX_ATTEMPTS||CONFIG.OTP_MAX_ATTEMPTS),now,exp,await hashContext(env,clientIp(request))).run(); try{ await SMSAdapter.sendOTP({phone,otp,expiresAt:exp},env); }catch(e){ await env.DB.prepare(`DELETE FROM otp_challenges WHERE id=?`).bind(id).run(); console.error("sms_provider_error",requestId,e?.message); return api(false,null,error("PROVIDER_UNAVAILABLE","سرویس پیامک در دسترس نیست.",503),requestId,503); } await audit(env,{userId:user?.id||null,eventType:"OTP_REQUESTED",success:true,requestId,request}); return api(true,{message:"اگر شماره قابل استفاده باشد، کد ارسال خواهد شد."},null,requestId,200); }
async function verifySms(request,env,requestId){ if(!csrfRequired(request,env))return api(false,null,error("CSRF_FAILED","درخواست نامعتبر است.",403),requestId,403); if(env.SMS_ENABLED!==true&&env.SMS_ENABLED!=="true")return api(false,null,error("FEATURE_DISABLED","ورود پیامکی فعال نیست.",404),requestId,404); const body=await request.json().catch(()=>null),phone=normalizePhone(body?.phone),otp=String(body?.otp||""); if(!validPhone(phone)||!validOtp(otp))return api(false,null,error("OTP_INVALID","کد واردشده صحیح نیست.",401),requestId,401); if(!(await rateLimit(env,`otp-ip:${clientIp(request)}`,"OTP_RATE_LIMIT"))||!(await rateLimit(env,`otp-phone:${phone}`,"OTP_RATE_LIMIT")))return api(false,null,error("RATE_LIMITED","تعداد تلاش‌ها بیش از حد مجاز است.",429),requestId,429); const ch=await env.DB.prepare(`SELECT * FROM otp_challenges WHERE phone=? AND purpose='login' AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1`).bind(phone).first(); if(!ch||ch.expires_at<=nowIso()||Number(ch.attempts)>=Number(ch.max_attempts)){return api(false,null,error("OTP_INVALID","کد واردشده صحیح نیست.",401),requestId,401);} const ok=safeEqual(await hmacSha256(env.SESSION_SECRET||"",otp),ch.otp_hash); if(!ok){await env.DB.prepare(`UPDATE otp_challenges SET attempts=attempts+1 WHERE id=?`).bind(ch.id).run();await audit(env,{userId:ch.user_id||null,eventType:"OTP_FAILED",success:false,requestId,request});return api(false,null,error("OTP_INVALID","کد واردشده صحیح نیست.",401),requestId,401);} await env.DB.prepare(`UPDATE otp_challenges SET consumed_at=? WHERE id=? AND consumed_at IS NULL`).bind(nowIso(),ch.id).run(); const user=await findUserByPhone(env.DB,phone); if(!user||user.status!=="active"){await audit(env,{eventType:"OTP_FAILED",success:false,requestId,request});return api(false,null,error("OTP_INVALID","کد واردشده صحیح نیست.",401),requestId,401);} await clearLoginFailure(env,user.id); await logAttempt(env,{userId:user.id,identifier:phone,method:"sms",success:true,request}); const s=await createSession(env,user.id,request); await audit(env,{userId:user.id,eventType:"OTP_VERIFIED",success:true,requestId,request}); return withHeaders({"Set-Cookie":sessionCookie(s.token,Number(env.SESSION_TTL_SECONDS||CONFIG.SESSION_TTL_SECONDS),env.COOKIE_SAMESITE||"Lax"),"Cache-Control":"no-store"})(api(true,{redirect:env.LOGIN_SUCCESS_REDIRECT||CONFIG.LOGIN_SUCCESS_REDIRECT,expiresAt:s.expiresAt},null,requestId,200)); }
const SMSAdapter={sendOTP:sendSmsPlaceholder};

function jwtParts(token){const p=String(token||"").split(".");if(p.length!==3)throw new Error("invalid_jwt");return {h:JSON.parse(textDecoder.decode(fromB64u(p[0]))),p:JSON.parse(textDecoder.decode(fromB64u(p[1]))),s:fromB64u(p[2]),signed:`${p[0]}.${p[1]}`};}
async function oidcDiscovery(env){ const issuer=env.OIDC_ISSUER||CONFIG.OIDC.ISSUER;if(!issuer)throw new Error("OIDC_ISSUER missing");const base=issuer.replace(/\/$/,"");const r=await fetch(`${base}/.well-known/openid-configuration`);if(!r.ok)throw new Error("oidc_discovery_failed");const d=await r.json();if(d.issuer!==issuer && d.issuer!==base)throw new Error("oidc_issuer_mismatch");return d; }
async function jwks(env,url){ const r=await fetch(url,{headers:{"Accept":"application/json"}});if(!r.ok)throw new Error("jwks_failed");return r.json(); }
async function importJwk(jwk,alg){ if(jwk.kty==="RSA")return crypto.subtle.importKey("jwk",jwk,{name:alg==="PS256"?"RSA-PSS":"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]); if(jwk.kty==="EC")return crypto.subtle.importKey("jwk",jwk,{name:"ECDSA",namedCurve:jwk.crv},false,["verify"]); throw new Error("unsupported_jwk"); }
async function verifyJwt(token,discovery,clientId,nonce){ const {h,p,s,signed}=jwtParts(token); if(!["RS256","PS256","ES256"].includes(h.alg))throw new Error("unsupported_alg");const keys=await jwks(null,discovery.jwks_uri);const jwk=keys.keys.find(k=>(h.kid? k.kid===h.kid:true)&&k.use!=="enc"&&((h.alg.startsWith("RS")&&k.kty==="RSA")||(h.alg==="ES256"&&k.kty==="EC")));if(!jwk)throw new Error("signing_key_not_found");const key=await importJwk(jwk,h.alg);let valid=false;if(h.alg==="ES256")valid=await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},key,s,textEncoder.encode(signed));else valid=await crypto.subtle.verify(h.alg==="PS256"?{name:"RSA-PSS",saltLength:32}:{name:"RSASSA-PKCS1-v1_5"},key,s,textEncoder.encode(signed));if(!valid)throw new Error("invalid_signature");const now=Math.floor(Date.now()/1000);if(p.iss!==discovery.issuer||!Array.isArray(p.aud)&&p.aud!==clientId||Array.isArray(p.aud)&&!p.aud.includes(clientId)||p.exp<=now||(p.nbf&&p.nbf>now+60)||p.nonce!==nonce)throw new Error("invalid_claims");return p; }
async function oidcStart(request,env,requestId){ if(env.OIDC_ENABLED!==true&&env.OIDC_ENABLED!=="true")return api(false,null,error("FEATURE_DISABLED","ورود با OpenID فعال نیست.",404),requestId,404); const d=await oidcDiscovery(env),state=randomToken(32),nonce=randomToken(32),verifier=randomToken(32),challenge=b64u(await crypto.subtle.digest("SHA-256",textEncoder.encode(verifier))),exp=addSeconds(Number(env.OIDC_TX_TTL_SECONDS||CONFIG.OIDC_TX_TTL_SECONDS));const redirect=env.OIDC_REDIRECT_URI||CONFIG.OIDC.REDIRECT_URI;if(!redirect||new URL(redirect).origin!==new URL(request.url).origin)throw new Error("invalid_oidc_redirect");await env.DB.prepare(`INSERT INTO oidc_transactions(id,state_hash,nonce_hash,pkce_verifier_ciphertext,provider,redirect_uri,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)`).bind(uuid(),await sha256(state),await sha256(nonce),await encryptText(env.OIDC_TRANSACTION_SECRET||env.SESSION_SECRET,JSON.stringify({verifier,nonce})),env.OIDC_PROVIDER_NAME||CONFIG.OIDC.PROVIDER_NAME,redirect,nowIso(),exp).run();const u=new URL(d.authorization_endpoint);u.searchParams.set("client_id",env.OIDC_CLIENT_ID||CONFIG.OIDC.CLIENT_ID);u.searchParams.set("redirect_uri",redirect);u.searchParams.set("response_type","code");u.searchParams.set("scope",env.OIDC_SCOPES||CONFIG.OIDC.SCOPES);u.searchParams.set("state",state);u.searchParams.set("nonce",nonce);u.searchParams.set("code_challenge",challenge);u.searchParams.set("code_challenge_method","S256");return Response.redirect(u.toString(),302); }
async function oidcCallback(request,env,requestId){
  const u=new URL(request.url),code=u.searchParams.get("code"),state=u.searchParams.get("state"),err=u.searchParams.get("error");
  if(err||!code||!state)throw new Error("invalid_oidc_callback");
  const tx=await env.DB.prepare(`SELECT * FROM oidc_transactions WHERE state_hash=? AND consumed_at IS NULL AND expires_at>? LIMIT 1`).bind(await sha256(state),nowIso()).first();
  if(!tx)throw new Error("invalid_oidc_state");
  const d=await oidcDiscovery(env),txSecret=env.OIDC_TRANSACTION_SECRET||env.SESSION_SECRET;
  if(!txSecret)throw new Error("missing_oidc_transaction_secret");
  const txPayload=JSON.parse(await decryptText(txSecret,tx.pkce_verifier_ciphertext));
  const verifier=txPayload.verifier,nonce=txPayload.nonce;
  const tokenResp=await fetch(d.token_endpoint,{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded","accept":"application/json"},body:new URLSearchParams({grant_type:"authorization_code",code,redirect_uri:tx.redirect_uri,client_id:env.OIDC_CLIENT_ID||CONFIG.OIDC.CLIENT_ID,client_secret:env.OIDC_CLIENT_SECRET||"",code_verifier:verifier}).toString()});
  if(!tokenResp.ok)throw new Error("oidc_token_exchange_failed");
  const tokens=await tokenResp.json();
  if(!tokens.id_token)throw new Error("missing_id_token");
  const claims=await verifyJwt(tokens.id_token,d,env.OIDC_CLIENT_ID||CONFIG.OIDC.CLIENT_ID,nonce);
  if(!claims.sub)throw new Error("missing_subject");
  const issuer=d.issuer;
  const identity=await env.DB.prepare(`SELECT * FROM oidc_identities WHERE issuer=? AND subject=? LIMIT 1`).bind(issuer,String(claims.sub)).first();
  let user=null;
  if(identity) user=await env.DB.prepare(`SELECT * FROM users WHERE id=? AND status='active' LIMIT 1`).bind(identity.user_id).first();
  if(!user){
    const email=typeof claims.email==="string"?normalizeIdentifier(claims.email):null;
    const emailVerified=claims.email_verified===true || claims.email_verified==="true";
    if(email && emailVerified){ user=await env.DB.prepare(`SELECT * FROM users WHERE lower(email)=? AND status='active' LIMIT 1`).bind(email).first(); }
    if(!user && !(env.OIDC_AUTO_PROVISION===true||env.OIDC_AUTO_PROVISION==="true"))throw new Error("oidc_account_not_linked");
    if(!user){
      const uid=uuid(),now=nowIso();
      try{
        await env.DB.batch([
          env.DB.prepare(`INSERT INTO users(id,email,status,email_verified_at,created_at,updated_at) VALUES(?,?,?,?,?,?)`).bind(uid,email,"active",emailVerified?now:null,now,now),
          env.DB.prepare(`INSERT INTO oidc_identities(id,user_id,provider,issuer,subject,email_at_link,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`).bind(uuid(),uid,env.OIDC_PROVIDER_NAME||CONFIG.OIDC.PROVIDER_NAME,issuer,String(claims.sub),email,now,now)
        ]);
      }catch(e){
        if(email) user=await env.DB.prepare(`SELECT * FROM users WHERE lower(email)=? AND status='active' LIMIT 1`).bind(email).first();
        if(!user)throw e;
      }
      if(!user)user=await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(uid).first();
    }else if(!identity){
      await env.DB.prepare(`INSERT INTO oidc_identities(id,user_id,provider,issuer,subject,email_at_link,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`).bind(uuid(),user.id,env.OIDC_PROVIDER_NAME||CONFIG.OIDC.PROVIDER_NAME,issuer,String(claims.sub),claims.email||null,nowIso(),nowIso()).run();
    }
  }
  if(!user)throw new Error("oidc_user_unavailable");
  const consumed=await env.DB.prepare(`UPDATE oidc_transactions SET consumed_at=? WHERE id=? AND consumed_at IS NULL`).bind(nowIso(),tx.id).run();
  if(!consumed.meta || Number(consumed.meta.changes)!==1)throw new Error("oidc_transaction_replay");
  await clearLoginFailure(env,user.id);
  await logAttempt(env,{userId:user.id,identifier:claims.email||claims.sub,method:"oidc",success:true,request});
  await audit(env,{userId:user.id,eventType:"OIDC_LOGIN",success:true,requestId,request});
  const session=await createSession(env,user.id,request);
  return withHeaders({"Set-Cookie":sessionCookie(session.token,Number(env.SESSION_TTL_SECONDS||CONFIG.SESSION_TTL_SECONDS),env.COOKIE_SAMESITE||"Lax"),"Cache-Control":"no-store"})(Response.redirect(new URL(env.LOGIN_SUCCESS_REDIRECT||CONFIG.LOGIN_SUCCESS_REDIRECT,request.url).toString(),302));
}
async function getRoles(env,userId){const r=await env.DB.prepare(`SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id=r.id WHERE ur.user_id=?`).bind(userId).all();return (r.results||[]).map(x=>x.name);}
async function route(request,env,requestId){ const url=new URL(request.url),p=url.pathname; if(p==="/api/auth/v1/csrf"&&request.method==="GET")return issueCsrf(request,env); if(p==="/api/auth/v1/config"&&request.method==="GET")return api(true,publicConfig(env),null,requestId); if(p==="/api/auth/v1/login/password"&&request.method==="POST")return passwordLogin(request,env,requestId); if(p==="/api/auth/v1/login/sms/request"&&request.method==="POST")return requestSms(request,env,requestId); if(p==="/api/auth/v1/login/sms/verify"&&request.method==="POST")return verifySms(request,env,requestId); if(p==="/api/auth/v1/oidc/start"&&request.method==="GET"){if(!(await rateLimit(env,`oidc-start:${clientIp(request)}`,"OIDC_RATE_LIMIT")))return api(false,null,error("RATE_LIMITED","تعداد درخواست‌ها بیش از حد مجاز است.",429),requestId,429);return oidcStart(request,env,requestId);} if(p==="/api/auth/v1/oidc/callback"&&request.method==="GET"){if(!(await rateLimit(env,`oidc-callback:${clientIp(request)}`,"OIDC_RATE_LIMIT")))return api(false,null,error("RATE_LIMITED","تعداد درخواست‌ها بیش از حد مجاز است.",429),requestId,429);return oidcCallback(request,env,requestId);} if(p==="/api/auth/v1/session"&&request.method==="GET"){const s=await getSession(env,request);return api(true,s?{authenticated:true,user:{id:s.user_id,username:s.username,email:s.email,phone:s.phone},expiresAt:s.expires_at,roles:await getRoles(env,s.user_id)}:{authenticated:false},null,requestId);} if(p==="/api/auth/v1/refresh"&&request.method==="POST"){if(!csrfRequired(request,env))return api(false,null,error("CSRF_FAILED","درخواست نامعتبر است.",403),requestId,403);const old=await getSession(env,request);if(!old)return api(false,null,error("UNAUTHENTICATED","احراز هویت لازم است.",401),requestId,401);await revokeSession(env,request);const s=await createSession(env,old.user_id,request);await audit(env,{userId:old.user_id,eventType:"SESSION_CREATED",success:true,requestId,request});return withHeaders({"Set-Cookie":sessionCookie(s.token,Number(env.SESSION_TTL_SECONDS||CONFIG.SESSION_TTL_SECONDS),env.COOKIE_SAMESITE||"Lax"),"Cache-Control":"no-store"})(api(true,{expiresAt:s.expiresAt},null,requestId));} if(p==="/api/auth/v1/logout"&&request.method==="POST"){if(!csrfRequired(request,env))return api(false,null,error("CSRF_FAILED","درخواست نامعتبر است.",403),requestId,403);const s=await getSession(env,request);await revokeSession(env,request);await audit(env,{userId:s?.user_id||null,eventType:"LOGOUT",success:true,requestId,request});return withSecurity(api(true,{loggedOut:true},null,requestId),{"Set-Cookie":clearSessionCookie(),"Cache-Control":"no-store"});} if(p==="/api/auth/v1/protected/check"&&request.method==="GET"){const s=await getSession(env,request);return s?api(true,{authenticated:true},null,requestId):api(false,null,error("UNAUTHENTICATED","احراز هویت لازم است.",401),requestId,401);} return null; }

export { createPasswordHash };

export default {async fetch(request,env,ctx){const requestId=crypto.randomUUID();try{if(request.method==="OPTIONS"){if(!isAllowedOrigin(request,env))return withSecurity(new Response(null,{status:403}));const origin=requestOrigin(request);return withSecurity(new Response(null,{status:204,headers:{"Access-Control-Allow-Origin":origin||new URL(request.url).origin,"Access-Control-Allow-Credentials":"true","Access-Control-Allow-Headers":"Content-Type, X-CSRF-Token","Access-Control-Allow-Methods":"GET,POST,OPTIONS","Vary":"Origin"}}));}if(!isAllowedOrigin(request,env))return withSecurity(api(false,null,error("ORIGIN_DENIED","درخواست نامعتبر است.",403),requestId,403));const response=await route(request,env,requestId);if(response)return withSecurity(response,{"Cache-Control":response.headers.get("Cache-Control")||"no-store", ...(requestOrigin(request)?{"Access-Control-Allow-Origin":requestOrigin(request),"Access-Control-Allow-Credentials":"true","Vary":"Origin"}: {})});const url=new URL(request.url);if(url.pathname==="/dashboard.html"){const s=await getSession(env,request);if(!s)return Response.redirect(new URL("/login.html",request.url).toString(),302);if(env.ASSETS)return withSecurity(await env.ASSETS.fetch(request));return withSecurity(new Response("Dashboard asset binding is not configured.",{status:503}));}if(env.ASSETS)return withSecurity(await env.ASSETS.fetch(request));return withSecurity(new Response("Not Found",{status:404}));}catch(e){console.error("request_error",requestId,e?.stack||e?.message);try{const path=new URL(request.url).pathname;if(path.includes("/oidc/"))await audit(env,{eventType:"SECURITY_EVENT",success:false,requestId,request});}catch{}return withSecurity(api(false,null,error("INTERNAL_ERROR","خطایی رخ داد. لطفاً دوباره تلاش کنید.",500),requestId,500));}}};
