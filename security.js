// ============================================================
// 📁 security.js - Security Utilities (JWT Auth, Rate Limit,
//                  Input Validation, User-Agent Check)
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';

// ============================================================
// ===== JWT AUTHENTICATION (HS256, Web Crypto based) =====
// ============================================================

// JWT_SECRET is mandatory; there is no insecure default/fallback.
const MIN_SECRET_LENGTH = 64;

function getSecret(env) {
  const secret = String(env?.JWT_SECRET || '');
  if (secret.length < MIN_SECRET_LENGTH) {
    throw new Error(`JWT_SECRET must be at least ${MIN_SECRET_LENGTH} characters and must be configured as a Worker secret`);
  }
  return secret;
}

function base64urlEncode(bytes) {
  let binary = '';
  const arr = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes;
  for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecodeToString(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

function encodeJSON(obj) {
  return base64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function decodeJSON(str) {
  return JSON.parse(base64urlDecodeToString(str));
}

async function hmacSign(data, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return base64urlEncode(new Uint8Array(sig));
}

// ===== Create a signed JWT for a user =====
export async function signJWT(payload, env, expiresInSeconds = TOKEN_TTL_SECONDS) {
  const secret = getSecret(env);
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = { ...payload, iat: now, exp: now + expiresInSeconds };

  const headerEnc = encodeJSON(header);
  const payloadEnc = encodeJSON(fullPayload);
  const signature = await hmacSign(`${headerEnc}.${payloadEnc}`, secret);

  return `${headerEnc}.${payloadEnc}.${signature}`;
}

// ===== Verify a JWT, returns payload or throws Error =====
export async function verifyJWT(token, env) {
  if (!token || typeof token !== 'string' || token.split('.').length !== 3) {
    throw new Error('Malformed token');
  }
  const [headerEnc, payloadEnc, signature] = token.split('.');
  const header = decodeJSON(headerEnc);
  if (header.alg !== 'HS256' || header.typ !== 'JWT') throw new Error('Unsupported JWT algorithm');
  const secret = getSecret(env);
  const expectedSig = await hmacSign(`${headerEnc}.${payloadEnc}`, secret);

  if (!constantTimeEqual(expectedSig, signature)) {
    throw new Error('Invalid token signature');
  }

  const payload = decodeJSON(payloadEnc);
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now > payload.exp) {
    throw new Error('Token expired');
  }
  return payload;
}

// ===== Extract Bearer token from Authorization header =====
export function getBearerToken(request) {
  const header = request.headers.get('Authorization') || request.headers.get('authorization');
  if (!header || !header.startsWith('Bearer ')) return null;
  return header.slice(7).trim();
}

// ===== Require a valid JWT; returns { sub, username } payload =====
// Throws a Response (401) on failure - callers should catch and return it.
export async function requireAuth(request, env) {
  const token = getBearerToken(request);
  if (!token) {
    throw Response.json(
      { success: false, error: 'Authentication required' },
      { status: 401, headers: corsHeaders }
    );
  }
  try {
    const payload = await verifyJWT(token, env);
    if (!payload.sub) throw new Error('Invalid token payload');

    // Every authenticated request re-checks account status so a ban takes
    // effect immediately even if the user already has a valid JWT.
    const account = await querySecurityUser(env, payload.sub);
    if (!account) throw new Error('Account not found');
    if (account.is_banned) throw new Error('Account banned');
    if (await isEmailBanned(env, account.email)) throw new Error('Email banned');

    // A strong server-side automation signal automatically bans the account.
    // This is intentionally limited to clear automation indicators; normal
    // browser UA strings are not treated as bots.
    const bot = detectBotRequest(request);
    if (bot.detected) {
      await banEmail(env, account.email, `Automatic bot detection: ${bot.reason}`, account.id);
      throw new Error('Bot detected');
    }

    return { ...payload, email: account.email, role: account.role };
  } catch (err) {
    throw Response.json(
      { success: false, error: 'Invalid or expired session. Please log in again.' },
      { status: 401, headers: corsHeaders }
    );
  }
}

// ===== Require auth AND that the token owner matches :userId in the route =====
export async function requireSelf(request, env, userId) {
  const payload = await requireAuth(request, env);
  if (payload.sub !== userId) {
    throw Response.json(
      { success: false, error: 'You are not allowed to modify this account' },
      { status: 403, headers: corsHeaders }
    );
  }
  return payload;
}

// ============================================================
// ===== FIREBASE ID TOKEN VERIFICATION (RS256 via Google JWKS) =====
// Used only by the /auth/token exchange endpoint so that our
// app-level JWT is issued strictly to a user whose identity was
// just verified by Firebase Auth - not merely a client-supplied id.
// ============================================================

const FIREBASE_PROJECT_ID = 'socialock-c91dd';
const FIREBASE_JWK_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

let jwkCache = { keys: null, fetchedAt: 0 };

async function getFirebaseJWKs() {
  const now = Date.now();
  if (jwkCache.keys && now - jwkCache.fetchedAt < 60 * 60 * 1000) {
    return jwkCache.keys;
  }
  const res = await fetch(FIREBASE_JWK_URL);
  if (!res.ok) throw new Error('Unable to fetch Firebase signing keys');
  const data = await res.json();
  jwkCache = { keys: data.keys, fetchedAt: now };
  return data.keys;
}

function base64urlToUint8Array(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// Verifies a Firebase Auth ID token (RS256) and returns its payload.
export async function verifyFirebaseIdToken(idToken) {
  if (!idToken || typeof idToken !== 'string' || idToken.split('.').length !== 3) {
    throw new Error('Malformed Firebase ID token');
  }
  const [headerEnc, payloadEnc, sigEnc] = idToken.split('.');
  const header = decodeJSON(headerEnc);
  const payload = decodeJSON(payloadEnc);

  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || now > payload.exp) throw new Error('Firebase token expired');
  if (payload.aud !== FIREBASE_PROJECT_ID) throw new Error('Firebase token audience mismatch');
  if (payload.iss !== `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`) throw new Error('Firebase token issuer mismatch');
  if (!payload.sub) throw new Error('Firebase token missing subject');

  const keys = await getFirebaseJWKs();
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error('Unknown Firebase signing key');

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    publicKey,
    base64urlToUint8Array(sigEnc),
    new TextEncoder().encode(`${headerEnc}.${payloadEnc}`)
  );

  if (!valid) throw new Error('Invalid Firebase token signature');
  return payload; // payload.sub === Firebase UID
}

// ============================================================
// ===== RATE LIMITING (in-memory sliding window per isolate) =====
// ============================================================

const rateBuckets = new Map();

// Periodically trim old buckets so the map doesn't grow forever
function cleanupBuckets(now) {
  if (rateBuckets.size < 5000) return;
  for (const [key, bucket] of rateBuckets) {
    if (now - bucket.start > 10 * 60 * 1000) rateBuckets.delete(key);
  }
}

function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For') ||
    'unknown';
}

/**
 * Returns true if the request is within the allowed rate, false if it should be blocked.
 * @param {Request} request
 * @param {string} bucketName  e.g. 'auth', 'global', 'block'
 * @param {number} limit       max requests allowed in the window
 * @param {number} windowMs    window size in ms
 */
export function checkRateLimit(request, bucketName, limit = 60, windowMs = 60000) {
  const now = Date.now();
  cleanupBuckets(now);
  const key = `${bucketName}:${clientIp(request)}`;
  let bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.start > windowMs) {
    bucket = { start: now, count: 0 };
  }
  bucket.count++;
  rateBuckets.set(key, bucket);
  return bucket.count <= limit;
}

export function rateLimitResponse(retryAfterSec = 60) {
  return Response.json(
    { success: false, error: 'Too many requests. Please slow down and try again shortly.' },
    { status: 429, headers: { ...corsHeaders, 'Retry-After': String(retryAfterSec) } }
  );
}

// ============================================================
// ===== USER-AGENT CHECK =====
// ============================================================

const BLOCKED_UA_PATTERNS = [
  /^$/i,
  /curl\//i,
  /python-requests/i,
  /^wget/i,
  /scrapy/i,
  /^java\//i,
  /libwww-perl/i,
  /go-http-client/i,
  /^okhttp/i
];

// Returns true if the request's User-Agent looks legitimate (a browser/app)
export function isLegitimateUserAgent(request) {
  const ua = request.headers.get('User-Agent') || '';
  if (!ua || ua.trim().length === 0) return false;
  return !BLOCKED_UA_PATTERNS.some((re) => re.test(ua));
}

export function userAgentRejectResponse() {
  return Response.json(
    { success: false, error: 'Request blocked: invalid or missing client identification.' },
    { status: 403, headers: corsHeaders }
  );
}

// ============================================================
// ===== INPUT VALIDATION HELPERS =====
// ============================================================

export const USERNAME_MAX_LENGTH = 20;

export function isValidUsername(username) {
  return typeof username === 'string' &&
    username.length >= 2 &&
    username.length <= USERNAME_MAX_LENGTH &&
    /^[A-Za-z0-9_]+$/.test(username);
}

export function isValidEmail(email) {
  return typeof email === 'string' &&
    email.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 8 && password.length <= 128;
}

// Basic sanitizer: trims, strips control chars, enforces max length.
// Does not attempt to render HTML-safe output - callers must still
// escape on output (frontend already uses escapeHtml for this).
export function sanitizeText(input, maxLength = 5000) {
  if (typeof input !== 'string') return '';
  // eslint-disable-next-line no-control-regex
  const stripped = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
  return stripped.trim().slice(0, maxLength);
}

export function isValidPrivacy(value) {
  return value === 'public' || value === 'followers';
}


// ============================================================
// ACCOUNT BAN / BOT DETECTION
// ============================================================
export function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

export async function querySecurityUser(env, userId) {
  const result = await query(env,
    'SELECT id, email, role, COALESCE(is_banned, 0) AS is_banned FROM users WHERE id = ?',
    [userId]
  );
  return result.results[0] || null;
}

export async function isEmailBanned(env, email) {
  const normalized = normalizeEmail(email);
  if (!normalized) return false;
  const result = await query(env,
    'SELECT id FROM banned_emails WHERE email = ? AND active = 1 LIMIT 1',
    [normalized]
  );
  return result.results.length > 0;
}

export async function banEmail(env, email, reason = 'Policy violation', userId = null) {
  const normalized = normalizeEmail(email);
  if (!normalized) return;
  const now = new Date().toISOString();
  await run(env,
    `INSERT INTO banned_emails (email, reason, source, active, created_at, updated_at)
     VALUES (?, ?, ?, 1, ?, ?)
     ON CONFLICT(email) DO UPDATE SET
       reason = excluded.reason,
       source = excluded.source,
       active = 1,
       updated_at = excluded.updated_at`,
    [normalized, reason, userId ? 'automatic' : 'manual', now, now]
  );
  if (userId) {
    await run(env,
      `UPDATE users SET is_banned = 1, ban_reason = ?, banned_at = ?, updated_at = ? WHERE id = ?`,
      [reason, now, now, userId]
    );
  } else {
    await run(env,
      `UPDATE users SET is_banned = 1, ban_reason = ?, banned_at = ?, updated_at = ? WHERE lower(email) = ?`,
      [reason, now, now, normalized]
    );
  }
}


const CLEAR_BOT_UA_PATTERNS = [
  /curl\//i, /python-requests/i, /python-urllib/i, /wget\//i,
  /scrapy/i, /libwww-perl/i, /go-http-client/i, /okhttp/i,
  /aiohttp/i, /httpclient/i, /headlesschrome/i, /phantomjs/i,
  /selenium/i, /playwright/i, /puppeteer/i
];

export function detectBotRequest(request) {
  const ua = request.headers.get('User-Agent') || '';
  const automationHeader = request.headers.get('X-Client-Automation') === '1';
  const obviousUA = !ua.trim() || CLEAR_BOT_UA_PATTERNS.some(re => re.test(ua));
  return { detected: automationHeader || obviousUA, reason: automationHeader ? 'Browser automation detected' : 'Automated client detected' };
}

export async function autoBanIfBot(request, env, userId = null, email = null) {
  const detection = detectBotRequest(request);
  if (!detection.detected) return false;
  if (email) await banEmail(env, email, `Automatic bot detection: ${detection.reason}`, userId);
  else if (userId) {
    const user = await querySecurityUser(env, userId);
    if (user?.email) await banEmail(env, user.email, `Automatic bot detection: ${detection.reason}`, userId);
  }
  return true;
}

export function bannedResponse() {
  return Response.json(
    { success: false, error: 'This account or email address is banned.' },
    { status: 403, headers: corsHeaders }
  );
}
