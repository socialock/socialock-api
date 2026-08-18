// ============================================================
// 📁 security.js - Security Utilities (JWT Auth, Rate Limit,
//                  Input Validation, User-Agent Check)
// ============================================================

import { corsHeaders } from './cors.js';

// ============================================================
// ===== JWT AUTHENTICATION (HS256, Web Crypto based) =====
// ============================================================

// 64+ character fallback secret (dev/local only). In production this MUST be
// overridden with a strong, random 64+ character secret, e.g. generate one
// with `openssl rand -hex 32` (64 hex chars) and set it via:
//   wrangler secret put JWT_SECRET
const DEFAULT_DEV_SECRET = 'socialock-dev-secret-CHANGE-ME-in-wrangler-secret-please-use-a-64plus-char-random-value-before-deploying-to-production';
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days
const MIN_SECRET_LENGTH = 64;

function getSecret(env) {
  // In production set this with: wrangler secret put JWT_SECRET
  const secret = (env && env.JWT_SECRET) ? env.JWT_SECRET : DEFAULT_DEV_SECRET;
  if (secret.length < MIN_SECRET_LENGTH) {
    // Pad deterministically rather than reject outright, so a short custom
    // secret someone forgets to rotate still results in a >=64 char key
    // being used for HMAC signing (defense in depth, not a substitute for
    // setting a real 64+ char JWT_SECRET).
    console.error(`JWT_SECRET is shorter than ${MIN_SECRET_LENGTH} characters. Set a longer secret with: wrangler secret put JWT_SECRET`);
    return secret.padEnd(MIN_SECRET_LENGTH, ':socialock-secret-padding:');
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

function decodeJSON(str) {
  return JSON.parse(base64urlDecodeToString(str));
}

// Constant-time string comparison to avoid leaking signature bytes
// via response-timing side channels.
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
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
  const secret = getSecret(env);
  const expectedSig = await hmacSign(`${headerEnc}.${payloadEnc}`, secret);

  if (!timingSafeEqual(expectedSig, signature)) {
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
    return payload;
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
  return typeof password === 'string' && password.length >= 6 && password.length <= 128;
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
// ===== PASSWORD HASHING (PBKDF2-HMAC-SHA256, salted) =====
// ------------------------------------------------------------
// Previously passwords were hashed with a single unsalted
// SHA-256 pass - fast enough to brute-force at billions of
// guesses/sec on a GPU, and identical passwords produced
// identical hashes (rainbow-table friendly). This replaces it
// with per-user-salted PBKDF2 at 100,000 iterations, stored in
// the SAME `password` TEXT column as:
//   pbkdf2$<iterations>$<base64url salt>$<base64url hash>
// verifyPassword() also still recognizes the OLD bare-hex-SHA256
// format so existing accounts keep working, and transparently
// reports whether the record should be upgraded on next login.
// ============================================================

const PBKDF2_ITERATIONS = 100000;

function isLegacySha256Hex(stored) {
  return typeof stored === 'string' && /^[0-9a-f]{64}$/i.test(stored);
}

async function legacySha256Hex(password) {
  const data = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return `pbkdf2$${PBKDF2_ITERATIONS}$${base64urlEncode(salt)}$${base64urlEncode(bits)}`;
}

// Returns { valid: boolean, needsUpgrade: boolean }
export async function verifyPassword(password, stored) {
  if (!stored) return { valid: false, needsUpgrade: false };

  if (isLegacySha256Hex(stored)) {
    const computed = await legacySha256Hex(password);
    return { valid: timingSafeEqual(computed, stored), needsUpgrade: true };
  }

  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') {
    return { valid: false, needsUpgrade: false };
  }
  const [, iterStr, saltB64, hashB64] = parts;
  const iterations = parseInt(iterStr, 10);
  const salt = base64urlToUint8Array(saltB64);

  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  const computedB64 = base64urlEncode(bits);
  return { valid: timingSafeEqual(computedB64, hashB64), needsUpgrade: false };
}
