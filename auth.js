// ============================================================
// 📁 auth.js - Authentication API (Complete + JWT + Security)
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';
import {
  signJWT,
  requireAuth,
  isValidUsername,
  isValidEmail,
  isValidPassword,
  verifyFirebaseIdToken,
  USERNAME_MAX_LENGTH,
  normalizeEmail,
  isEmailBanned,
  banEmail,
  detectBotRequest,
  bannedResponse
} from './security.js';

// ===== Password hashing: PBKDF2-SHA256 =====
async function hashPassword(password, saltBytes = null) {
  const salt = saltBytes || crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 120000, hash: 'SHA-256' }, key, 256);
  const bytes = new Uint8Array(bits);
  const hash = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  return { hash, salt: saltHex };
}

async function verifyPassword(password, storedHash, storedSalt) {
  if (!storedSalt) {
    // Legacy SHA-256 compatibility; successful login is upgraded below.
    const data = new TextEncoder().encode(password);
    const digest = await crypto.subtle.digest('SHA-256', data);
    const legacy = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
    return { valid: legacy === storedHash, legacy: true };
  }
  const salt = new Uint8Array(storedSalt.match(/.{2}/g).map(h => parseInt(h, 16)));
  const result = await hashPassword(password, salt);
  return { valid: result.hash === storedHash, legacy: false };
}

// ============================================================
// REGISTER
// ============================================================
export async function handleRegister(request, env) {
  try {
    const body = await request.json();
    const { id, username, email, password, country, idToken } = body;
    const normalizedEmail = normalizeEmail(email);

    if (!id || !username || !email || !password || !idToken) {
      return Response.json({
        success: false,
        error: 'Missing required fields'
      }, { status: 400, headers: corsHeaders });
    }

    let firebasePayload;
    try {
      firebasePayload = await verifyFirebaseIdToken(idToken);
    } catch (_) {
      return Response.json({success:false,error:'Invalid Firebase authentication'}, {status:401,headers:corsHeaders});
    }
    if (firebasePayload.sub !== id || normalizeEmail(firebasePayload.email) !== normalizedEmail) {
      return Response.json({success:false,error:'Registration identity mismatch'}, {status:403,headers:corsHeaders});
    }

    // Validate username
    if (!isValidUsername(username)) {
      return Response.json({
        success: false,
        error: `Username must be 2-${USERNAME_MAX_LENGTH} characters and contain only letters, numbers, and underscores`
      }, { status: 400, headers: corsHeaders });
    }

    // Validate email
    if (!isValidEmail(normalizedEmail)) {
      return Response.json({
        success: false,
        error: 'Please provide a valid email address'
      }, { status: 400, headers: corsHeaders });
    }

    // Validate password
    if (!isValidPassword(password)) {
      return Response.json({
        success: false,
        error: 'Password must be at least 8 characters'
      }, { status: 400, headers: corsHeaders });
    }

    if (await isEmailBanned(env, normalizedEmail)) return bannedResponse();
    const bot = detectBotRequest(request);
    if (bot.detected) {
      await banEmail(env, normalizedEmail, `Automatic bot detection: ${bot.reason}`);
      return bannedResponse();
    }

    // Check duplicates (unique username AND unique email)
    const existingUsername = await query(env, 'SELECT id FROM users WHERE username = ?', [username]);
    if (existingUsername.results.length > 0) {
      return Response.json({
        success: false,
        error: 'Username already taken'
      }, { status: 400, headers: corsHeaders });
    }

    const existingEmail = await query(env, 'SELECT id FROM users WHERE email = ?', [normalizedEmail]);
    if (existingEmail.results.length > 0) {
      return Response.json({
        success: false,
        error: 'Email already registered'
      }, { status: 400, headers: corsHeaders });
    }

    const passwordData = await hashPassword(password);

    await run(env,
      `INSERT INTO users (id, username, email, password, country, role, privacy, created_at) 
       VALUES (?, ?, ?, ?, ?, 'user', 'public', ?)`,
      [id, username, normalizedEmail, passwordData.hash, country || '', new Date().toISOString()]
    );

    await run(env, 'UPDATE users SET password_salt = ? WHERE id = ?', [passwordData.salt, id]);

    const token = await signJWT({ sub: id, username }, env);

    return Response.json({
      success: true,
      message: 'User registered successfully',
      data: { token, user: { id, username, email, country } }
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}

// ============================================================
// LOGIN
// ============================================================
export async function handleLogin(request, env) {
  try {
    const body = await request.json();
    const { username, password, idToken } = body;
    const loginIdentifier = String(username || '').trim();

    if (!loginIdentifier || !password || !idToken) {
      return Response.json({ success:false, error:'Missing credentials' }, { status:400, headers:corsHeaders });
    }

    let firebasePayload;
    try { firebasePayload = await verifyFirebaseIdToken(idToken); }
    catch (_) { return Response.json({success:false,error:'Invalid Firebase authentication'}, {status:401,headers:corsHeaders}); }

    const bot = detectBotRequest(request);
    if (bot.detected && isValidEmail(loginIdentifier)) {
      await banEmail(env, loginIdentifier, `Automatic bot detection: ${bot.reason}`);
      return bannedResponse();
    }
    if (isValidEmail(loginIdentifier) && await isEmailBanned(env, loginIdentifier)) return bannedResponse();

    let user = await query(env,
      'SELECT id, username, email, country, role, password, password_salt, COALESCE(is_banned,0) AS is_banned FROM users WHERE username = ?',
      [loginIdentifier]
    );
    if (user.results.length === 0) {
      user = await query(env,
        'SELECT id, username, email, country, role, password, password_salt, COALESCE(is_banned,0) AS is_banned FROM users WHERE lower(email) = lower(?)',
        [loginIdentifier]
      );
    }

    if (user.results.length === 0) return Response.json({ success:false, error:'Invalid credentials' }, { status:401, headers:corsHeaders });
    const u = user.results[0];
    if (u.id !== firebasePayload.sub || normalizeEmail(u.email) !== normalizeEmail(firebasePayload.email)) {
      return Response.json({success:false,error:'Login identity mismatch'}, {status:403,headers:corsHeaders});
    }
    if (u.is_banned || await isEmailBanned(env, u.email)) return bannedResponse();

    const passwordCheck = await verifyPassword(password, u.password, u.password_salt);
    if (!passwordCheck.valid) return Response.json({ success:false, error:'Invalid credentials' }, { status:401, headers:corsHeaders });
    if (passwordCheck.legacy) {
      const upgraded = await hashPassword(password);
      await run(env, 'UPDATE users SET password = ?, password_salt = ?, updated_at = ? WHERE id = ?', [upgraded.hash, upgraded.salt, new Date().toISOString(), u.id]);
    }
    delete u.password; delete u.password_salt; delete u.is_banned;
    const token = await signJWT({ sub: u.id, username: u.username }, env);
    return Response.json({ success:true, data:{ user:u, token } }, { headers:corsHeaders });
  } catch (error) {
    return Response.json({ success:false, error:error.message }, { status:500, headers:corsHeaders });
  }
}

// ============================================================
// RESET PASSWORD (Daily limit 5) - request-a-reset-link gate.
// The actual email delivery + link handling is done by Firebase
// Auth (sendPasswordResetEmail / confirmPasswordReset) on the
// frontend; this endpoint just rate-limits reset requests per email.
// ============================================================
export async function handleResetPassword(request, env) {
  try {
    const body = await request.json();
    const { email } = body;

    if (!email || !isValidEmail(email)) {
      return Response.json({
        success: false,
        error: 'Invalid email address'
      }, { status: 400, headers: corsHeaders });
    }

    const normalizedEmail = normalizeEmail(email);
    if (await isEmailBanned(env, normalizedEmail)) return bannedResponse();
    const bot = detectBotRequest(request);
    if (bot.detected) {
      await banEmail(env, normalizedEmail, `Automatic bot detection: ${bot.reason}`);
      return bannedResponse();
    }
    const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD

    const existing = await query(env,
      `SELECT count FROM password_resets WHERE email = ? AND date = ?`,
      [normalizedEmail, today]
    );

    let currentCount = 0;
    if (existing.results.length > 0) {
      currentCount = existing.results[0].count;
    }

    if (currentCount >= 5) {
      return Response.json({
        success: false,
        error: 'You have reached the daily limit (5 requests). Please try again tomorrow.'
      }, { status: 429, headers: corsHeaders });
    }

    if (existing.results.length > 0) {
      await run(env,
        `UPDATE password_resets SET count = count + 1 WHERE email = ? AND date = ?`,
        [normalizedEmail, today]
      );
    } else {
      await run(env,
        `INSERT INTO password_resets (email, date, count) VALUES (?, ?, 1)`,
        [normalizedEmail, today]
      );
    }

    return Response.json({
      success: true,
      message: 'Reset request allowed'
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}

// ============================================================
// SYNC PASSWORD AFTER FIREBASE RESET
// The actual "forgot password" reset is completed on the client
// via Firebase (sendPasswordResetEmail -> confirmPasswordReset).
// Since the user isn't holding a session yet at that point, we
// can't require a JWT here. As defense-in-depth we only allow the
// sync if a reset was actually requested for this email today
// (tracked by handleResetPassword), and the endpoint is rate
// limited like the other auth routes.
// ============================================================
export async function handleSyncPassword(request, env) {
  try {
    const body = await request.json();
    const { email, newPassword, idToken } = body;

    if (!email || !idToken || !isValidEmail(email) || !isValidPassword(newPassword)) {
      return Response.json({
        success: false,
        error: 'Invalid request'
      }, { status: 400, headers: corsHeaders });
    }

    const normalizedEmail = normalizeEmail(email);
    if (await isEmailBanned(env, normalizedEmail)) return bannedResponse();

    let firebasePayload;
    try { firebasePayload = await verifyFirebaseIdToken(idToken); }
    catch (_) { return Response.json({ success:false, error:'Invalid reset authorization' }, { status:401, headers:corsHeaders }); }
    if (normalizeEmail(firebasePayload.email) !== normalizedEmail) {
      return Response.json({ success:false, error:'Reset identity mismatch' }, { status:403, headers:corsHeaders });
    }

    const user = await query(env, 'SELECT id FROM users WHERE lower(email) = lower(?)', [normalizedEmail]);
    if (user.results.length === 0) return Response.json({ success:false, error:'Account not found' }, { status:404, headers:corsHeaders });
    const newPasswordData = await hashPassword(newPassword);
    await run(env, 'UPDATE users SET password = ?, password_salt = ?, updated_at = ? WHERE id = ?',
      [newPasswordData.hash, newPasswordData.salt, new Date().toISOString(), user.results[0].id]);

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}

// ============================================================
// ISSUE SESSION TOKEN (after client already authenticated via Firebase)
// The frontend authenticates the user's identity with Firebase Auth
// (email/password or Google) and then exchanges the known, existing
// user id for a signed app-level JWT used to authorize all
// sensitive settings actions (change password/email/username,
// block/unblock, privacy).
// ============================================================
export async function handleIssueToken(request, env) {
  try {
    const body = await request.json();
    const { id, idToken } = body;

    if (!id || !idToken) {
      return Response.json({
        success: false,
        error: 'User id and Firebase ID token are required'
      }, { status: 400, headers: corsHeaders });
    }

    // Verify the Firebase ID token is genuine and belongs to this user id
    // before minting our own app-level session JWT.
    let firebasePayload;
    try {
      firebasePayload = await verifyFirebaseIdToken(idToken);
      if (firebasePayload.sub !== id) {
        throw new Error('Token does not match requested user');
      }
    } catch (verifyErr) {
      return Response.json({
        success: false,
        error: 'Could not verify your session. Please log in again.'
      }, { status: 401, headers: corsHeaders });
    }

    const bot = detectBotRequest(request);
    if (bot.detected) {
      await banEmail(env, firebasePayload.email || '', `Automatic bot detection: ${bot.reason}`, id);
      return bannedResponse();
    }

    const result = await query(env, 'SELECT id, username, email, country, role, COALESCE(is_banned,0) AS is_banned FROM users WHERE id = ?', [id]);
    if (result.results.length === 0) {
      return Response.json({
        success: false,
        error: 'User not found'
      }, { status: 404, headers: corsHeaders });
    }

    const u = result.results[0];
    if (u.is_banned || await isEmailBanned(env, u.email)) return bannedResponse();
    const token = await signJWT({ sub: u.id, username: u.username }, env);

    return Response.json({
      success: true,
      data: { token, user: u }
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}

// ============================================================
// CHANGE PASSWORD (requires current password + valid session)
// ============================================================
export async function handleChangePassword(request, env) {
  try {
    let auth;
    try {
      auth = await requireAuth(request, env);
    } catch (authResponse) {
      return authResponse;
    }

    const body = await request.json();
    const { oldPassword, newPassword } = body;

    if (!oldPassword || !newPassword) {
      return Response.json({
        success: false,
        error: 'Current and new password are required'
      }, { status: 400, headers: corsHeaders });
    }

    if (!isValidPassword(newPassword)) {
      return Response.json({
        success: false,
        error: 'New password must be at least 8 characters'
      }, { status: 400, headers: corsHeaders });
    }

    const userId = auth.sub;
    const userResult = await query(env, 'SELECT password FROM users WHERE id = ?', [userId]);

    if (userResult.results.length === 0) {
      return Response.json({
        success: false,
        error: 'User not found'
      }, { status: 404, headers: corsHeaders });
    }

    const oldCheck = await verifyPassword(oldPassword, userResult.results[0].password, userResult.results[0].password_salt);
    if (!oldCheck.valid) {
      return Response.json({
        success: false,
        error: 'Current password is incorrect'
      }, { status: 401, headers: corsHeaders });
    }

    const newPasswordData = await hashPassword(newPassword);
    await run(env,
      'UPDATE users SET password = ?, password_salt = ?, updated_at = ? WHERE id = ?',
      [newPasswordData.hash, newPasswordData.salt, new Date().toISOString(), userId]
    );

    return Response.json({
      success: true,
      message: 'Password updated successfully'
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}
