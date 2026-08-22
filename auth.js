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
  hashPassword,
  verifyPassword
} from './security.js';

// ============================================================
// REGISTER
// ============================================================
export async function handleRegister(request, env) {
  try {
    const body = await request.json();
    const { id, username, email, password, country } = body;

    if (!id || !username || !email || !password) {
      return Response.json({
        success: false,
        error: 'Missing required fields'
      }, { status: 400, headers: corsHeaders });
    }

    // Validate username
    if (!isValidUsername(username)) {
      return Response.json({
        success: false,
        error: `Username must be 2-${USERNAME_MAX_LENGTH} characters and contain only letters, numbers, and underscores`
      }, { status: 400, headers: corsHeaders });
    }

    // Validate email
    if (!isValidEmail(email)) {
      return Response.json({
        success: false,
        error: 'Please provide a valid email address'
      }, { status: 400, headers: corsHeaders });
    }

    // Validate password
    if (!isValidPassword(password)) {
      return Response.json({
        success: false,
        error: 'Password must be at least 6 characters'
      }, { status: 400, headers: corsHeaders });
    }

    // Check duplicates (unique username AND unique email)
    const existingUsername = await query(env, 'SELECT id FROM users WHERE username = ?', [username]);
    if (existingUsername.results.length > 0) {
      return Response.json({
        success: false,
        error: 'Username already taken'
      }, { status: 400, headers: corsHeaders });
    }

    const existingEmail = await query(env, 'SELECT id FROM users WHERE email = ?', [email]);
    if (existingEmail.results.length > 0) {
      return Response.json({
        success: false,
        error: 'Email already registered'
      }, { status: 400, headers: corsHeaders });
    }

    const hashedPassword = await hashPassword(password);

    await run(env,
      `INSERT INTO users (id, username, email, password, country, role, privacy, created_at) 
       VALUES (?, ?, ?, ?, ?, 'user', 'public', ?)`,
      [id, username, email, hashedPassword, country || '', new Date().toISOString()]
    );

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
    const { username, password } = body;

    if (!username || !password) {
      return Response.json({
        success: false,
        error: 'Missing credentials'
      }, { status: 400, headers: corsHeaders });
    }

    // Find user by username, falling back to email. Password is now
    // salted (PBKDF2), so it can no longer be matched with a plain SQL
    // equality on a precomputed hash - fetch the stored hash and verify
    // it in application code instead.
    let user = await query(env,
      'SELECT id, username, email, country, role, password, is_banned, ban_reason FROM users WHERE username = ?',
      [username]
    );

    if (user.results.length === 0) {
      user = await query(env,
        'SELECT id, username, email, country, role, password, is_banned, ban_reason FROM users WHERE email = ?',
        [username]
      );
    }

    if (user.results.length === 0) {
      return Response.json({
        success: false,
        error: 'Invalid credentials'
      }, { status: 401, headers: corsHeaders });
    }

    const u = user.results[0];
    const { valid, needsUpgrade } = await verifyPassword(password, u.password);

    if (!valid) {
      return Response.json({
        success: false,
        error: 'Invalid credentials'
      }, { status: 401, headers: corsHeaders });
    }

    // A banned account cannot log in at all - reject before issuing a token.
    if (u.is_banned) {
      return Response.json({
        success: false,
        error: u.ban_reason
          ? `Your account has been banned. Reason: ${u.ban_reason}`
          : 'Your account has been banned.',
        banned: true
      }, { status: 403, headers: corsHeaders });
    }

    // Transparently upgrade legacy unsalted SHA-256 hashes to salted
    // PBKDF2 now that we have the plaintext password in hand.
    if (needsUpgrade) {
      const upgraded = await hashPassword(password);
      await run(env, 'UPDATE users SET password = ? WHERE id = ?', [upgraded, u.id]);
    }

    delete u.password;
    delete u.is_banned;
    delete u.ban_reason;
    const token = await signJWT({ sub: u.id, username: u.username }, env);

    return Response.json({
      success: true,
      data: { user: u, token }
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
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

    const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD

    const existing = await query(env,
      `SELECT count FROM password_resets WHERE email = ? AND date = ?`,
      [email, today]
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
        [email, today]
      );
    } else {
      await run(env,
        `INSERT INTO password_resets (email, date, count) VALUES (?, ?, 1)`,
        [email, today]
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
    const { email, newPassword } = body;

    if (!email || !isValidEmail(email) || !isValidPassword(newPassword)) {
      return Response.json({
        success: false,
        error: 'Invalid request'
      }, { status: 400, headers: corsHeaders });
    }

    const today = new Date().toISOString().split('T')[0];
    const resetRequest = await query(env,
      'SELECT count FROM password_resets WHERE email = ? AND date = ?',
      [email, today]
    );

    if (resetRequest.results.length === 0 || resetRequest.results[0].count < 1) {
      return Response.json({
        success: false,
        error: 'No pending reset request found for this email'
      }, { status: 400, headers: corsHeaders });
    }

    const user = await query(env, 'SELECT id FROM users WHERE email = ?', [email]);
    if (user.results.length === 0) {
      return Response.json({ success: false, error: 'Account not found' }, { status: 404, headers: corsHeaders });
    }

    const newHashed = await hashPassword(newPassword);
    await run(env,
      'UPDATE users SET password = ?, updated_at = ? WHERE email = ?',
      [newHashed, new Date().toISOString(), email]
    );

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
    try {
      const firebasePayload = await verifyFirebaseIdToken(idToken);
      if (firebasePayload.sub !== id) {
        throw new Error('Token does not match requested user');
      }
    } catch (verifyErr) {
      return Response.json({
        success: false,
        error: 'Could not verify your session. Please log in again.'
      }, { status: 401, headers: corsHeaders });
    }

    const result = await query(env, 'SELECT id, username, email, country, role, is_banned, ban_reason FROM users WHERE id = ?', [id]);
    if (result.results.length === 0) {
      return Response.json({
        success: false,
        error: 'User not found'
      }, { status: 404, headers: corsHeaders });
    }

    const u = result.results[0];

    // A banned account cannot receive a session token - this is what
    // actually gates "login" for the Firebase-based frontend flow.
    if (u.is_banned) {
      return Response.json({
        success: false,
        error: u.ban_reason
          ? `Your account has been banned. Reason: ${u.ban_reason}`
          : 'Your account has been banned.',
        banned: true
      }, { status: 403, headers: corsHeaders });
    }

    delete u.is_banned;
    delete u.ban_reason;
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
        error: 'New password must be at least 6 characters'
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

    const { valid } = await verifyPassword(oldPassword, userResult.results[0].password);
    if (!valid) {
      return Response.json({
        success: false,
        error: 'Current password is incorrect'
      }, { status: 401, headers: corsHeaders });
    }

    const newHashed = await hashPassword(newPassword);
    await run(env,
      'UPDATE users SET password = ?, updated_at = ? WHERE id = ?',
      [newHashed, new Date().toISOString(), userId]
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
