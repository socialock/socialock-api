// ============================================================
// 📁 users.js - Users API (Complete)
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';
import {
  requireSelf,
  isValidUsername,
  isValidEmail,
  isValidPassword,
  isValidPrivacy,
  sanitizeText,
  USERNAME_MAX_LENGTH
} from './security.js';

// ===== SHA-256 hash helper (kept identical to auth.js so hashes match) =====
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ===== GET USER PROFILE =====
export async function getUser(request, env, userId) {
  try {
    const result = await query(env,
      `SELECT id, username, email, country, bio, cover_photo, avatar_url, 
              is_verified, is_online, privacy, created_at 
       FROM users WHERE id = ?`,
      [userId]
    );

    if (result.results.length === 0) {
      return Response.json({ 
        success: false, 
        error: 'User not found' 
      }, { status: 404, headers: corsHeaders });
    }

    return Response.json({ 
      success: true, 
      data: result.results[0] 
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== GET USER POSTS =====
export async function getUserPosts(request, env, userId) {
  try {
    const result = await query(env,
      'SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );

    return Response.json({ 
      success: true, 
      data: result.results 
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== ✅ GET USER TOOLS (NEW) =====
export async function getUserTools(request, env, userId) {
  try {
    const result = await query(env,
      'SELECT * FROM tools WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );

    return Response.json({ 
      success: true, 
      data: result.results 
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== UPDATE BIO =====
export async function updateBio(request, env, userId) {
  try {
    try {
      await requireSelf(request, env, userId);
    } catch (authResponse) {
      return authResponse;
    }

    const body = await request.json();
    const bio = sanitizeText(body.bio || '', 300);

    await run(env,
      'UPDATE users SET bio = ?, updated_at = ? WHERE id = ?',
      [bio, new Date().toISOString(), userId]
    );

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== SEARCH USERS =====
export async function searchUsers(request, env) {
  try {
    const url = new URL(request.url);
    const queryParam = url.searchParams.get('q') || '';

    if (!queryParam || queryParam.length < 1) {
      return Response.json({ success: true, data: [] }, { headers: corsHeaders });
    }

    const result = await query(env,
      'SELECT id, username FROM users WHERE username LIKE ? LIMIT 20',
      [`%${queryParam}%`]
    );

    return Response.json({ 
      success: true, 
      data: result.results 
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== GET VERIFIED USERS =====
export async function getVerifiedUsers(request, env) {
  try {
    const result = await query(env,
      'SELECT id FROM users WHERE is_verified = 1'
    );

    return Response.json({ 
      success: true, 
      data: result.results.map(r => r.id) 
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== UPDATE USERNAME (edit profile) =====
export async function updateUsername(request, env, userId) {
  try {
    try {
      await requireSelf(request, env, userId);
    } catch (authResponse) {
      return authResponse;
    }

    const body = await request.json();
    const username = (body.username || '').trim();

    if (!isValidUsername(username)) {
      return Response.json({
        success: false,
        error: `Username must be 2-${USERNAME_MAX_LENGTH} characters and contain only letters, numbers, and underscores`
      }, { status: 400, headers: corsHeaders });
    }

    // Uniqueness check (excluding self)
    const existing = await query(env,
      'SELECT id FROM users WHERE username = ? AND id != ?',
      [username, userId]
    );
    if (existing.results.length > 0) {
      return Response.json({
        success: false,
        error: 'Username already taken'
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      'UPDATE users SET username = ?, updated_at = ? WHERE id = ?',
      [username, new Date().toISOString(), userId]
    );

    return Response.json({ success: true, data: { username } }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== UPDATE EMAIL (requires current password confirmation) =====
export async function updateEmail(request, env, userId) {
  try {
    try {
      await requireSelf(request, env, userId);
    } catch (authResponse) {
      return authResponse;
    }

    const body = await request.json();
    const newEmail = (body.email || '').trim();
    const password = body.password || '';

    if (!isValidEmail(newEmail)) {
      return Response.json({
        success: false,
        error: 'Please provide a valid email address'
      }, { status: 400, headers: corsHeaders });
    }

    if (!password) {
      return Response.json({
        success: false,
        error: 'Please confirm your current password'
      }, { status: 400, headers: corsHeaders });
    }

    const userResult = await query(env, 'SELECT password FROM users WHERE id = ?', [userId]);
    if (userResult.results.length === 0) {
      return Response.json({ success: false, error: 'User not found' }, { status: 404, headers: corsHeaders });
    }

    const hashed = await hashPassword(password);
    if (userResult.results[0].password !== hashed) {
      return Response.json({
        success: false,
        error: 'Password is incorrect'
      }, { status: 401, headers: corsHeaders });
    }

    // Uniqueness check (excluding self)
    const existing = await query(env,
      'SELECT id FROM users WHERE email = ? AND id != ?',
      [newEmail, userId]
    );
    if (existing.results.length > 0) {
      return Response.json({
        success: false,
        error: 'Email already registered to another account'
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      'UPDATE users SET email = ?, updated_at = ? WHERE id = ?',
      [newEmail, new Date().toISOString(), userId]
    );

    return Response.json({ success: true, data: { email: newEmail } }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== DELETE ACCOUNT (requires current password confirmation) =====
// Permanently deletes the user and every row that references them:
// posts, comments (by them + on their posts), likes, notifications
// (received + generated), follows (both directions), blocks (both
// directions), tools, and any reports they filed.
export async function deleteAccount(request, env, userId) {
  try {
    try {
      await requireSelf(request, env, userId);
    } catch (authResponse) {
      return authResponse;
    }

    const body = await request.json().catch(() => ({}));
    const password = body.password || '';

    if (!password) {
      return Response.json({
        success: false,
        error: 'Please confirm your password to delete your account'
      }, { status: 400, headers: corsHeaders });
    }

    const userResult = await query(env, 'SELECT password, email FROM users WHERE id = ?', [userId]);
    if (userResult.results.length === 0) {
      return Response.json({ success: false, error: 'User not found' }, { status: 404, headers: corsHeaders });
    }

    const hashed = await hashPassword(password);
    if (userResult.results[0].password !== hashed) {
      return Response.json({
        success: false,
        error: 'Password is incorrect'
      }, { status: 401, headers: corsHeaders });
    }

    const userEmail = userResult.results[0].email;

    // Posts authored by this user
    const ownPosts = await query(env, 'SELECT id FROM posts WHERE user_id = ?', [userId]);
    const ownPostIds = ownPosts.results.map(p => p.id);

    for (const postId of ownPostIds) {
      await run(env, 'DELETE FROM comments WHERE post_id = ?', [postId]);
      await run(env, 'DELETE FROM likes WHERE post_id = ?', [postId]);
    }

    // Comments/likes this user made on other people's posts
    await run(env, 'DELETE FROM comments WHERE user_id = ?', [userId]);
    await run(env, 'DELETE FROM likes WHERE user_id = ?', [userId]);

    // Notifications sent to them or generated by their activity
    await run(env, 'DELETE FROM notifications WHERE user_id = ? OR actor_id = ?', [userId, userId]);

    // Follow relationships in both directions
    await run(env, 'DELETE FROM follows WHERE follower_id = ? OR following_id = ?', [userId, userId]);

    // Block relationships in both directions
    await run(env, 'DELETE FROM blocks WHERE user_id = ? OR blocked_user_id = ?', [userId, userId]);

    // Tools they published
    await run(env, 'DELETE FROM tools WHERE user_id = ?', [userId]);

    // Reports they filed (reports filed against them are kept for moderation history)
    await run(env, 'DELETE FROM reports WHERE reporter_id = ?', [userId]);

    // Their posts themselves
    await run(env, 'DELETE FROM posts WHERE user_id = ?', [userId]);

    // Password reset rate-limit rows tied to their email
    if (userEmail) {
      await run(env, 'DELETE FROM password_resets WHERE email = ?', [userEmail]);
    }

    // Finally, the user row itself
    await run(env, 'DELETE FROM users WHERE id = ?', [userId]);

    return Response.json({
      success: true,
      message: 'Account and all associated data deleted successfully'
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== UPDATE PRIVACY (public vs followers-only posts) =====
export async function updatePrivacy(request, env, userId) {
  try {
    try {
      await requireSelf(request, env, userId);
    } catch (authResponse) {
      return authResponse;
    }

    const body = await request.json();
    const privacy = body.privacy;

    if (!isValidPrivacy(privacy)) {
      return Response.json({
        success: false,
        error: "Privacy must be 'public' or 'followers'"
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      'UPDATE users SET privacy = ?, updated_at = ? WHERE id = ?',
      [privacy, new Date().toISOString(), userId]
    );

    return Response.json({ success: true, data: { privacy } }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}