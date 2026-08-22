// ============================================================
// 📁 admin.js - Admin Moderation API (Ban / Unban Users)
// ============================================================
// All handlers require an admin session (role = 'admin' on the
// calling user's row). A banned account:
//   - cannot log in (auth.js rejects at /auth/login and /auth/token)
//   - cannot do anything that requires a session token: create
//     posts/comments, like, follow, change settings, report, create
//     tools, etc. (security.js#requireAuth rejects every such call)
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';
import { requireAdmin, sanitizeText } from './security.js';

// ===== BAN A USER =====
// POST /api/admin/users/:id/ban   body: { "reason": "optional text" }
export async function banUser(request, env, targetUserId) {
  try {
    let admin;
    try {
      admin = await requireAdmin(request, env);
    } catch (authResponse) {
      return authResponse;
    }

    if (admin.sub === targetUserId) {
      return Response.json({
        success: false,
        error: 'You cannot ban your own account'
      }, { status: 400, headers: corsHeaders });
    }

    const target = await query(env, 'SELECT id, is_banned FROM users WHERE id = ?', [targetUserId]);
    if (target.results.length === 0) {
      return Response.json({ success: false, error: 'User not found' }, { status: 404, headers: corsHeaders });
    }

    if (target.results[0].is_banned) {
      return Response.json({ success: false, error: 'User is already banned' }, { status: 400, headers: corsHeaders });
    }

    let reason = '';
    try {
      const body = await request.json();
      reason = sanitizeText(body.reason || '', 500);
    } catch (e) {
      // no body / not JSON - ban with no reason is fine
    }

    await run(env,
      'UPDATE users SET is_banned = 1, ban_reason = ?, banned_at = ? WHERE id = ?',
      [reason || null, new Date().toISOString(), targetUserId]
    );

    return Response.json({
      success: true,
      message: 'User banned successfully',
      data: { id: targetUserId, is_banned: true, ban_reason: reason || null }
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
  }
}

// ===== UNBAN A USER =====
// POST /api/admin/users/:id/unban
export async function unbanUser(request, env, targetUserId) {
  try {
    try {
      await requireAdmin(request, env);
    } catch (authResponse) {
      return authResponse;
    }

    const target = await query(env, 'SELECT id, is_banned FROM users WHERE id = ?', [targetUserId]);
    if (target.results.length === 0) {
      return Response.json({ success: false, error: 'User not found' }, { status: 404, headers: corsHeaders });
    }

    if (!target.results[0].is_banned) {
      return Response.json({ success: false, error: 'User is not banned' }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      'UPDATE users SET is_banned = 0, ban_reason = NULL, banned_at = NULL WHERE id = ?',
      [targetUserId]
    );

    return Response.json({
      success: true,
      message: 'User unbanned successfully',
      data: { id: targetUserId, is_banned: false }
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
  }
}

// ===== LIST BANNED USERS =====
// GET /api/admin/banned-users
export async function listBannedUsers(request, env) {
  try {
    try {
      await requireAdmin(request, env);
    } catch (authResponse) {
      return authResponse;
    }

    const result = await query(env,
      `SELECT id, username, email, ban_reason, banned_at
       FROM users WHERE is_banned = 1 ORDER BY banned_at DESC`
    );

    return Response.json({ success: true, data: result.results }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
  }
}
