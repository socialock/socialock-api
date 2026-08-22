// ============================================================
// 📁 blocks.js - Block / Unblock Users API
// ============================================================
//
// Frontend contract (already wired into home.html / userprofile.html):
//   GET  /api/users/:id/blocked   -> { success, data: [blockedUserId, ...] }
//   POST /api/users/block         body { user_id, blocked_user_id }
//                                  -> { success, action: 'blocked' | 'unblocked' }
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';
import { requireSelf } from './security.js';

// ===== Helper: is `a` blocked in relation to `b` (either direction) =====
export async function isBlocked(env, userIdA, userIdB) {
  if (!userIdA || !userIdB) return false;
  const result = await query(env,
    `SELECT id FROM blocks
     WHERE (user_id = ? AND blocked_user_id = ?)
        OR (user_id = ? AND blocked_user_id = ?)
     LIMIT 1`,
    [userIdA, userIdB, userIdB, userIdA]
  );
  return result.results.length > 0;
}

// ===== TOGGLE BLOCK (block if not blocked, unblock if already blocked) =====
export async function toggleBlockUser(request, env) {
  try {
    const body = await request.json();
    const { user_id, blocked_user_id } = body;

    if (!user_id || !blocked_user_id) {
      return Response.json({
        success: false,
        error: 'Missing required fields'
      }, { status: 400, headers: corsHeaders });
    }

    if (user_id === blocked_user_id) {
      return Response.json({
        success: false,
        error: 'You cannot block yourself'
      }, { status: 400, headers: corsHeaders });
    }

    // The official SociaLock account can never be blocked by anyone.
    const target = await query(env, 'SELECT username FROM users WHERE id = ?', [blocked_user_id]);
    if (target.results.length > 0 && String(target.results[0].username || '').toLowerCase() === 'socialock') {
      return Response.json({
        success: false,
        error: 'The official SociaLock account cannot be blocked'
      }, { status: 403, headers: corsHeaders });
    }

    // Auth: caller must be the blocker
    try {
      await requireSelf(request, env, user_id);
    } catch (authResponse) {
      return authResponse;
    }

    const existing = await query(env,
      'SELECT id FROM blocks WHERE user_id = ? AND blocked_user_id = ?',
      [user_id, blocked_user_id]
    );

    if (existing.results.length > 0) {
      // Already blocked -> unblock
      await run(env,
        'DELETE FROM blocks WHERE user_id = ? AND blocked_user_id = ?',
        [user_id, blocked_user_id]
      );
      return Response.json({ success: true, action: 'unblocked' }, { headers: corsHeaders });
    }

    // Not blocked -> block, and tear down any existing follow relationship both ways
    await run(env,
      'INSERT INTO blocks (user_id, blocked_user_id, created_at) VALUES (?, ?, ?)',
      [user_id, blocked_user_id, new Date().toISOString()]
    );

    await run(env, 'DELETE FROM follows WHERE follower_id = ? AND following_id = ?', [user_id, blocked_user_id]);
    await run(env, 'DELETE FROM follows WHERE follower_id = ? AND following_id = ?', [blocked_user_id, user_id]);

    return Response.json({ success: true, action: 'blocked' }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== GET LIST OF BLOCKED USER IDs =====
export async function getBlockedUsers(request, env, userId) {
  try {
    try {
      await requireSelf(request, env, userId);
    } catch (authResponse) {
      return authResponse;
    }

    const result = await query(env,
      'SELECT blocked_user_id FROM blocks WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );

    return Response.json({
      success: true,
      data: result.results.map(r => r.blocked_user_id)
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== GET LIST OF BLOCKED USERS WITH PROFILE INFO (for settings page) =====
export async function getBlockedUsersDetailed(request, env, userId) {
  try {
    try {
      await requireSelf(request, env, userId);
    } catch (authResponse) {
      return authResponse;
    }

    const result = await query(env,
      `SELECT u.id, u.username, u.avatar_url, u.is_verified, b.created_at AS blocked_at
       FROM blocks b
       JOIN users u ON u.id = b.blocked_user_id
       WHERE b.user_id = ?
       ORDER BY b.created_at DESC`,
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
