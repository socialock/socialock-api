// ============================================================
// 📁 follows.js - Follows API
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';

// ===== FOLLOW USER =====
export async function followUser(request, env) {
  try {
    const body = await request.json();
    const { follower_id, following_id } = body;

    if (!follower_id || !following_id) {
      return Response.json({ 
        success: false, 
        error: 'Missing required fields' 
      }, { status: 400, headers: corsHeaders });
    }

    if (follower_id === following_id) {
      return Response.json({ 
        success: false, 
        error: 'You cannot follow yourself' 
      }, { status: 400, headers: corsHeaders });
    }

    const existing = await query(env,
      'SELECT id FROM follows WHERE follower_id = ? AND following_id = ?',
      [follower_id, following_id]
    );

    if (existing.results.length > 0) {
      return Response.json({ 
        success: false, 
        error: 'Already following' 
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      'INSERT INTO follows (follower_id, following_id, created_at) VALUES (?, ?, ?)',
      [follower_id, following_id, new Date().toISOString()]
    );

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== UNFOLLOW USER =====
export async function unfollowUser(request, env) {
  try {
    const body = await request.json();
    const { follower_id, following_id } = body;

    if (!follower_id || !following_id) {
      return Response.json({ 
        success: false, 
        error: 'Missing required fields' 
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      'DELETE FROM follows WHERE follower_id = ? AND following_id = ?',
      [follower_id, following_id]
    );

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== GET FOLLOWERS =====
export async function getFollowers(request, env, userId) {
  try {
    const result = await query(env,
      `SELECT u.id, u.username, u.is_verified 
       FROM follows f 
       JOIN users u ON f.follower_id = u.id 
       WHERE f.following_id = ?`,
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

// ===== GET FOLLOWING =====
export async function getFollowing(request, env, userId) {
  try {
    const result = await query(env,
      `SELECT u.id, u.username, u.is_verified 
       FROM follows f 
       JOIN users u ON f.following_id = u.id 
       WHERE f.follower_id = ?`,
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

