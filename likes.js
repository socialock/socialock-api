// ============================================================
// 📁 likes.js - Likes API
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';

// ===== LIKE POST =====
export async function likePost(request, env, postId) {
  try {
    const body = await request.json();
    const { user_id } = body;

    if (!user_id) {
      return Response.json({ 
        success: false, 
        error: 'User ID required' 
      }, { status: 400, headers: corsHeaders });
    }

    // Check if already liked
    const existing = await query(env,
      'SELECT id FROM likes WHERE post_id = ? AND user_id = ?',
      [postId, user_id]
    );

    if (existing.results.length > 0) {
      return Response.json({ 
        success: false, 
        error: 'Already liked' 
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      'INSERT INTO likes (post_id, user_id, created_at) VALUES (?, ?, ?)',
      [postId, user_id, new Date().toISOString()]
    );

    await run(env,
      'UPDATE posts SET likes_count = likes_count + 1 WHERE id = ?',
      [postId]
    );

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== UNLIKE POST =====
export async function unlikePost(request, env, postId) {
  try {
    const body = await request.json();
    const { user_id } = body;

    if (!user_id) {
      return Response.json({ 
        success: false, 
        error: 'User ID required' 
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      'DELETE FROM likes WHERE post_id = ? AND user_id = ?',
      [postId, user_id]
    );

    await run(env,
      'UPDATE posts SET likes_count = likes_count - 1 WHERE id = ? AND likes_count > 0',
      [postId]
    );

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

