// ============================================================
// 📁 likes.js - Likes API (Complete with Notification)
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';
import { createOrUpdateLikeNotification } from './notifications.js';
import { requireAuth } from './security.js';

// ===== LIKE POST =====
export async function likePost(request, env, postId) {
  try {
    // Must be authenticated - a like is always recorded as the JWT
    // owner, never as a client-supplied user_id.
    let auth;
    try {
      auth = await requireAuth(request, env);
    } catch (authResponse) {
      return authResponse;
    }
    const user_id = auth.sub;
    const body = await request.json().catch(() => ({}));
    const username = auth.username || body.username;

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

    // Get post owner info
    const post = await query(env,
      'SELECT user_id, content FROM posts WHERE id = ?',
      [postId]
    );

    if (post.results.length === 0) {
      return Response.json({ 
        success: false, 
        error: 'Post not found' 
      }, { status: 404, headers: corsHeaders });
    }

    const postOwnerId = post.results[0].user_id;
    const postContent = post.results[0].content;

    // Add like
    await run(env,
      'INSERT INTO likes (post_id, user_id, created_at) VALUES (?, ?, ?)',
      [postId, user_id, new Date().toISOString()]
    );

    await run(env,
      'UPDATE posts SET likes_count = likes_count + 1 WHERE id = ?',
      [postId]
    );

    // Create/refresh a grouped like notification (only if not owner)
    if (postOwnerId !== user_id) {
      await createOrUpdateLikeNotification(env, {
        user_id: postOwnerId,
        actor_id: user_id,
        actor_username: username || 'User',
        post_id: parseInt(postId),
        post_content: postContent
      });
    }

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
    // Must be authenticated - can only remove your own like.
    let auth;
    try {
      auth = await requireAuth(request, env);
    } catch (authResponse) {
      return authResponse;
    }
    const user_id = auth.sub;

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

// ===== CHECK IF USER LIKED POST =====
export async function checkLiked(request, env, postId) {
  try {
    const url = new URL(request.url);
    const userId = url.searchParams.get('userId');

    if (!userId) {
      return Response.json({ 
        success: false, 
        error: 'User ID required' 
      }, { status: 400, headers: corsHeaders });
    }

    const result = await query(env,
      'SELECT id FROM likes WHERE post_id = ? AND user_id = ?',
      [postId, userId]
    );

    return Response.json({ 
      success: true, 
      data: result.results.length > 0 
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}