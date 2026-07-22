// ============================================================
// 📁 posts.js - Posts API
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';

// ===== GET ALL POSTS =====
export async function getPosts(request, env) {
  try {
    const result = await query(env,
      `SELECT p.*, u.is_verified 
       FROM posts p 
       LEFT JOIN users u ON p.user_id = u.id 
       ORDER BY p.created_at DESC 
       LIMIT 50`
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

// ===== CREATE POST =====
export async function createPost(request, env) {
  try {
    const body = await request.json();
    const { user_id, username, content } = body;

    if (!user_id || !username || !content) {
      return Response.json({ 
        success: false, 
        error: 'Missing required fields' 
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      `INSERT INTO posts (user_id, username, content, likes_count, comments_count, created_at) 
       VALUES (?, ?, ?, 0, 0, ?)`,
      [user_id, username, content, new Date().toISOString()]
    );

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== GET SINGLE POST =====
export async function getPost(request, env, postId) {
  try {
    const result = await query(env,
      `SELECT p.*, u.is_verified 
       FROM posts p 
       LEFT JOIN users u ON p.user_id = u.id 
       WHERE p.id = ?`,
      [postId]
    );

    if (result.results.length === 0) {
      return Response.json({ 
        success: false, 
        error: 'Post not found' 
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

// ===== DELETE POST =====
export async function deletePost(request, env, postId) {
  try {
    const body = await request.json();
    const { user_id } = body;

    if (!user_id) {
      return Response.json({ 
        success: false, 
        error: 'User ID required' 
      }, { status: 400, headers: corsHeaders });
    }

    await run(env, 'DELETE FROM comments WHERE post_id = ?', [postId]);
    await run(env, 'DELETE FROM likes WHERE post_id = ?', [postId]);
    await run(env, 'DELETE FROM posts WHERE id = ? AND user_id = ?', [postId, user_id]);

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}
