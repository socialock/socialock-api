// ============================================================
// 📁 posts.js - Posts API (FULL UPDATED)
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';
import { getBearerToken, verifyJWT, requireAuth, sanitizeText } from './security.js';

// ============================================================
// GET ALL POSTS (FEED)
// ============================================================
export async function getPosts(request, env) {
  try {
    let viewerId = null;
    const token = getBearerToken(request);
    if (token) {
      try {
        viewerId = (await verifyJWT(token, env)).sub || null;
      } catch (_) {}
    }

    const result = await query(env,
      `SELECT p.*, COALESCE(u.username, p.username) AS username, u.is_verified
       FROM posts p 
       LEFT JOIN users u ON p.user_id = u.id
       WHERE (u.privacy IS NULL OR u.privacy != 'followers' OR p.user_id = ? OR EXISTS (
         SELECT 1 FROM follows f WHERE f.follower_id = ? AND f.following_id = p.user_id
       ))
       ORDER BY p.created_at DESC
       LIMIT 50`,
      [viewerId, viewerId]
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

// ============================================================
// CREATE POST
// ============================================================
export async function createPost(request, env) {
  try {
    const auth = await requireAuth(request, env);
    const user_id = auth.sub;
    const username = auth.username;
    
    const body = await request.json();
    const { content, image_url } = body;

    if (!user_id || !username || !content) {
      return Response.json({ 
        success: false, 
        error: 'Missing required fields' 
      }, { status: 400, headers: corsHeaders });
    }

    const sanitizedContent = sanitizeText(content, 5000);
    if (!sanitizedContent.trim()) {
      return Response.json({ 
        success: false, 
        error: 'Content cannot be empty' 
      }, { status: 400, headers: corsHeaders });
    }

    const postId = crypto.randomUUID ? crypto.randomUUID() : Date.now().toString();

    await run(env,
      `INSERT INTO posts (id, user_id, username, content, image_url, likes_count, comments_count, created_at) 
       VALUES (?, ?, ?, ?, ?, 0, 0, ?)`,
      [postId, user_id, username, sanitizedContent, image_url || null, new Date().toISOString()]
    );

    return Response.json({ 
      success: true, 
      data: { id: postId } 
    }, { headers: corsHeaders });

  } catch (error) {
    if (error instanceof Response) return error;
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ============================================================
// GET SINGLE POST
// ============================================================
export async function getPost(request, env, postId) {
  try {
    let viewerId = null;
    const token = getBearerToken(request);
    if (token) { 
      try { 
        viewerId = (await verifyJWT(token, env)).sub || null; 
      } catch (_) {} 
    }
    
    const result = await query(env,
      `SELECT p.*, COALESCE(u.username, p.username) AS username, u.is_verified
       FROM posts p LEFT JOIN users u ON p.user_id = u.id
       WHERE p.id = ?
         AND (u.privacy IS NULL OR u.privacy != 'followers' OR p.user_id = ? OR EXISTS (
           SELECT 1 FROM follows f WHERE f.follower_id = ? AND f.following_id = p.user_id
         ))`,
      [postId, viewerId, viewerId]
    );
    
    if (!result.results?.length) {
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

// ============================================================
// DELETE POST
// ============================================================
export async function deletePost(request, env, postId) {
  try {
    const auth = await requireAuth(request, env);
    const owner = await query(env, 'SELECT user_id FROM posts WHERE id = ?', [postId]);
    
    if (!owner.results.length) {
      return Response.json({
        success: false,
        error: 'Post not found'
      }, { status: 404, headers: corsHeaders });
    }
    
    if (owner.results[0].user_id !== auth.sub) {
      return Response.json({
        success: false,
        error: 'Not allowed'
      }, { status: 403, headers: corsHeaders });
    }

    // Delete all related data
    await run(env, 'DELETE FROM comments WHERE post_id = ?', [postId]);
    await run(env, 'DELETE FROM likes WHERE post_id = ?', [postId]);
    await run(env, 'DELETE FROM posts WHERE id = ? AND user_id = ?', [postId, auth.sub]);
    
    return Response.json({ success: true }, { headers: corsHeaders });
    
  } catch (error) {
    if (error instanceof Response) return error;
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}

// ============================================================
// UPDATE POST
// ============================================================
export async function updatePost(request, env, postId) {
  try {
    const auth = await requireAuth(request, env);
    const body = await request.json();
    
    if (body.likes_count !== undefined || body.comments_count !== undefined) {
      return Response.json({
        success: false,
        error: 'Server-managed counters cannot be modified by clients'
      }, { status: 400, headers: corsHeaders });
    }
    
    if (typeof body.content !== 'string' || !body.content.trim()) {
      return Response.json({
        success: false,
        error: 'Content is required'
      }, { status: 400, headers: corsHeaders });
    }
    
    const sanitizedContent = sanitizeText(body.content.trim(), 5000);
    const result = await run(env, 
      'UPDATE posts SET content = ? WHERE id = ? AND user_id = ?', 
      [sanitizedContent, postId, auth.sub]
    );
    
    if (!result.meta?.changes) {
      return Response.json({
        success: false,
        error: 'Post not found or not owned by you'
      }, { status: 403, headers: corsHeaders });
    }
    
    return Response.json({ success: true }, { headers: corsHeaders });
    
  } catch (error) {
    if (error instanceof Response) return error;
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}