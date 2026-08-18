// ============================================================
// 📁 posts.js - Posts API
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';
import { getBearerToken, verifyJWT, requireAuth } from './security.js';

// ============================================================
// GET POSTS
// ============================================================
// Feed rules:
// - Maximum 50 posts
// - Non-interacted posts are requested first
// - Interacted posts only fill remaining slots
// - Latest posts are preferred inside each group
// - Current username is returned from users table so old posts
//   automatically show the user's latest username.
// ============================================================
export async function getPost(request, env, postId) {
  try {
    let viewerId = null;
    const token = getBearerToken(request);
    if (token) { try { viewerId = (await verifyJWT(token, env)).sub || null; } catch (_) {} }
    const result = await query(env,
      `SELECT p.*, COALESCE(u.username, p.username) AS username, u.is_verified
       FROM posts p LEFT JOIN users u ON p.user_id = u.id
       WHERE p.id = ?
         AND (u.privacy IS NULL OR u.privacy != 'followers' OR p.user_id = ? OR EXISTS (
           SELECT 1 FROM follows f WHERE f.follower_id = ? AND f.following_id = p.user_id
         ))`,
      [postId, viewerId, viewerId]
    );
    if (!result.results?.length) return Response.json({success:false,error:'Post not found'}, {status:404,headers:corsHeaders});
    return Response.json({success:true,data:result.results[0]}, {headers:corsHeaders});
  } catch (error) {
    return Response.json({success:false,error:error.message}, {status:500,headers:corsHeaders});
  }
}

// ============================================================
// DELETE POST
// ============================================================
export async function deletePost(request, env, postId) {
  try {
    const auth = await requireAuth(request, env);
    const owner = await query(env, 'SELECT user_id FROM posts WHERE id = ?', [postId]);
    if (!owner.results.length) return Response.json({success:false,error:'Post not found'}, {status:404,headers:corsHeaders});
    if (owner.results[0].user_id !== auth.sub) return Response.json({success:false,error:'Not allowed'}, {status:403,headers:corsHeaders});

    // Ownership is checked BEFORE any destructive child-row deletion.
    await run(env, 'DELETE FROM comments WHERE post_id = ?', [postId]);
    await run(env, 'DELETE FROM likes WHERE post_id = ?', [postId]);
    await run(env, 'DELETE FROM posts WHERE id = ? AND user_id = ?', [postId, auth.sub]);
    return Response.json({success:true}, {headers:corsHeaders});
  } catch (error) {
    if (error instanceof Response) return error;
    return Response.json({success:false,error:error.message}, {status:500,headers:corsHeaders});
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
      return Response.json({success:false,error:'Server-managed counters cannot be modified by clients'}, {status:400,headers:corsHeaders});
    }
    if (typeof body.content !== 'string' || !body.content.trim()) {
      return Response.json({success:false,error:'Content is required'}, {status:400,headers:corsHeaders});
    }
    const result = await run(env, 'UPDATE posts SET content = ? WHERE id = ? AND user_id = ?', [body.content.trim(), postId, auth.sub]);
    if (!result.meta?.changes) return Response.json({success:false,error:'Post not found or not owned by you'}, {status:403,headers:corsHeaders});
    return Response.json({success:true}, {headers:corsHeaders});
  } catch (error) {
    if (error instanceof Response) return error;
    return Response.json({success:false,error:error.message}, {status:500,headers:corsHeaders});
  }
}
