// ============================================================
// 📁 comments.js - Comments API
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';

// ===== GET COMMENTS =====
export async function getComments(request, env, postId) {
  try {
    const result = await query(env,
      `SELECT * FROM comments WHERE post_id = ? AND parent_comment_id IS NULL 
       ORDER BY created_at DESC LIMIT 10`,
      [postId]
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

// ===== CREATE COMMENT =====
export async function createComment(request, env, postId) {
  try {
    const body = await request.json();
    const { user_id, username, content, parent_comment_id } = body;

    if (!user_id || !username || !content) {
      return Response.json({ 
        success: false, 
        error: 'Missing required fields' 
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      `INSERT INTO comments (post_id, user_id, username, content, parent_comment_id, replies_count, created_at) 
       VALUES (?, ?, ?, ?, ?, 0, ?)`,
      [postId, user_id, username, content, parent_comment_id || null, new Date().toISOString()]
    );

    await run(env,
      'UPDATE posts SET comments_count = comments_count + 1 WHERE id = ?',
      [postId]
    );

    if (parent_comment_id) {
      await run(env,
        'UPDATE comments SET replies_count = replies_count + 1 WHERE id = ?',
        [parent_comment_id]
      );
    }

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== DELETE COMMENT =====
export async function deleteComment(request, env, commentId) {
  try {
    const body = await request.json();
    const { user_id } = body;

    if (!user_id) {
      return Response.json({ 
        success: false, 
        error: 'User ID required' 
      }, { status: 400, headers: corsHeaders });
    }

    // Get comment info first
    const comment = await query(env,
      'SELECT post_id, parent_comment_id FROM comments WHERE id = ?',
      [commentId]
    );

    if (comment.results.length === 0) {
      return Response.json({ 
        success: false, 
        error: 'Comment not found' 
      }, { status: 404, headers: corsHeaders });
    }

    const postId = comment.results[0].post_id;
    const parentId = comment.results[0].parent_comment_id;

    await run(env, 'DELETE FROM comments WHERE id = ? AND user_id = ?', [commentId, user_id]);

    await run(env,
      'UPDATE posts SET comments_count = comments_count - 1 WHERE id = ? AND comments_count > 0',
      [postId]
    );

    if (parentId) {
      await run(env,
        'UPDATE comments SET replies_count = replies_count - 1 WHERE id = ? AND replies_count > 0',
        [parentId]
      );
    }

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

