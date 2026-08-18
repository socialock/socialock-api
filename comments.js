// ============================================================
// 📁 comments.js - Comments API (Complete with Notification)
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';
import { createNotification } from './notifications.js';
import { isBlocked } from './blocks.js';

// ===== GET COMMENTS =====
export async function getComments(request, env, postId) {
  try {
    const url = new URL(request.url);
    const parentId = url.searchParams.get('parentId') || null;
    
    let sql = 'SELECT * FROM comments WHERE post_id = ?';
    let params = [postId];
    
    if (parentId) {
      sql += ' AND parent_comment_id = ?';
      params.push(parentId);
    } else {
      sql += ' AND parent_comment_id IS NULL';
    }
    
    sql += ' ORDER BY created_at ASC LIMIT 20';
    
    const result = await query(env, sql, params);

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

// ===== CREATE COMMENT / REPLY =====
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

    // Get post info
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

    if (await isBlocked(env, user_id, postOwnerId)) {
      return Response.json({
        success: false,
        error: 'You are unable to comment on this post'
      }, { status: 403, headers: corsHeaders });
    }

    let notificationUserId = postOwnerId;
    let notificationType = 'comment';
    let parentCommentContent = null;

    // If reply, get parent comment info
    if (parent_comment_id) {
      const parentComment = await query(env,
        'SELECT user_id, content FROM comments WHERE id = ?',
        [parent_comment_id]
      );

      if (parentComment.results.length > 0) {
        notificationUserId = parentComment.results[0].user_id;
        notificationType = 'reply';
        parentCommentContent = parentComment.results[0].content;
      }
    }

    // Insert comment
    await run(env,
      `INSERT INTO comments (post_id, user_id, username, content, parent_comment_id, replies_count, created_at) 
       VALUES (?, ?, ?, ?, ?, 0, ?)`,
      [postId, user_id, username, content, parent_comment_id || null, new Date().toISOString()]
    );

    // Update post comment count
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

    // Create notification
    if (notificationUserId !== user_id) {
      await createNotification(env, {
        user_id: notificationUserId,
        actor_id: user_id,
        actor_username: username,
        type: notificationType,
        post_id: parseInt(postId),
        post_content: postContent,
        comment_id: parent_comment_id || null,
        comment_content: parentCommentContent,
        reply_content: notificationType === 'reply' ? content : null
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

// ===== GET REPLIES =====
export async function getReplies(request, env, commentId) {
  try {
    const result = await query(env,
      'SELECT * FROM comments WHERE parent_comment_id = ? ORDER BY created_at ASC LIMIT 20',
      [commentId]
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

    await run(env, 'DELETE FROM comments WHERE parent_comment_id = ?', [commentId]);
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