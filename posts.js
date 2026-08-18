// ============================================================
// 📁 posts.js - Posts API
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';
import { getBearerToken, verifyJWT, requireAuth, sanitizeText } from './security.js';

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
export async function getPosts(request, env) {
  try {
    let viewerId = null;

    const token = getBearerToken(request);

    if (token) {
      try {
        const payload = await verifyJWT(token, env);
        viewerId = payload.sub || null;
      } catch (e) {
        // Anonymous viewer
        viewerId = null;
      }
    }

    const result = await query(
      env,
      `SELECT
          p.*,

          -- Always use the current username from users table.
          -- This fixes old posts showing an old username.
          COALESCE(u.username, p.username) AS username,

          u.is_verified,

          -- 1 = user has interacted/liked the post
          -- 0 = user has not interacted
          CASE
            WHEN ? IS NOT NULL
             AND EXISTS (
                SELECT 1
                FROM likes l
                WHERE l.post_id = p.id
                  AND l.user_id = ?
             )
            THEN 1
            ELSE 0
          END AS user_interacted

       FROM posts p

       LEFT JOIN users u
         ON p.user_id = u.id

       WHERE
         (
           u.privacy IS NULL
           OR u.privacy != 'followers'
           OR p.user_id = ?
           OR EXISTS (
              SELECT 1
              FROM follows f
              WHERE f.follower_id = ?
                AND f.following_id = p.user_id
           )
         )

       -- Non-interacted posts first.
       -- Interacted posts only occupy remaining positions
       -- if fewer than 50 non-interacted posts exist.
       ORDER BY
         user_interacted ASC,
         p.created_at DESC

       LIMIT 50`,
      [
        viewerId,
        viewerId,
        viewerId,
        viewerId
      ]
    );

    return Response.json(
      {
        success: true,
        data: result.results || []
      },
      {
        headers: corsHeaders
      }
    );

  } catch (error) {
    return Response.json(
      {
        success: false,
        error: error.message
      },
      {
        status: 500,
        headers: corsHeaders
      }
    );
  }
}


// ============================================================
// CREATE POST
// ============================================================
export async function createPost(request, env) {
  try {
    // Must be authenticated - the post is always created as the
    // JWT owner, never as a client-supplied user_id/username.
    let auth;
    try {
      auth = await requireAuth(request, env);
    } catch (authResponse) {
      return authResponse;
    }

    const body = await request.json();
    const content = sanitizeText(body.content || '', 5000);

    if (!content) {
      return Response.json(
        {
          success: false,
          error: 'Missing required fields'
        },
        {
          status: 400,
          headers: corsHeaders
        }
      );
    }

    const userId = auth.sub;
    const username = auth.username;

    await run(
      env,
      `INSERT INTO posts
        (
          user_id,
          username,
          content,
          likes_count,
          comments_count,
          created_at
        )
       VALUES
        (?, ?, ?, 0, 0, ?)`,
      [
        userId,
        username,
        content,
        new Date().toISOString()
      ]
    );

    return Response.json(
      {
        success: true
      },
      {
        headers: corsHeaders
      }
    );

  } catch (error) {
    return Response.json(
      {
        success: false,
        error: error.message
      },
      {
        status: 500,
        headers: corsHeaders
      }
    );
  }
}


// ============================================================
// GET SINGLE POST
// ============================================================
export async function getPost(request, env, postId) {
  try {
    const result = await query(
      env,
      `SELECT
          p.*,
          COALESCE(u.username, p.username) AS username,
          u.is_verified
       FROM posts p
       LEFT JOIN users u
         ON p.user_id = u.id
       WHERE p.id = ?`,
      [postId]
    );

    if (!result.results || result.results.length === 0) {
      return Response.json(
        {
          success: false,
          error: 'Post not found'
        },
        {
          status: 404,
          headers: corsHeaders
        }
      );
    }

    return Response.json(
      {
        success: true,
        data: result.results[0]
      },
      {
        headers: corsHeaders
      }
    );

  } catch (error) {
    return Response.json(
      {
        success: false,
        error: error.message
      },
      {
        status: 500,
        headers: corsHeaders
      }
    );
  }
}


// ============================================================
// DELETE POST
// ============================================================
export async function deletePost(request, env, postId) {
  try {
    // Must be authenticated as the post owner - user_id can no longer
    // be spoofed via the request body.
    let auth;
    try {
      auth = await requireAuth(request, env);
    } catch (authResponse) {
      return authResponse;
    }
    const userId = auth.sub;

    const existing = await query(env, 'SELECT user_id FROM posts WHERE id = ?', [postId]);
    if (existing.results.length === 0) {
      return Response.json(
        { success: false, error: 'Post not found' },
        { status: 404, headers: corsHeaders }
      );
    }
    if (existing.results[0].user_id !== userId) {
      return Response.json(
        { success: false, error: 'You are not allowed to delete this post' },
        { status: 403, headers: corsHeaders }
      );
    }

    await run(
      env,
      'DELETE FROM comments WHERE post_id = ?',
      [postId]
    );

    await run(
      env,
      'DELETE FROM likes WHERE post_id = ?',
      [postId]
    );

    await run(
      env,
      'DELETE FROM posts WHERE id = ? AND user_id = ?',
      [postId, userId]
    );

    return Response.json(
      {
        success: true
      },
      {
        headers: corsHeaders
      }
    );

  } catch (error) {
    return Response.json(
      {
        success: false,
        error: error.message
      },
      {
        status: 500,
        headers: corsHeaders
      }
    );
  }
}


// ============================================================
// UPDATE POST
// ------------------------------------------------------------
// REMOVED: this used to let ANY caller (no auth check at all)
// directly overwrite likes_count / comments_count on ANY post to
// an arbitrary value. Those counters are already maintained
// correctly and atomically by likePost/unlikePost and
// createComment/deleteComment, so this endpoint had no legitimate
// use and was pure attack surface (like/comment-count spoofing).
// The route has been removed from worker.js as well.
// ============================================================