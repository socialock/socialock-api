// ============================================================
// 📁 posts.js - Posts API
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';
import { getBearerToken, verifyJWT } from './security.js';

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
    const body = await request.json();

    const {
      user_id,
      username,
      content
    } = body;

    if (!user_id || !username || !content) {
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
        user_id,
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
    const body = await request.json();
    const { user_id } = body;

    if (!user_id) {
      return Response.json(
        {
          success: false,
          error: 'User ID required'
        },
        {
          status: 400,
          headers: corsHeaders
        }
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
      [postId, user_id]
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
// ============================================================
export async function updatePost(request, env, postId) {
  try {
    const body = await request.json();

    const {
      likes_count,
      comments_count
    } = body;

    const updates = [];
    const params = [];

    if (likes_count !== undefined) {
      updates.push('likes_count = ?');
      params.push(likes_count);
    }

    if (comments_count !== undefined) {
      updates.push('comments_count = ?');
      params.push(comments_count);
    }

    if (updates.length === 0) {
      return Response.json(
        {
          success: false,
          error: 'No fields to update'
        },
        {
          status: 400,
          headers: corsHeaders
        }
      );
    }

    params.push(postId);

    await run(
      env,
      `UPDATE posts
       SET ${updates.join(', ')}
       WHERE id = ?`,
      params
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