// ============================================================
// 📁 users.js - Users API
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';

// ===== GET USER PROFILE =====
export async function getUser(request, env, userId) {
  try {
    const result = await query(env,
      `SELECT id, username, email, country, bio, cover_photo, avatar_url, 
              is_verified, is_online, created_at 
       FROM users WHERE id = ?`,
      [userId]
    );

    if (result.results.length === 0) {
      return Response.json({ 
        success: false, 
        error: 'User not found' 
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

// ===== GET USER POSTS =====
export async function getUserPosts(request, env, userId) {
  try {
    const result = await query(env,
      'SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC',
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

// ===== UPDATE BIO =====
export async function updateBio(request, env, userId) {
  try {
    const body = await request.json();
    const { bio } = body;

    await run(env,
      'UPDATE users SET bio = ?, updated_at = ? WHERE id = ?',
      [bio || '', new Date().toISOString(), userId]
    );

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== SEARCH USERS =====
export async function searchUsers(request, env) {
  try {
    const url = new URL(request.url);
    const queryParam = url.searchParams.get('q') || '';

    if (!queryParam || queryParam.length < 1) {
      return Response.json({ success: true, data: [] }, { headers: corsHeaders });
    }

    const result = await query(env,
      'SELECT id, username FROM users WHERE username LIKE ? LIMIT 20',
      [`%${queryParam}%`]
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

