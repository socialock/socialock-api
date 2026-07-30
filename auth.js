// ============================================================
// 📁 auth.js - Authentication API (Complete)
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';

// ============================================================
// REGISTER
// ============================================================
export async function handleRegister(request, env) {
  try {
    const body = await request.json();
    const { id, username, email, password, country } = body;

    if (!id || !username || !email || !password) {
      return Response.json({ 
        success: false, 
        error: 'Missing required fields' 
      }, { status: 400, headers: corsHeaders });
    }

    // Validate username
    if (!/^[A-Za-z0-9]+$/.test(username)) {
      return Response.json({ 
        success: false, 
        error: 'Username can only contain letters and numbers' 
      }, { status: 400, headers: corsHeaders });
    }

    if (username.length > 10) {
      return Response.json({ 
        success: false, 
        error: 'Username cannot exceed 10 characters' 
      }, { status: 400, headers: corsHeaders });
    }

    // Check if username exists
    const existingUser = await query(env, 
      'SELECT id FROM users WHERE username = ?', [username]
    );
    if (existingUser.results.length > 0) {
      return Response.json({ 
        success: false, 
        error: 'Username already taken' 
      }, { status: 400, headers: corsHeaders });
    }

    // Check if email exists
    const existingEmail = await query(env, 
      'SELECT id FROM users WHERE email = ?', [email]
    );
    if (existingEmail.results.length > 0) {
      return Response.json({ 
        success: false, 
        error: 'Email already registered' 
      }, { status: 400, headers: corsHeaders });
    }

    // SHA-256 hash password
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashedPassword = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    await run(env,
      `INSERT INTO users (id, username, email, password, country, role, created_at) 
       VALUES (?, ?, ?, ?, ?, 'user', ?)`,
      [id, username, email, hashedPassword, country || '', new Date().toISOString()]
    );

    return Response.json({ 
      success: true, 
      message: 'User registered successfully' 
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ============================================================
// LOGIN
// ============================================================
export async function handleLogin(request, env) {
  try {
    const body = await request.json();
    const { username, password } = body;

    if (!username || !password) {
      return Response.json({ 
        success: false, 
        error: 'Missing credentials' 
      }, { status: 400, headers: corsHeaders });
    }

    // SHA-256 hash password
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashedPassword = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    // Find user by username
    let user = await query(env,
      'SELECT id, username, email, country, role FROM users WHERE username = ? AND password = ?',
      [username, hashedPassword]
    );

    // If not found by username, try email
    if (user.results.length === 0) {
      user = await query(env,
        'SELECT id, username, email, country, role FROM users WHERE email = ? AND password = ?',
        [username, hashedPassword]
      );
    }

    if (user.results.length === 0) {
      return Response.json({ 
        success: false, 
        error: 'Invalid credentials' 
      }, { status: 401, headers: corsHeaders });
    }

    return Response.json({ 
      success: true, 
      data: { 
        user: user.results[0] 
      }
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}