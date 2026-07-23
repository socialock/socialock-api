// ============================================================
// 📁 worker.js - Cloudflare Worker API (Complete)
// ============================================================

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;

    // ===== CORS PREFLIGHT =====
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      // ============================================================
      // 🔐 AUTH - REGISTER
      // ============================================================
      if (path === '/api/auth/register' && method === 'POST') {
        const body = await request.json();
        const { id, username, email, password, country } = body;

        if (!id || !username || !email || !password) {
          return Response.json({ success: false, error: 'Missing required fields' }, { status: 400, headers: corsHeaders });
        }

        const { results: userCheck } = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).all();
        if (userCheck.length > 0) {
          return Response.json({ success: false, error: 'Username already taken' }, { status: 400, headers: corsHeaders });
        }

        const { results: emailCheck } = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).all();
        if (emailCheck.length > 0) {
          return Response.json({ success: false, error: 'Email already registered' }, { status: 400, headers: corsHeaders });
        }

        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashedPassword = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        await env.DB.prepare(
          `INSERT INTO users (id, username, email, password, country, role, created_at) 
           VALUES (?, ?, ?, ?, ?, 'user', ?)`
        ).bind(id, username, email, hashedPassword, country || '', new Date().toISOString()).run();

        return Response.json({ success: true }, { headers: corsHeaders });
      }

      // ============================================================
      // 👤 USERS
      // ============================================================

      // ===== GET /api/users/search =====
      if (path === '/api/users/search' && method === 'GET') {
        const query = url.searchParams.get('q') || '';
        if (!query || query.length < 1) {
          return Response.json({ success: true, data: [] }, { headers: corsHeaders });
        }
        const { results } = await env.DB.prepare(
          'SELECT id, username FROM users WHERE username LIKE ? LIMIT 20'
        ).bind(`%${query}%`).all();
        return Response.json({ success: true, data: results }, { headers: corsHeaders });
      }

      // ===== GET /api/users/:id =====
      if (path.startsWith('/api/users/') && method === 'GET') {
        const parts = path.split('/');
        const userId = parts[3];

        if (!userId) {
          return Response.json({ success: false, error: 'User ID required' }, { status: 400, headers: corsHeaders });
        }

        // /api/users/:id/posts
        if (path.includes('/posts')) {
          const { results } = await env.DB.prepare(
            'SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC'
          ).bind(userId).all();
          return Response.json({ success: true, data: results }, { headers: corsHeaders });
        }

        // /api/users/:id/followers
        if (path.includes('/followers')) {
          const { results } = await env.DB.prepare(
            `SELECT u.id, u.username, u.is_verified 
             FROM follows f JOIN users u ON f.follower_id = u.id 
             WHERE f.following_id = ?`
          ).bind(userId).all();
          return Response.json({ success: true, data: results }, { headers: corsHeaders });
        }

        // /api/users/:id/following
        if (path.includes('/following')) {
          const { results } = await env.DB.prepare(
            `SELECT u.id, u.username, u.is_verified 
             FROM follows f JOIN users u ON f.following_id = u.id 
             WHERE f.follower_id = ?`
          ).bind(userId).all();
          return Response.json({ success: true, data: results }, { headers: corsHeaders });
        }

        // /api/users/:id/blocked
        if (path.includes('/blocked')) {
          const { results } = await env.DB.prepare(
            'SELECT blocked_user_id FROM blocks WHERE user_id = ?'
          ).bind(userId).all();
          return Response.json({ 
            success: true, 
            data: results.map(r => r.blocked_user_id) 
          }, { headers: corsHeaders });
        }

        // ===== PROFILE (সবার শেষে) =====
        const { results } = await env.DB.prepare(
          `SELECT id, username, email, country, bio, cover_photo, avatar_url, 
                  is_verified, is_online, created_at 
           FROM users WHERE id = ?`
        ).bind(userId).all();

        if (results.length === 0) {
          return Response.json({ 
            success: false, 
            error: 'User not found' 
          }, { status: 404, headers: corsHeaders });
        }

        return Response.json({ 
          success: true, 
          data: results[0] 
        }, { headers: corsHeaders });
      }

      // ===== PUT /api/users/:id/bio =====
      if (path.startsWith('/api/users/') && path.includes('/bio') && method === 'PUT') {
        const userId = path.split('/')[3];
        const body = await request.json();
        const { bio } = body;
        await env.DB.prepare(
          'UPDATE users SET bio = ?, updated_at = ? WHERE id = ?'
        ).bind(bio || '', new Date().toISOString(), userId).run();
        return Response.json({ success: true }, { headers: corsHeaders });
      }

      // ============================================================
      // 🔄 FOLLOW / UNFOLLOW
      // ============================================================

      if (path === '/api/users/follow' && method === 'POST') {
        const body = await request.json();
        const { follower_id, following_id } = body;
        if (!follower_id || !following_id) {
          return Response.json({ success: false, error: 'Missing required fields' }, { status: 400, headers: corsHeaders });
        }
        if (follower_id === following_id) {
          return Response.json({ success: false, error: 'You cannot follow yourself' }, { status: 400, headers: corsHeaders });
        }
        const { results } = await env.DB.prepare(
          'SELECT id FROM follows WHERE follower_id = ? AND following_id = ?'
        ).bind(follower_id, following_id).all();
        if (results.length > 0) {
          return Response.json({ success: false, error: 'Already following' }, { status: 400, headers: corsHeaders });
        }
        await env.DB.prepare(
          'INSERT INTO follows (follower_id, following_id, created_at) VALUES (?, ?, ?)'
        ).bind(follower_id, following_id, new Date().toISOString()).run();
        return Response.json({ success: true }, { headers: corsHeaders });
      }

      if (path === '/api/users/follow' && method === 'DELETE') {
        const body = await request.json();
        const { follower_id, following_id } = body;
        if (!follower_id || !following_id) {
          return Response.json({ success: false, error: 'Missing required fields' }, { status: 400, headers: corsHeaders });
        }
        await env.DB.prepare(
          'DELETE FROM follows WHERE follower_id = ? AND following_id = ?'
        ).bind(follower_id, following_id).run();
        return Response.json({ success: true }, { headers: corsHeaders });
      }

      // ============================================================
      // 📝 POSTS
      // ============================================================

      if (path === '/api/posts' && method === 'GET') {
        const { results } = await env.DB.prepare(
          `SELECT p.*, u.is_verified 
           FROM posts p LEFT JOIN users u ON p.user_id = u.id 
           ORDER BY p.created_at DESC LIMIT 50`
        ).all();
        return Response.json({ success: true, data: results }, { headers: corsHeaders });
      }

      if (path === '/api/posts' && method === 'POST') {
        const body = await request.json();
        const { user_id, username, content } = body;
        if (!user_id || !username || !content) {
          return Response.json({ success: false, error: 'Missing required fields' }, { status: 400, headers: corsHeaders });
        }
        await env.DB.prepare(
          `INSERT INTO posts (user_id, username, content, likes_count, comments_count, created_at) 
           VALUES (?, ?, ?, 0, 0, ?)`
        ).bind(user_id, username, content, new Date().toISOString()).run();
        return Response.json({ success: true }, { headers: corsHeaders });
      }

      if (path.startsWith('/api/posts/') && method === 'GET') {
        const postId = path.split('/')[3];
        
        // /api/posts/:id/liked
        if (path.includes('/liked')) {
          const userId = url.searchParams.get('userId');
          if (!userId) {
            return Response.json({ success: false, error: 'User ID required' }, { status: 400, headers: corsHeaders });
          }
          const { results } = await env.DB.prepare(
            'SELECT id FROM likes WHERE post_id = ? AND user_id = ?'
          ).bind(postId, userId).all();
          return Response.json({ 
            success: true, 
            data: results.length > 0 
          }, { headers: corsHeaders });
        }

        // /api/posts/:id/comments
        if (path.includes('/comments')) {
          const { results } = await env.DB.prepare(
            'SELECT * FROM comments WHERE post_id = ? AND parent_comment_id IS NULL ORDER BY created_at DESC LIMIT 10'
          ).bind(postId).all();
          return Response.json({ success: true, data: results }, { headers: corsHeaders });
        }

        // /api/posts/:id (single post)
        const { results } = await env.DB.prepare(
          `SELECT p.*, u.is_verified 
           FROM posts p LEFT JOIN users u ON p.user_id = u.id 
           WHERE p.id = ?`
        ).bind(postId).all();
        if (results.length === 0) {
          return Response.json({ success: false, error: 'Post not found' }, { status: 404, headers: corsHeaders });
        }
        return Response.json({ success: true, data: results[0] }, { headers: corsHeaders });
      }

      if (path.startsWith('/api/posts/') && method === 'DELETE') {
        const postId = path.split('/')[3];
        const body = await request.json();
        const { user_id } = body;
        if (!user_id) {
          return Response.json({ success: false, error: 'User ID required' }, { status: 400, headers: corsHeaders });
        }
        await env.DB.prepare('DELETE FROM comments WHERE post_id = ?').bind(postId).run();
        await env.DB.prepare('DELETE FROM likes WHERE post_id = ?').bind(postId).run();
        await env.DB.prepare('DELETE FROM posts WHERE id = ? AND user_id = ?').bind(postId, user_id).run();
        return Response.json({ success: true }, { headers: corsHeaders });
      }

      // ============================================================
      // ❤️ LIKES
      // ============================================================

      if (path.startsWith('/api/posts/') && path.includes('/like')) {
        const postId = path.split('/')[3];
        const body = await request.json();
        const { user_id } = body;

        if (!user_id) {
          return Response.json({ success: false, error: 'User ID required' }, { status: 400, headers: corsHeaders });
        }

        if (method === 'POST') {
          const { results } = await env.DB.prepare(
            'SELECT id FROM likes WHERE post_id = ? AND user_id = ?'
          ).bind(postId, user_id).all();
          if (results.length > 0) {
            return Response.json({ success: false, error: 'Already liked' }, { status: 400, headers: corsHeaders });
          }
          await env.DB.prepare(
            'INSERT INTO likes (post_id, user_id, created_at) VALUES (?, ?, ?)'
          ).bind(postId, user_id, new Date().toISOString()).run();
          await env.DB.prepare(
            'UPDATE posts SET likes_count = likes_count + 1 WHERE id = ?'
          ).bind(postId).run();
          return Response.json({ success: true }, { headers: corsHeaders });
        }

        if (method === 'DELETE') {
          await env.DB.prepare(
            'DELETE FROM likes WHERE post_id = ? AND user_id = ?'
          ).bind(postId, user_id).run();
          await env.DB.prepare(
            'UPDATE posts SET likes_count = likes_count - 1 WHERE id = ? AND likes_count > 0'
          ).bind(postId).run();
          return Response.json({ success: true }, { headers: corsHeaders });
        }
      }

      // ============================================================
      // 💬 COMMENTS
      // ============================================================

      if (path.startsWith('/api/posts/') && path.includes('/comments') && method === 'POST') {
        const postId = path.split('/')[3];
        const body = await request.json();
        const { user_id, username, content, parent_comment_id } = body;
        if (!user_id || !username || !content) {
          return Response.json({ success: false, error: 'Missing required fields' }, { status: 400, headers: corsHeaders });
        }
        await env.DB.prepare(
          `INSERT INTO comments (post_id, user_id, username, content, parent_comment_id, replies_count, created_at) 
           VALUES (?, ?, ?, ?, ?, 0, ?)`
        ).bind(postId, user_id, username, content, parent_comment_id || null, new Date().toISOString()).run();
        await env.DB.prepare(
          'UPDATE posts SET comments_count = comments_count + 1 WHERE id = ?'
        ).bind(postId).run();
        if (parent_comment_id) {
          await env.DB.prepare(
            'UPDATE comments SET replies_count = replies_count + 1 WHERE id = ?'
          ).bind(parent_comment_id).run();
        }
        return Response.json({ success: true }, { headers: corsHeaders });
      }

      if (path.startsWith('/api/comments/') && method === 'DELETE') {
        const commentId = path.split('/')[3];
        const body = await request.json();
        const { user_id } = body;
        if (!user_id) {
          return Response.json({ success: false, error: 'User ID required' }, { status: 400, headers: corsHeaders });
        }
        const comment = await env.DB.prepare(
          'SELECT post_id, parent_comment_id FROM comments WHERE id = ?'
        ).bind(commentId).all();
        if (comment.results.length === 0) {
          return Response.json({ success: false, error: 'Comment not found' }, { status: 404, headers: corsHeaders });
        }
        const postId = comment.results[0].post_id;
        const parentId = comment.results[0].parent_comment_id;
        await env.DB.prepare('DELETE FROM comments WHERE id = ? AND user_id = ?').bind(commentId, user_id).run();
        await env.DB.prepare(
          'UPDATE posts SET comments_count = comments_count - 1 WHERE id = ? AND comments_count > 0'
        ).bind(postId).run();
        if (parentId) {
          await env.DB.prepare(
            'UPDATE comments SET replies_count = replies_count - 1 WHERE id = ? AND replies_count > 0'
          ).bind(parentId).run();
        }
        return Response.json({ success: true }, { headers: corsHeaders });
      }

      // ============================================================
      // 🔔 NOTIFICATIONS
      // ============================================================

      if (path === '/api/notifications' && method === 'GET') {
        const userId = url.searchParams.get('userId');
        if (!userId) {
          return Response.json({ success: false, error: 'User ID required' }, { status: 400, headers: corsHeaders });
        }
        const { results } = await env.DB.prepare(
          'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50'
        ).bind(userId).all();
        return Response.json({ success: true, data: results }, { headers: corsHeaders });
      }

      if (path === '/api/notifications/read-all' && method === 'PUT') {
        const body = await request.json();
        const { user_id } = body;
        if (!user_id) {
          return Response.json({ success: false, error: 'User ID required' }, { status: 400, headers: corsHeaders });
        }
        await env.DB.prepare(
          'UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0'
        ).bind(user_id).run();
        return Response.json({ success: true }, { headers: corsHeaders });
      }

      if (path.startsWith('/api/notifications/') && method === 'DELETE') {
        const notifId = path.split('/')[3];
        const body = await request.json();
        const { user_id } = body;
        if (!user_id) {
          return Response.json({ success: false, error: 'User ID required' }, { status: 400, headers: corsHeaders });
        }
        await env.DB.prepare(
          'DELETE FROM notifications WHERE id = ? AND user_id = ?'
        ).bind(notifId, user_id).run();
        return Response.json({ success: true }, { headers: corsHeaders });
      }

      // ============================================================
      // 🛠️ TOOLS
      // ============================================================

      if (path === '/api/tools' && method === 'GET') {
        const { results } = await env.DB.prepare(
          'SELECT * FROM tools ORDER BY created_at DESC'
        ).all();
        return Response.json({ success: true, data: results }, { headers: corsHeaders });
      }

      if (path === '/api/tools' && method === 'POST') {
        const body = await request.json();
        const { user_id, name, type, link } = body;
        if (!user_id || !name || !type || !link) {
          return Response.json({ success: false, error: 'Missing required fields' }, { status: 400, headers: corsHeaders });
        }
        const toolId = crypto.randomUUID ? crypto.randomUUID() : Date.now().toString();
        await env.DB.prepare(
          'INSERT INTO tools (id, user_id, name, type, link, created_at) VALUES (?, ?, ?, ?, ?, ?)'
        ).bind(toolId, user_id, name, type, link, new Date().toISOString()).run();
        return Response.json({ success: true }, { headers: corsHeaders });
      }

      if (path.startsWith('/api/tools/') && method === 'DELETE') {
        const toolId = path.split('/')[3];
        const body = await request.json();
        const { user_id } = body;
        if (!user_id) {
          return Response.json({ success: false, error: 'User ID required' }, { status: 400, headers: corsHeaders });
        }
        await env.DB.prepare(
          'DELETE FROM tools WHERE id = ? AND user_id = ?'
        ).bind(toolId, user_id).run();
        return Response.json({ success: true }, { headers: corsHeaders });
      }

      if (path === '/api/tools_ads' && method === 'GET') {
        const country = url.searchParams.get('country') || 'Bangladesh';
        const { results } = await env.DB.prepare(
          'SELECT * FROM tools_ads WHERE target_country = ? OR target_country = "Global" LIMIT 5'
        ).bind(country).all();
        return Response.json({ success: true, data: results }, { headers: corsHeaders });
      }

      // ============================================================
      // 📢 ADS
      // ============================================================

      if (path === '/api/ads' && method === 'GET') {
        const country = url.searchParams.get('country') || 'Bangladesh';
        const { results } = await env.DB.prepare(
          'SELECT * FROM ads WHERE target_country = ? OR target_country = "Global" LIMIT 10'
        ).bind(country).all();
        return Response.json({ success: true, data: results }, { headers: corsHeaders });
      }

      // ============================================================
      // 404
      // ============================================================
      return Response.json({
        success: false,
        error: 'API endpoint not found'
      }, {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });

    } catch (error) {
      console.error('Worker Error:', error);
      return Response.json({
        success: false,
        error: 'Internal server error: ' + error.message
      }, {
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }
  }
};
