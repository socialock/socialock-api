// ============================================================
// 📁 worker.js - Complete (Fixed User Routes)
// ============================================================

import { corsHeaders, handleCORS } from './cors.js';
import { handleRegister } from './auth.js';
import { getUser, getUserPosts, updateBio, searchUsers } from './users.js';
import { getPosts, createPost, getPost, deletePost } from './posts.js';
import { getComments, createComment, deleteComment } from './comments.js';
import { likePost, unlikePost } from './likes.js';
import { followUser, unfollowUser, getFollowers, getFollowing } from './follows.js';
import { getNotifications, markNotificationRead, markAllNotificationsRead, deleteNotification } from './notifications.js';
import { getTools, createTool, deleteTool, getToolsAds } from './tools.js';
import { getAds } from './ads.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;

    const corsResponse = handleCORS(request);
    if (corsResponse) return corsResponse;

    try {
      // ===== AUTH =====
      if (path === '/api/auth/register' && method === 'POST') {
        return handleRegister(request, env);
      }

      // ============================================================
      // 👤 USERS - FIXED
      // ============================================================
      
      // ===== SEARCH =====
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

      // ===== USER ROUTES =====
      if (path.startsWith('/api/users/') && method === 'GET') {
        const parts = path.split('/');
        const userId = parts[3];
        
        if (!userId) {
          return Response.json({ 
            success: false, 
            error: 'User ID required' 
          }, { status: 400, headers: corsHeaders });
        }

        // posts
        if (path.includes('/posts')) {
          const { results } = await env.DB.prepare(
            'SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC'
          ).bind(userId).all();
          return Response.json({ success: true, data: results }, { headers: corsHeaders });
        }

        // followers
        if (path.includes('/followers')) {
          const { results } = await env.DB.prepare(
            `SELECT u.id, u.username, u.is_verified 
             FROM follows f JOIN users u ON f.follower_id = u.id 
             WHERE f.following_id = ?`
          ).bind(userId).all();
          return Response.json({ success: true, data: results }, { headers: corsHeaders });
        }

        // following
        if (path.includes('/following')) {
          const { results } = await env.DB.prepare(
            `SELECT u.id, u.username, u.is_verified 
             FROM follows f JOIN users u ON f.following_id = u.id 
             WHERE f.follower_id = ?`
          ).bind(userId).all();
          return Response.json({ success: true, data: results }, { headers: corsHeaders });
        }

        // blocked
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

      // ===== FOLLOW =====
      if (path === '/api/users/follow' && method === 'POST') {
        return followUser(request, env);
      }
      if (path === '/api/users/follow' && method === 'DELETE') {
        return unfollowUser(request, env);
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

      // ... বাকি POST, COMMENTS, LIKES, NOTIFICATIONS, TOOLS, ADS রাউটিং আপনার আগের মতোই থাকবে

      // ===== 404 =====
      return Response.json({
        success: false,
        error: 'API endpoint not found'
      }, {
        status: 404,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });

    } catch (error) {
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