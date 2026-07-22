// ============================================================
// 📁 worker.js - Main Entry Point (রুট ফোল্ডারে)
// ============================================================

import { corsHeaders, handleCORS } from './cors.js';

// Import all route handlers
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

    // ===== CORS PREFLIGHT =====
    const corsResponse = handleCORS(request);
    if (corsResponse) return corsResponse;

    try {
      // ============================================================
      // AUTH ROUTES
      // ============================================================
      if (path === '/api/auth/register' && method === 'POST') {
        return handleRegister(request, env);
      }

      // ============================================================
      // USER ROUTES
      // ============================================================
      if (path === '/api/users/search' && method === 'GET') {
        return searchUsers(request, env);
      }

      if (path.startsWith('/api/users/')) {
        const parts = path.split('/');
        const userId = parts[3];
        const isPosts = path.includes('/posts');
        const isBio = path.includes('/bio');
        const isFollowers = path.includes('/followers');
        const isFollowing = path.includes('/following');

        if (method === 'GET' && !isPosts && !isBio && !isFollowers && !isFollowing) {
          return getUser(request, env, userId);
        }
        if (method === 'GET' && isPosts) {
          return getUserPosts(request, env, userId);
        }
        if (method === 'PUT' && isBio) {
          return updateBio(request, env, userId);
        }
        if (method === 'GET' && isFollowers) {
          return getFollowers(request, env, userId);
        }
        if (method === 'GET' && isFollowing) {
          return getFollowing(request, env, userId);
        }
      }

      // ===== FOLLOW/UNFOLLOW =====
      if (path === '/api/users/follow' && method === 'POST') {
        return followUser(request, env);
      }
      if (path === '/api/users/follow' && method === 'DELETE') {
        return unfollowUser(request, env);
      }

      // ============================================================
      // POST ROUTES
      // ============================================================
      if (path === '/api/posts' && method === 'GET') {
        return getPosts(request, env);
      }
      if (path === '/api/posts' && method === 'POST') {
        return createPost(request, env);
      }

      if (path.startsWith('/api/posts/')) {
        const parts = path.split('/');
        const postId = parts[3];
        const isComments = path.includes('/comments');
        const isLikes = path.includes('/like');

        if (method === 'GET' && !isComments && !isLikes) {
          return getPost(request, env, postId);
        }
        if (method === 'DELETE' && !isComments && !isLikes) {
          return deletePost(request, env, postId);
        }

        // ===== COMMENTS =====
        if (isComments && method === 'GET') {
          return getComments(request, env, postId);
        }
        if (isComments && method === 'POST') {
          return createComment(request, env, postId);
        }

        // ===== LIKES =====
        if (isLikes && method === 'POST') {
          return likePost(request, env, postId);
        }
        if (isLikes && method === 'DELETE') {
          return unlikePost(request, env, postId);
        }
      }

      // ===== DELETE COMMENT (standalone) =====
      if (path.startsWith('/api/comments/') && method === 'DELETE') {
        const commentId = path.split('/')[3];
        return deleteComment(request, env, commentId);
      }

      // ============================================================
      // NOTIFICATIONS ROUTES
      // ============================================================
      if (path === '/api/notifications' && method === 'GET') {
        return getNotifications(request, env);
      }
      if (path === '/api/notifications/read-all' && method === 'PUT') {
        return markAllNotificationsRead(request, env);
      }
      if (path.startsWith('/api/notifications/')) {
        const notifId = path.split('/')[3];
        if (method === 'PUT' && path.includes('/read')) {
          return markNotificationRead(request, env, notifId);
        }
        if (method === 'DELETE') {
          return deleteNotification(request, env, notifId);
        }
      }

      // ============================================================
      // TOOLS ROUTES
      // ============================================================
      if (path === '/api/tools' && method === 'GET') {
        return getTools(request, env);
      }
      if (path === '/api/tools' && method === 'POST') {
        return createTool(request, env);
      }
      if (path.startsWith('/api/tools/') && method === 'DELETE') {
        const toolId = path.split('/')[3];
        return deleteTool(request, env, toolId);
      }

      if (path === '/api/tools_ads' && method === 'GET') {
        return getToolsAds(request, env);
      }

      // ============================================================
      // ADS ROUTES
      // ============================================================
      if (path === '/api/ads' && method === 'GET') {
        return getAds(request, env);
      }

      // ============================================================
      // 404 - Not Found
      // ============================================================
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