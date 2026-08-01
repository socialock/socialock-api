// ============================================================
// 📁 worker.js - Main Entry Point (Complete)
// ============================================================

import { corsHeaders, handleCORS } from './cors.js';
import { handleRegister, handleLogin, handleResetPassword } from './auth.js';
import { getUser, getUserPosts, updateBio, searchUsers, getVerifiedUsers, getUserTools } from './users.js';
import { getPosts, createPost, getPost, deletePost, updatePost } from './posts.js';
import { getComments, createComment, deleteComment, getReplies } from './comments.js';
import { likePost, unlikePost, checkLiked } from './likes.js';
import { followUser, unfollowUser, getFollowers, getFollowing } from './follows.js';
import { getNotifications, markNotificationRead, markAllNotificationsRead, deleteNotification, deleteAllNotifications } from './notifications.js';
import { getTools, createTool, deleteTool, getToolsAds } from './tools.js';
import { getAds } from './ads.js';

export default {
  async fetch(request, env) {
    // CORS Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization',
          'Access-Control-Max-Age': '86400',
        }
      });
    }

    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;

    try {
      // ============================================================
      // AUTH ROUTES
      // ============================================================
      if (path === '/api/auth/register' && method === 'POST') {
        return handleRegister(request, env);
      }

      if (path === '/api/auth/login' && method === 'POST') {
        return handleLogin(request, env);
      }

      // ✅ Reset Password route
      if (path === '/api/auth/reset-password' && method === 'POST') {
        return handleResetPassword(request, env);
      }

      // ============================================================
      // USER ROUTES
      // ============================================================
      
      if (path === '/api/users/search' && method === 'GET') {
        return searchUsers(request, env);
      }

      if (path === '/api/users/verified' && method === 'GET') {
        return getVerifiedUsers(request, env);
      }

      if (path.startsWith('/api/users/')) {
        const parts = path.split('/');
        const userId = parts[3];
        const isPosts = path.includes('/posts');
        const isBio = path.includes('/bio');
        const isFollowers = path.includes('/followers');
        const isFollowing = path.includes('/following');
        const isTools = path.includes('/tools');

        if (method === 'GET' && isTools) {
          return getUserTools(request, env, userId);
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

        if (method === 'GET' && !isPosts && !isBio && !isFollowers && !isFollowing && !isTools) {
          return getUser(request, env, userId);
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
        const isLiked = path.includes('/liked');

        if (isLiked && method === 'GET') {
          return checkLiked(request, env, postId);
        }

        if (method === 'PATCH' && !isComments && !isLikes && !isLiked) {
          return updatePost(request, env, postId);
        }

        if (method === 'GET' && !isComments && !isLikes && !isLiked) {
          return getPost(request, env, postId);
        }

        if (method === 'DELETE' && !isComments && !isLikes && !isLiked) {
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

      // ===== REPLIES =====
      if (path.startsWith('/api/comments/') && path.includes('/replies') && method === 'GET') {
        const commentId = path.split('/')[3];
        return getReplies(request, env, commentId);
      }

      // ===== DELETE COMMENT =====
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
      if (path === '/api/notifications/delete-all' && method === 'DELETE') {
        return deleteAllNotifications(request, env);
      }
      if (path.startsWith('/api/notifications/') && path.endsWith('/read') && method === 'PUT') {
        const notifId = path.split('/')[3];
        return markNotificationRead(request, env, notifId);
      }
      if (path.startsWith('/api/notifications/') && method === 'DELETE') {
        const notifId = path.split('/')[3];
        if (notifId !== 'delete-all') {
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