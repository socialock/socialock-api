// ============================================================
// 📁 worker.js - Main Entry Point (Complete with CORS)
// ============================================================

import { corsHeaders, handleCORS, corsResponse, jsonResponse } from './cors.js';
import { handleRegister, handleLogin } from './auth.js';
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
    // ============================================================
    // 1️⃣ CORS Preflight - সবচেয়ে আগে হ্যান্ডেল করুন
    // ============================================================
    const corsPreflight = handleCORS(request);
    if (corsPreflight) return corsPreflight;

    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;

    try {
      let response = null;

      // ============================================================
      // AUTH ROUTES
      // ============================================================
      if (path === '/api/auth/register' && method === 'POST') {
        response = await handleRegister(request, env);
      } 
      else if (path === '/api/auth/login' && method === 'POST') {
        response = await handleLogin(request, env);
      }

      // ============================================================
      // USER ROUTES
      // ============================================================
      else if (path === '/api/users/search' && method === 'GET') {
        response = await searchUsers(request, env);
      } 
      else if (path === '/api/users/verified' && method === 'GET') {
        response = await getVerifiedUsers(request, env);
      } 
      else if (path.startsWith('/api/users/')) {
        const parts = path.split('/');
        const userId = parts[3];
        const isPosts = path.includes('/posts');
        const isBio = path.includes('/bio');
        const isFollowers = path.includes('/followers');
        const isFollowing = path.includes('/following');
        const isTools = path.includes('/tools');

        if (method === 'GET' && isTools) {
          response = await getUserTools(request, env, userId);
        } 
        else if (method === 'GET' && isPosts) {
          response = await getUserPosts(request, env, userId);
        } 
        else if (method === 'PUT' && isBio) {
          response = await updateBio(request, env, userId);
        } 
        else if (method === 'GET' && isFollowers) {
          response = await getFollowers(request, env, userId);
        } 
        else if (method === 'GET' && isFollowing) {
          response = await getFollowing(request, env, userId);
        } 
        else if (method === 'GET' && !isPosts && !isBio && !isFollowers && !isFollowing && !isTools) {
          response = await getUser(request, env, userId);
        }
      }

      // ===== FOLLOW / UNFOLLOW =====
      else if (path === '/api/users/follow' && method === 'POST') {
        response = await followUser(request, env);
      } 
      else if (path === '/api/users/follow' && method === 'DELETE') {
        response = await unfollowUser(request, env);
      }

      // ============================================================
      // POST ROUTES
      // ============================================================
      else if (path === '/api/posts' && method === 'GET') {
        response = await getPosts(request, env);
      } 
      else if (path === '/api/posts' && method === 'POST') {
        response = await createPost(request, env);
      } 
      else if (path.startsWith('/api/posts/')) {
        const parts = path.split('/');
        const postId = parts[3];
        const isComments = path.includes('/comments');
        const isLikes = path.includes('/like');
        const isLiked = path.includes('/liked');

        if (isLiked && method === 'GET') {
          response = await checkLiked(request, env, postId);
        } 
        else if (method === 'PATCH' && !isComments && !isLikes && !isLiked) {
          response = await updatePost(request, env, postId);
        } 
        else if (method === 'GET' && !isComments && !isLikes && !isLiked) {
          response = await getPost(request, env, postId);
        } 
        else if (method === 'DELETE' && !isComments && !isLikes && !isLiked) {
          response = await deletePost(request, env, postId);
        } 
        else if (isComments && method === 'GET') {
          response = await getComments(request, env, postId);
        } 
        else if (isComments && method === 'POST') {
          response = await createComment(request, env, postId);
        } 
        else if (isLikes && method === 'POST') {
          response = await likePost(request, env, postId);
        } 
        else if (isLikes && method === 'DELETE') {
          response = await unlikePost(request, env, postId);
        }
      }

      // ===== REPLIES =====
      else if (path.startsWith('/api/comments/') && path.includes('/replies') && method === 'GET') {
        const commentId = path.split('/')[3];
        response = await getReplies(request, env, commentId);
      } 
      else if (path.startsWith('/api/comments/') && method === 'DELETE') {
        const commentId = path.split('/')[3];
        response = await deleteComment(request, env, commentId);
      }

      // ============================================================
      // NOTIFICATIONS ROUTES - ✅ সঠিক অর্ডার
      // ============================================================
      // 1️⃣ GET notifications
      else if (path === '/api/notifications' && method === 'GET') {
        response = await getNotifications(request, env);
      }
      // 2️⃣ Mark single as read - read-all এর আগে বসাতে হবে
      else if (path.startsWith('/api/notifications/') && path.endsWith('/read') && method === 'PUT') {
        const notifId = path.split('/')[3];
        response = await markNotificationRead(request, env, notifId);
      }
      // 3️⃣ Mark all as read
      else if (path === '/api/notifications/read-all' && method === 'PUT') {
        response = await markAllNotificationsRead(request, env);
      }
      // 4️⃣ Delete all
      else if (path === '/api/notifications/delete-all' && method === 'DELETE') {
        response = await deleteAllNotifications(request, env);
      }
      // 5️⃣ Delete single
      else if (path.startsWith('/api/notifications/') && method === 'DELETE') {
        const parts = path.split('/');
        const notifId = parts[3];
        if (notifId !== 'delete-all') {
          response = await deleteNotification(request, env, notifId);
        }
      }

      // ============================================================
      // TOOLS ROUTES
      // ============================================================
      else if (path === '/api/tools' && method === 'GET') {
        response = await getTools(request, env);
      } 
      else if (path === '/api/tools' && method === 'POST') {
        response = await createTool(request, env);
      } 
      else if (path.startsWith('/api/tools/') && method === 'DELETE') {
        const toolId = path.split('/')[3];
        response = await deleteTool(request, env, toolId);
      } 
      else if (path === '/api/tools_ads' && method === 'GET') {
        response = await getToolsAds(request, env);
      }

      // ============================================================
      // ADS ROUTES
      // ============================================================
      else if (path === '/api/ads' && method === 'GET') {
        response = await getAds(request, env);
      }

      // ============================================================
      // 404 - Not Found
      // ============================================================
      else {
        response = jsonResponse({
          success: false,
          error: 'API endpoint not found'
        }, 404);
      }

      // ============================================================
      // 2️⃣ সব Response-এ CORS Headers যোগ করুন
      // ============================================================
      return corsResponse(response);

    } catch (error) {
      console.error('Worker Error:', error);
      return jsonResponse({
        success: false,
        error: 'Internal server error: ' + error.message
      }, 500);
    }
  }
};