// ============================================================
// 📁 worker.js - Main Entry Point (Complete)
// ============================================================

import { corsHeaders, handleCORS } from './cors.js';
import { handleRegister, handleLogin, handleResetPassword, handleChangePassword, handleSyncPassword, handleIssueToken } from './auth.js';
import { getUser, getUserPosts, updateBio, searchUsers, getVerifiedUsers, getUserTools, updateUsername, updateEmail, updatePrivacy, updateCountry, deleteAccount } from './users.js';
import { getPosts, createPost, getPost, deletePost } from './posts.js';
import { getComments, createComment, deleteComment, getReplies } from './comments.js';
import { likePost, unlikePost, checkLiked } from './likes.js';
import { followUser, unfollowUser, getFollowers, getFollowing } from './follows.js';
import { getNotifications, markNotificationRead, markAllNotificationsRead, deleteNotification, deleteAllNotifications } from './notifications.js';
import { getTools, createTool, deleteTool, getToolsAds, recordToolView } from './tools.js';
import { getAds } from './ads.js';
import { toggleBlockUser, getBlockedUsers, getBlockedUsersDetailed } from './blocks.js';
import { checkRateLimit, rateLimitResponse, isLegitimateUserAgent, userAgentRejectResponse } from './security.js';
import { createReport } from './reports.js';
import { banUser, unbanUser, listBannedUsers } from './admin.js';

// ===== P2P Imports =====
import {
    handleCreateRoom,
    handleJoinRoom,
    handleGetRooms,
    handleHeartbeat,
    handleDeleteRoom,
    handleSaveSignal,
    handleGetSignals,
    handleApproveUser,
    handleKickUser,
    handleGetParticipants,
    handleP2PWebSocket
} from './p2p.js';

// ===== Live Imports =====
import {
    handleCreateLive,
    handleJoinLive,
    handleGetLiveRooms,
    handleLiveParticipants,
    handleLiveBan,
    handleDeleteLive,
    handleSaveLiveSignal,
    handleGetLiveSignals
} from './live.js';

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
            // SECURITY: USER-AGENT CHECK (state-changing requests only)
            // ============================================================
            if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method) && !isLegitimateUserAgent(request)) {
                return userAgentRejectResponse();
            }

            // ============================================================
            // SECURITY: RATE LIMITING
            // ============================================================
            const isAuthRoute = path.startsWith('/api/auth/');
            const isAccountDeleteRoute = method === 'DELETE' && path.startsWith('/api/users/') &&
                path.split('/').length === 4; // /api/users/:id (no further segments)
            const isToolViewRoute = method === 'POST' && path.startsWith('/api/tools/') && path.endsWith('/view');
            const isAdminRoute = path.startsWith('/api/admin/');
            const isSensitiveRoute = path === '/api/users/block' || path.endsWith('/username') ||
                path.endsWith('/email') || path.endsWith('/privacy') || path === '/api/reports' ||
                isAccountDeleteRoute || isToolViewRoute || isAdminRoute;

            if (isAuthRoute) {
                // Tighter limit on auth endpoints (login/register/reset/change-password brute force protection)
                if (!checkRateLimit(request, 'auth', 10, 60000)) {
                    return rateLimitResponse(60);
                }
            } else if (isSensitiveRoute) {
                if (!checkRateLimit(request, 'sensitive', 20, 60000)) {
                    return rateLimitResponse(60);
                }
            } else {
                // General API rate limit
                if (!checkRateLimit(request, 'global', 120, 60000)) {
                    return rateLimitResponse(60);
                }
            }

            // ============================================================
            // AUTH ROUTES
            // ============================================================
            if (path === '/api/auth/register' && method === 'POST') {
                return handleRegister(request, env);
            }
            if (path === '/api/auth/login' && method === 'POST') {
                return handleLogin(request, env);
            }
            if (path === '/api/auth/reset-password' && method === 'POST') {
                return handleResetPassword(request, env);
            }
            if (path === '/api/auth/change-password' && method === 'POST') {
                return handleChangePassword(request, env);
            }
            if (path === '/api/auth/sync-password' && method === 'POST') {
                return handleSyncPassword(request, env);
            }
            if (path === '/api/auth/token' && method === 'POST') {
                return handleIssueToken(request, env);
            }

            // ===== FOLLOW/UNFOLLOW (must be BEFORE /api/users/:id routes) =====
            if (path === '/api/users/follow' && method === 'POST') {
                return followUser(request, env);
            }
            if (path === '/api/users/follow' && method === 'DELETE') {
                return unfollowUser(request, env);
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
                const isBlocked = path.endsWith('/blocked');
                const isBlockedDetailed = path.endsWith('/blocked/detailed');
                const isUsername = path.endsWith('/username');
                const isEmail = path.endsWith('/email');
                const isPrivacy = path.endsWith('/privacy');
                const isCountry = path.endsWith('/country');
                const isPlainUserPath = parts.length === 4; // /api/users/:id exactly

                if (method === 'DELETE' && isPlainUserPath) {
                    return deleteAccount(request, env, userId);
                }
                if (method === 'GET' && isBlockedDetailed) {
                    return getBlockedUsersDetailed(request, env, userId);
                }
                if (method === 'GET' && isBlocked) {
                    return getBlockedUsers(request, env, userId);
                }
                if (method === 'PUT' && isUsername) {
                    return updateUsername(request, env, userId);
                }
                if (method === 'PUT' && isEmail) {
                    return updateEmail(request, env, userId);
                }
                if (method === 'PUT' && isPrivacy) {
                    return updatePrivacy(request, env, userId);
                }
                if (method === 'PUT' && isCountry) {
                    return updateCountry(request, env, userId);
                }
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
                if (method === 'GET' && !isPosts && !isBio && !isFollowers && !isFollowing &&
                    !isTools && !isBlocked && !isBlockedDetailed && !isUsername && !isEmail && !isPrivacy && !isCountry) {
                    return getUser(request, env, userId);
                }
            }

            // ===== BLOCK/UNBLOCK (toggle) =====
            if (path === '/api/users/block' && method === 'POST') {
                return toggleBlockUser(request, env);
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
                // NOTE: PATCH /api/posts/:id (raw likes_count/comments_count
                // overwrite) was removed - it had no auth check and let any
                // caller set any post's counters to any value. Counters are
                // maintained automatically by the like/comment endpoints.
                if (method === 'GET' && !isComments && !isLikes && !isLiked) {
                    return getPost(request, env, postId);
                }
                if (method === 'DELETE' && !isComments && !isLikes && !isLiked) {
                    return deletePost(request, env, postId);
                }
                if (isComments && method === 'GET') {
                    return getComments(request, env, postId);
                }
                if (isComments && method === 'POST') {
                    return createComment(request, env, postId);
                }
                if (isLikes && method === 'POST') {
                    return likePost(request, env, postId);
                }
                if (isLikes && method === 'DELETE') {
                    return unlikePost(request, env, postId);
                }
            }

            // ===== REPLIES & DELETE COMMENT =====
            if (path.startsWith('/api/comments/') && path.includes('/replies') && method === 'GET') {
                const commentId = path.split('/')[3];
                return getReplies(request, env, commentId);
            }
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
            // REPORTS
            // ============================================================
            if (path === '/api/reports' && method === 'POST') {
                return createReport(request, env);
            }

            // ============================================================
            // ADMIN (ban / unban users) - all require role = 'admin'
            // ============================================================
            if (path === '/api/admin/banned-users' && method === 'GET') {
                return listBannedUsers(request, env);
            }
            if (path.startsWith('/api/admin/users/') && path.endsWith('/ban') && method === 'POST') {
                const parts = path.split('/');
                const targetUserId = parts[4]; // /api/admin/users/:id/ban
                return banUser(request, env, targetUserId);
            }
            if (path.startsWith('/api/admin/users/') && path.endsWith('/unban') && method === 'POST') {
                const parts = path.split('/');
                const targetUserId = parts[4]; // /api/admin/users/:id/unban
                return unbanUser(request, env, targetUserId);
            }

            // ============================================================
            // TOOLS & ADS
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
            if (path.startsWith('/api/tools/') && path.endsWith('/view') && method === 'POST') {
                const toolId = path.split('/')[3];
                return recordToolView(request, env, toolId);
            }
            if (path === '/api/tools_ads' && method === 'GET') {
                return getToolsAds(request, env);
            }
            if (path === '/api/ads' && method === 'GET') {
                return getAds(request, env);
            }

            // ============================================================
            // P2P ROUTES
            // ============================================================
            if (path === '/api/p2p/create-room' && method === 'POST') {
                return handleCreateRoom(request, env);
            }
            if (path === '/api/p2p/join-room' && method === 'POST') {
                return handleJoinRoom(request, env);
            }
            if (path === '/api/p2p/rooms' && method === 'GET') {
                return handleGetRooms(request, env);
            }
            if (path === '/api/p2p/heartbeat' && method === 'POST') {
                return handleHeartbeat(request, env);
            }
            if (path === '/api/p2p/delete-room' && method === 'POST') {
                return handleDeleteRoom(request, env);
            }
            if (path === '/api/p2p/signal' && method === 'POST') {
                return handleSaveSignal(request, env);
            }
            if (path === '/api/p2p/signals' && method === 'GET') {
                return handleGetSignals(request, env);
            }
            if (path === '/api/p2p/approve' && method === 'POST') {
                return handleApproveUser(request, env);
            }
            if (path === '/api/p2p/kick' && method === 'POST') {
                return handleKickUser(request, env);
            }
            if (path === '/api/p2p/participants' && method === 'GET') {
                return handleGetParticipants(request, env);
            }
            if (path === '/api/p2p/ws' && method === 'GET') {
                return handleP2PWebSocket(request, env);
            }

            // ============================================================
            // LIVE ROUTES
            // ============================================================
            if (path === '/api/live/create' && method === 'POST') {
                return handleCreateLive(request, env);
            }
            if (path === '/api/live/join' && method === 'POST') {
                return handleJoinLive(request, env);
            }
            if (path === '/api/live/rooms' && method === 'GET') {
                return handleGetLiveRooms(request, env);
            }
            if (path === '/api/live/participants' && method === 'GET') {
                return handleLiveParticipants(request, env);
            }
            if (path === '/api/live/ban' && method === 'POST') {
                return handleLiveBan(request, env);
            }
            if (path === '/api/live/delete-room' && method === 'POST') {
                return handleDeleteLive(request, env);
            }
            if (path === '/api/live/signal' && method === 'POST') {
                return handleSaveLiveSignal(request, env);
            }
            if (path === '/api/live/signals' && method === 'GET') {
                return handleGetLiveSignals(request, env);
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