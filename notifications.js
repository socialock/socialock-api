// ============================================================
// 📁 notifications.js - Notifications API (FULL UPDATED)
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';

// ============================================================
// CREATE NOTIFICATION
// ============================================================
export async function createNotification(env, data) {
  try {
    const { user_id, actor_id, actor_username, type, post_id, post_content, comment_id, comment_content, reply_id, reply_content } = data;

    if (!user_id || !actor_id || !actor_username || !type) {
      console.error('Missing required fields for notification');
      return false;
    }

    // Don't notify yourself
    if (user_id === actor_id) return false;

    const id = crypto.randomUUID ? crypto.randomUUID() : Date.now().toString();

    await run(env,
      `INSERT INTO notifications (id, user_id, actor_id, actor_username, type, post_id, post_content, comment_id, comment_content, reply_id, reply_content, is_read, created_at) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
      [id, user_id, actor_id, actor_username, type, post_id || null, post_content || null, comment_id || null, comment_content || null, reply_id || null, reply_content || null, new Date().toISOString()]
    );

    return true;
  } catch (error) {
    console.error('Create notification error:', error);
    return false;
  }
}

// ============================================================
// GET NOTIFICATIONS
// ============================================================
export async function getNotifications(request, env) {
  try {
    const url = new URL(request.url);
    const userId = url.searchParams.get('userId');

    if (!userId) {
      return Response.json({ 
        success: false, 
        error: 'User ID required' 
      }, { status: 400, headers: corsHeaders });
    }

    const result = await query(env,
      'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
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

// ============================================================
// MARK NOTIFICATION AS READ - ✅ FIXED
// ============================================================
export async function markNotificationRead(request, env, notifId) {
  try {
    const body = await request.json();
    const { user_id } = body;

    if (!user_id) {
      return Response.json({ 
        success: false, 
        error: 'User ID required' 
      }, { status: 400, headers: corsHeaders });
    }

    console.log('📤 Marking as read:', notifId, 'for user:', user_id);

    await run(env,
      'UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?',
      [notifId, user_id]
    );

    return Response.json({ 
      success: true,
      message: 'Notification marked as read'
    }, { headers: corsHeaders });

  } catch (error) {
    console.error('❌ Mark read error:', error);
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ============================================================
// MARK ALL NOTIFICATIONS AS READ
// ============================================================
export async function markAllNotificationsRead(request, env) {
  try {
    const body = await request.json();
    const { user_id } = body;

    if (!user_id) {
      return Response.json({ 
        success: false, 
        error: 'User ID required' 
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      'UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0',
      [user_id]
    );

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ============================================================
// DELETE NOTIFICATION - ✅ FIXED
// ============================================================
export async function deleteNotification(request, env, notifId) {
  try {
    const body = await request.json();
    const { user_id } = body;

    if (!user_id) {
      return Response.json({ 
        success: false, 
        error: 'User ID required' 
      }, { status: 400, headers: corsHeaders });
    }

    console.log('📤 Deleting notification:', notifId, 'for user:', user_id);

    await run(env,
      'DELETE FROM notifications WHERE id = ? AND user_id = ?',
      [notifId, user_id]
    );

    return Response.json({ 
      success: true,
      message: 'Notification deleted'
    }, { headers: corsHeaders });

  } catch (error) {
    console.error('❌ Delete error:', error);
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ============================================================
// DELETE ALL NOTIFICATIONS
// ============================================================
export async function deleteAllNotifications(request, env) {
  try {
    const body = await request.json();
    const { user_id } = body;

    if (!user_id) {
      return Response.json({ 
        success: false, 
        error: 'User ID required' 
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      'DELETE FROM notifications WHERE user_id = ?',
      [user_id]
    );

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}