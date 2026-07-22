// ============================================================
// 📁 notifications.js - Notifications API
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';

// ===== GET NOTIFICATIONS =====
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

// ===== MARK NOTIFICATION AS READ =====
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

    await run(env,
      'UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?',
      [notifId, user_id]
    );

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== MARK ALL NOTIFICATIONS AS READ =====
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

// ===== DELETE NOTIFICATION =====
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

    await run(env,
      'DELETE FROM notifications WHERE id = ? AND user_id = ?',
      [notifId, user_id]
    );

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

