// ============================================================
// 📁 reports.js - Report Post/Tool/User API
// ============================================================
// Frontend contract:
//   POST /api/reports  body { reporter_id, target_type, target_id, reason, details? }
//                       -> { success, message }
//   target_type must be one of: 'post' | 'tool' | 'user'
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';
import { requireAuth, sanitizeText } from './security.js';

const VALID_TARGET_TYPES = ['post', 'tool', 'user'];
const VALID_REASONS = [
  'spam',
  'harassment',
  'hate_speech',
  'nudity_or_sexual_content',
  'violence',
  'false_information',
  'impersonation',
  'other'
];

export function isValidTargetType(value) {
  return VALID_TARGET_TYPES.includes(value);
}

// ===== CREATE REPORT =====
export async function createReport(request, env) {
  try {
    let auth;
    try {
      auth = await requireAuth(request, env);
    } catch (authResponse) {
      return authResponse;
    }

    const body = await request.json();
    const { reporter_id, target_type, target_id, reason, details } = body;

    if (!reporter_id || !target_type || !target_id || !reason) {
      return Response.json({
        success: false,
        error: 'Missing required fields'
      }, { status: 400, headers: corsHeaders });
    }

    // The reporter must be the authenticated user - prevents filing
    // reports on someone else's behalf.
    if (auth.sub !== reporter_id) {
      return Response.json({
        success: false,
        error: 'You are not allowed to file this report'
      }, { status: 403, headers: corsHeaders });
    }

    if (!isValidTargetType(target_type)) {
      return Response.json({
        success: false,
        error: "target_type must be one of: post, tool, user"
      }, { status: 400, headers: corsHeaders });
    }

    const normalizedReason = VALID_REASONS.includes(reason) ? reason : 'other';
    const detailsText = sanitizeText(details || '', 500);
    const targetIdStr = String(target_id);

    // Confirm the target actually exists so we don't collect junk reports.
    let targetExists = false;
    if (target_type === 'post') {
      const r = await query(env, 'SELECT id FROM posts WHERE id = ?', [targetIdStr]);
      targetExists = r.results.length > 0;
    } else if (target_type === 'tool') {
      const r = await query(env, 'SELECT id FROM tools WHERE id = ?', [targetIdStr]);
      targetExists = r.results.length > 0;
    } else if (target_type === 'user') {
      const r = await query(env, 'SELECT id FROM users WHERE id = ?', [targetIdStr]);
      targetExists = r.results.length > 0;
    }

    if (!targetExists) {
      return Response.json({
        success: false,
        error: 'The content you are trying to report no longer exists'
      }, { status: 404, headers: corsHeaders });
    }

    const id = crypto.randomUUID ? crypto.randomUUID() : Date.now().toString();

    await run(env,
      `INSERT OR IGNORE INTO reports (id, reporter_id, target_type, target_id, reason, details, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)`,
      [id, reporter_id, target_type, targetIdStr, normalizedReason, detailsText || null, new Date().toISOString()]
    );

    return Response.json({
      success: true,
      message: 'Report submitted. Thank you for helping keep SociaLock safe.'
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}
