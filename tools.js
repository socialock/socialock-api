// ============================================================
// 📁 tools.js - Tools API
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';
import { requireAuth, sanitizeText } from './security.js';

// ===== GET ALL TOOLS =====
export async function getTools(request, env) {
  try {
    const result = await query(env,
      'SELECT * FROM tools ORDER BY created_at DESC'
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

// ===== CREATE TOOL =====
export async function createTool(request, env) {
  try {
    // Must be authenticated - tool is always created as the JWT owner.
    let auth;
    try {
      auth = await requireAuth(request, env);
    } catch (authResponse) {
      return authResponse;
    }
    const user_id = auth.sub;

    const body = await request.json();
    const name = sanitizeText(body.name || '', 100);
    const type = sanitizeText(body.type || '', 50);
    const link = sanitizeText(body.link || '', 500);

    if (!name || !type || !link) {
      return Response.json({ 
        success: false, 
        error: 'Missing required fields' 
      }, { status: 400, headers: corsHeaders });
    }

    if (!/^https?:\/\//i.test(link)) {
      return Response.json({
        success: false,
        error: 'Link must be a valid http(s) URL'
      }, { status: 400, headers: corsHeaders });
    }

    const toolId = crypto.randomUUID ? crypto.randomUUID() : Date.now().toString();

    await run(env,
      'INSERT INTO tools (id, user_id, name, type, link, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [toolId, user_id, name, type, link, new Date().toISOString()]
    );

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== DELETE TOOL =====
export async function deleteTool(request, env, toolId) {
  try {
    // Must be authenticated as the tool owner.
    let auth;
    try {
      auth = await requireAuth(request, env);
    } catch (authResponse) {
      return authResponse;
    }
    const user_id = auth.sub;

    const existing = await query(env, 'SELECT user_id FROM tools WHERE id = ?', [toolId]);
    if (existing.results.length === 0) {
      return Response.json({ success: false, error: 'Tool not found' }, { status: 404, headers: corsHeaders });
    }
    if (existing.results[0].user_id !== user_id) {
      return Response.json({
        success: false,
        error: 'You are not allowed to delete this tool'
      }, { status: 403, headers: corsHeaders });
    }

    await run(env,
      'DELETE FROM tools WHERE id = ? AND user_id = ?',
      [toolId, user_id]
    );

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== GET TOOLS ADS =====
export async function getToolsAds(request, env) {
  try {
    const url = new URL(request.url);
    const country = url.searchParams.get('country') || 'Bangladesh';

    const result = await query(env,
      'SELECT * FROM tools_ads WHERE target_country = ? OR target_country = "Global" LIMIT 5',
      [country]
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

