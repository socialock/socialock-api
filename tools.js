// ============================================================
// 📁 tools.js - Tools API
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';

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
    const body = await request.json();
    const { user_id, name, type, link } = body;

    if (!user_id || !name || !type || !link) {
      return Response.json({ 
        success: false, 
        error: 'Missing required fields' 
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
    const body = await request.json();
    const { user_id } = body;

    if (!user_id) {
      return Response.json({ 
        success: false, 
        error: 'User ID required' 
      }, { status: 400, headers: corsHeaders });
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

