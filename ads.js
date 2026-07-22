// ============================================================
// 📁 ads.js - Ads API
// ============================================================

import { corsHeaders } from './cors.js';
import { query } from './db.js';

export async function getAds(request, env) {
  try {
    const url = new URL(request.url);
    const country = url.searchParams.get('country') || 'Bangladesh';

    const result = await query(env,
      'SELECT * FROM ads WHERE target_country = ? OR target_country = "Global" LIMIT 10',
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

