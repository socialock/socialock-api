// ============================================================
// 📁 cors.js - CORS Headers (Complete)
// ============================================================

// ✅ CORS Headers - সব Response এ যোগ করতে হবে
export const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

// ✅ OPTIONS Preflight Handle
export function handleCORS(request) {
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        ...corsHeaders,
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }
    });
  }
  return null;
}

// ✅ Response Wrapper - সব Response এ CORS Headers যোগ করে
export function corsResponse(response) {
  const newResponse = new Response(response.body, response);
  newResponse.headers.set('Access-Control-Allow-Origin', '*');
  newResponse.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  newResponse.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  newResponse.headers.set('Access-Control-Max-Age', '86400');
  return newResponse;
}

// ✅ JSON Response Helper - CORS সহ JSON Response
export function jsonResponse(data, status = 200) {
  return corsResponse(new Response(JSON.stringify(data), {
    status: status,
    headers: { 'Content-Type': 'application/json' }
  }));
}