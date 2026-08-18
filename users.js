// ============================================================
// 📁 users.js - Users API (Complete)
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';
import {
  requireSelf,
  isValidUsername,
  isValidEmail,
  isValidPassword,
  isValidPrivacy,
  sanitizeText,
  USERNAME_MAX_LENGTH,
  getBearerToken,
  verifyJWT,
  verifyPassword
} from './security.js';


// ===== COUNTRY LIST (must stay in sync with login.html) =====
export const COUNTRY_LIST = [
  "Afghanistan", "Albania", "Algeria", "Andorra", "Angola",
  "Antigua and Barbuda", "Argentina", "Armenia", "Australia", "Austria",
  "Azerbaijan", "Bahamas", "Bahrain", "Bangladesh", "Barbados",
  "Belarus", "Belgium", "Belize", "Benin", "Bhutan",
  "Bolivia", "Bosnia and Herzegovina", "Botswana", "Brazil", "Brunei",
  "Bulgaria", "Burkina Faso", "Burundi", "Cabo Verde", "Cambodia",
  "Cameroon", "Canada", "Central African Republic", "Chad", "Chile",
  "China", "Colombia", "Comoros", "Congo", "Costa Rica",
  "Croatia", "Cuba", "Cyprus", "Czech Republic", "Denmark",
  "Djibouti", "Dominica", "Dominican Republic", "Ecuador", "Egypt",
  "El Salvador", "Equatorial Guinea", "Eritrea", "Estonia", "Eswatini",
  "Ethiopia", "Fiji", "Finland", "France", "Gabon",
  "Gambia", "Georgia", "Germany", "Ghana", "Greece",
  "Grenada", "Guatemala", "Guinea", "Guinea-Bissau", "Guyana",
  "Haiti", "Honduras", "Hungary", "Iceland", "India",
  "Indonesia", "Iran", "Iraq", "Ireland", "Israel",
  "Italy", "Jamaica", "Japan", "Jordan", "Kazakhstan",
  "Kenya", "Kiribati", "Korea, North", "Korea, South", "Kuwait",
  "Kyrgyzstan", "Laos", "Latvia", "Lebanon", "Lesotho",
  "Liberia", "Libya", "Liechtenstein", "Lithuania", "Luxembourg",
  "Madagascar", "Malawi", "Malaysia", "Maldives", "Mali",
  "Malta", "Marshall Islands", "Mauritania", "Mauritius", "Mexico",
  "Micronesia", "Moldova", "Monaco", "Mongolia", "Montenegro",
  "Morocco", "Mozambique", "Myanmar", "Namibia", "Nauru",
  "Nepal", "Netherlands", "New Zealand", "Nicaragua", "Niger",
  "Nigeria", "North Macedonia", "Norway", "Oman", "Pakistan",
  "Palau", "Palestine", "Panama", "Papua New Guinea", "Paraguay",
  "Peru", "Philippines", "Poland", "Portugal", "Qatar",
  "Romania", "Russia", "Rwanda", "Saint Kitts and Nevis", "Saint Lucia",
  "Saint Vincent", "Samoa", "San Marino", "Sao Tome and Principe", "Saudi Arabia",
  "Senegal", "Serbia", "Seychelles", "Sierra Leone", "Singapore",
  "Slovakia", "Slovenia", "Solomon Islands", "Somalia", "South Africa",
  "South Sudan", "Spain", "Sri Lanka", "Sudan", "Suriname",
  "Sweden", "Switzerland", "Syria", "Taiwan", "Tajikistan",
  "Tanzania", "Thailand", "Timor-Leste", "Togo", "Tonga",
  "Trinidad and Tobago", "Tunisia", "Turkey", "Turkmenistan", "Tuvalu",
  "Uganda", "Ukraine", "United Arab Emirates", "United Kingdom", "United States",
  "Uruguay", "Uzbekistan", "Vanuatu", "Vatican City", "Venezuela",
  "Vietnam", "Yemen", "Zambia", "Zimbabwe"
];

// ===== GET USER PROFILE =====
// `country` is private, like a Gmail recovery detail: it is only ever
// returned when the caller is viewing their own profile. Every other
// viewer gets the row with `country` stripped out, regardless of the
// requested userId.
export async function getUser(request, env, userId) {
  try {
    const result = await query(env,
      `SELECT id, username, email, country, bio, cover_photo, avatar_url, 
              is_verified, is_online, privacy, created_at 
       FROM users WHERE id = ?`,
      [userId]
    );

    if (result.results.length === 0) {
      return Response.json({ 
        success: false, 
        error: 'User not found' 
      }, { status: 404, headers: corsHeaders });
    }

    const userData = { ...result.results[0] };

    // Determine whether the requester is the profile owner. Auth here is
    // optional (profiles are viewable while logged out), so a missing or
    // invalid token simply means "not the owner" rather than a 401.
    let isSelf = false;
    const token = getBearerToken(request);
    if (token) {
      try {
        const payload = await verifyJWT(token, env);
        isSelf = payload.sub === userId;
      } catch (err) {
        isSelf = false;
      }
    }

    if (!isSelf) {
      delete userData.country;
    }

    return Response.json({ 
      success: true, 
      data: userData 
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== GET USER POSTS =====
// Respects the same privacy rule as the main feed: if the profile is
// 'followers'-only, only the owner and their followers may see the
// posts. Previously this ignored privacy entirely and returned every
// post to any caller who knew the userId.
export async function getUserPosts(request, env, userId) {
  try {
    let viewerId = null;
    const token = getBearerToken(request);
    if (token) {
      try {
        const payload = await verifyJWT(token, env);
        viewerId = payload.sub || null;
      } catch (e) {
        viewerId = null;
      }
    }

    const owner = await query(env, 'SELECT privacy FROM users WHERE id = ?', [userId]);
    if (owner.results.length === 0) {
      return Response.json({ success: false, error: 'User not found' }, { status: 404, headers: corsHeaders });
    }

    if (owner.results[0].privacy === 'followers' && viewerId !== userId) {
      let isFollower = false;
      if (viewerId) {
        const f = await query(env,
          'SELECT id FROM follows WHERE follower_id = ? AND following_id = ?',
          [viewerId, userId]
        );
        isFollower = f.results.length > 0;
      }
      if (!isFollower) {
        return Response.json({ success: true, data: [] }, { headers: corsHeaders });
      }
    }

    const result = await query(env,
      'SELECT * FROM posts WHERE user_id = ? ORDER BY created_at DESC',
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

// ===== ✅ GET USER TOOLS (NEW) =====
export async function getUserTools(request, env, userId) {
  try {
    const result = await query(env,
      'SELECT * FROM tools WHERE user_id = ? ORDER BY created_at DESC',
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

// ===== UPDATE BIO =====
export async function updateBio(request, env, userId) {
  try {
    try {
      await requireSelf(request, env, userId);
    } catch (authResponse) {
      return authResponse;
    }

    const body = await request.json();
    const bio = sanitizeText(body.bio || '', 300);

    await run(env,
      'UPDATE users SET bio = ?, updated_at = ? WHERE id = ?',
      [bio, new Date().toISOString(), userId]
    );

    return Response.json({ success: true }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== SEARCH USERS =====
export async function searchUsers(request, env) {
  try {
    const url = new URL(request.url);
    const queryParam = url.searchParams.get('q') || '';

    if (!queryParam || queryParam.length < 1) {
      return Response.json({ success: true, data: [] }, { headers: corsHeaders });
    }

    const result = await query(env,
      'SELECT id, username FROM users WHERE username LIKE ? LIMIT 20',
      [`%${queryParam}%`]
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

// ===== GET VERIFIED USERS =====
export async function getVerifiedUsers(request, env) {
  try {
    const result = await query(env,
      'SELECT id FROM users WHERE is_verified = 1'
    );

    return Response.json({ 
      success: true, 
      data: result.results.map(r => r.id) 
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({ 
      success: false, 
      error: error.message 
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== UPDATE COUNTRY (edit profile) =====
export async function updateCountry(request, env, userId) {
  try {
    try {
      await requireSelf(request, env, userId);
    } catch (authResponse) {
      return authResponse;
    }

    const body = await request.json();
    const country = typeof body.country === 'string' ? body.country.trim() : '';

    if (!country || !COUNTRY_LIST.includes(country)) {
      return Response.json({
        success: false,
        error: 'Please select a valid country from the country list'
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      'UPDATE users SET country = ?, updated_at = ? WHERE id = ?',
      [country, new Date().toISOString(), userId]
    );

    return Response.json({
      success: true,
      data: { country }
    }, { headers: corsHeaders });
  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== UPDATE USERNAME (edit profile) =====
export async function updateUsername(request, env, userId) {
  try {
    try {
      await requireSelf(request, env, userId);
    } catch (authResponse) {
      return authResponse;
    }

    const body = await request.json();
    const username = (body.username || '').trim();

    if (!isValidUsername(username)) {
      return Response.json({
        success: false,
        error: `Username must be 2-${USERNAME_MAX_LENGTH} characters and contain only letters, numbers, and underscores`
      }, { status: 400, headers: corsHeaders });
    }

    // Uniqueness check (excluding self)
    const existing = await query(env,
      'SELECT id FROM users WHERE username = ? AND id != ?',
      [username, userId]
    );
    if (existing.results.length > 0) {
      return Response.json({
        success: false,
        error: 'Username already taken'
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      'UPDATE users SET username = ?, updated_at = ? WHERE id = ?',
      [username, new Date().toISOString(), userId]
    );

    return Response.json({ success: true, data: { username } }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== UPDATE EMAIL (requires current password confirmation) =====
export async function updateEmail(request, env, userId) {
  try {
    try {
      await requireSelf(request, env, userId);
    } catch (authResponse) {
      return authResponse;
    }

    const body = await request.json();
    const newEmail = (body.email || '').trim();
    const password = body.password || '';

    if (!isValidEmail(newEmail)) {
      return Response.json({
        success: false,
        error: 'Please provide a valid email address'
      }, { status: 400, headers: corsHeaders });
    }

    if (!password) {
      return Response.json({
        success: false,
        error: 'Please confirm your current password'
      }, { status: 400, headers: corsHeaders });
    }

    const userResult = await query(env, 'SELECT password FROM users WHERE id = ?', [userId]);
    if (userResult.results.length === 0) {
      return Response.json({ success: false, error: 'User not found' }, { status: 404, headers: corsHeaders });
    }

    const { valid } = await verifyPassword(password, userResult.results[0].password);
    if (!valid) {
      return Response.json({
        success: false,
        error: 'Password is incorrect'
      }, { status: 401, headers: corsHeaders });
    }

    // Uniqueness check (excluding self)
    const existing = await query(env,
      'SELECT id FROM users WHERE email = ? AND id != ?',
      [newEmail, userId]
    );
    if (existing.results.length > 0) {
      return Response.json({
        success: false,
        error: 'Email already registered to another account'
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      'UPDATE users SET email = ?, updated_at = ? WHERE id = ?',
      [newEmail, new Date().toISOString(), userId]
    );

    return Response.json({ success: true, data: { email: newEmail } }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== DELETE ACCOUNT (requires current password confirmation) =====
// Permanently deletes the user and every row that references them:
// posts, comments (by them + on their posts), likes, notifications
// (received + generated), follows (both directions), blocks (both
// directions), tools, and any reports they filed.
export async function deleteAccount(request, env, userId) {
  try {
    try {
      await requireSelf(request, env, userId);
    } catch (authResponse) {
      return authResponse;
    }

    const body = await request.json().catch(() => ({}));
    const password = body.password || '';

    if (!password) {
      return Response.json({
        success: false,
        error: 'Please confirm your password to delete your account'
      }, { status: 400, headers: corsHeaders });
    }

    const userResult = await query(env, 'SELECT password, email FROM users WHERE id = ?', [userId]);
    if (userResult.results.length === 0) {
      return Response.json({ success: false, error: 'User not found' }, { status: 404, headers: corsHeaders });
    }

    const { valid } = await verifyPassword(password, userResult.results[0].password);
    if (!valid) {
      return Response.json({
        success: false,
        error: 'Password is incorrect'
      }, { status: 401, headers: corsHeaders });
    }

    const userEmail = userResult.results[0].email;

    // Posts authored by this user
    const ownPosts = await query(env, 'SELECT id FROM posts WHERE user_id = ?', [userId]);
    const ownPostIds = ownPosts.results.map(p => p.id);

    for (const postId of ownPostIds) {
      await run(env, 'DELETE FROM comments WHERE post_id = ?', [postId]);
      await run(env, 'DELETE FROM likes WHERE post_id = ?', [postId]);
    }

    // Comments/likes this user made on other people's posts
    await run(env, 'DELETE FROM comments WHERE user_id = ?', [userId]);
    await run(env, 'DELETE FROM likes WHERE user_id = ?', [userId]);

    // Notifications sent to them or generated by their activity
    await run(env, 'DELETE FROM notifications WHERE user_id = ? OR actor_id = ?', [userId, userId]);

    // Follow relationships in both directions
    await run(env, 'DELETE FROM follows WHERE follower_id = ? OR following_id = ?', [userId, userId]);

    // Block relationships in both directions
    await run(env, 'DELETE FROM blocks WHERE user_id = ? OR blocked_user_id = ?', [userId, userId]);

    // Tools they published
    await run(env, 'DELETE FROM tools WHERE user_id = ?', [userId]);

    // Reports they filed (reports filed against them are kept for moderation history)
    await run(env, 'DELETE FROM reports WHERE reporter_id = ?', [userId]);

    // Their posts themselves
    await run(env, 'DELETE FROM posts WHERE user_id = ?', [userId]);

    // Password reset rate-limit rows tied to their email
    if (userEmail) {
      await run(env, 'DELETE FROM password_resets WHERE email = ?', [userEmail]);
    }

    // Finally, the user row itself
    await run(env, 'DELETE FROM users WHERE id = ?', [userId]);

    return Response.json({
      success: true,
      message: 'Account and all associated data deleted successfully'
    }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}

// ===== UPDATE PRIVACY (public vs followers-only posts) =====
export async function updatePrivacy(request, env, userId) {
  try {
    try {
      await requireSelf(request, env, userId);
    } catch (authResponse) {
      return authResponse;
    }

    const body = await request.json();
    const privacy = body.privacy;

    if (!isValidPrivacy(privacy)) {
      return Response.json({
        success: false,
        error: "Privacy must be 'public' or 'followers'"
      }, { status: 400, headers: corsHeaders });
    }

    await run(env,
      'UPDATE users SET privacy = ?, updated_at = ? WHERE id = ?',
      [privacy, new Date().toISOString(), userId]
    );

    return Response.json({ success: true, data: { privacy } }, { headers: corsHeaders });

  } catch (error) {
    return Response.json({
      success: false,
      error: error.message
    }, { status: 500, headers: corsHeaders });
  }
}