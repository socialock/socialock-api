// ============================================================
// 📁 live.js - Live Streaming API (Worker)
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';

// SHA-256 হ্যাশ ফাংশন
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ===== ১. ক্রিয়েট লাইভ রুম =====
export async function handleCreateLive(request, env) {
    try {
        const body = await request.json();
        const { host_id, host_name, room_name, type, password } = body;

        if (!host_id || !host_name || !room_name || !type) {
            return Response.json({ success: false, error: 'Missing fields' }, { status: 400, headers: corsHeaders });
        }
        if (type === 'private' && !password) {
            return Response.json({ success: false, error: 'Password required for private room' }, { status: 400, headers: corsHeaders });
        }

        const room_id = crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).substr(2);
        const now = Date.now();
        let password_hash = null;
        if (password) {
            password_hash = await hashPassword(password);
        }

        // যদি একই নামে রুম থাকে, পুরনোটি বন্ধ করুন (ঐচ্ছিক)
        await run(env,
            `UPDATE live_rooms SET is_active = 0 WHERE room_name = ? AND is_active = 1`,
            [room_name]
        );

        await run(env,
            `INSERT INTO live_rooms (room_id, host_id, host_name, room_name, type, password, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [room_id, host_id, host_name, room_name, type, password_hash, now]
        );

        // হোস্টকে পার্টিসিপ্যান্টে যোগ করুন
        await run(env,
            `INSERT INTO live_participants (room_id, user_id, user_name, role, joined_at) VALUES (?, ?, ?, 'host', ?)`,
            [room_id, host_id, host_name, now]
        );

        return Response.json({
            success: true,
            data: { room_id }
        }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ===== ২. জয়েন লাইভ রুম =====
export async function handleJoinLive(request, env) {
    try {
        const body = await request.json();
        const { room_id, user_id, user_name, password } = body;

        if (!room_id || !user_id || !user_name) {
            return Response.json({ success: false, error: 'Missing fields' }, { status: 400, headers: corsHeaders });
        }

        // ১. রুম খুঁজুন
        const room = await query(env,
            `SELECT host_id, host_name, type, password, is_active FROM live_rooms WHERE room_id = ? AND is_active = 1`,
            [room_id]
        );
        if (room.results.length === 0) {
            return Response.json({ success: false, error: 'Room not found or inactive' }, { status: 404, headers: corsHeaders });
        }

        const roomData = room.results[0];

        // ২. প্রাইভেট চেক
        if (roomData.type === 'private') {
            if (!password) {
                return Response.json({ success: false, error: 'Password required for private room' }, { status: 403, headers: corsHeaders });
            }
            const inputHash = await hashPassword(password);
            if (inputHash !== roomData.password) {
                return Response.json({ success: false, error: 'Incorrect password' }, { status: 403, headers: corsHeaders });
            }
        }

        // ৩. ব্যান চেক
        const banned = await query(env,
            `SELECT user_id FROM live_bans WHERE room_id = ? AND user_id = ?`,
            [room_id, user_id]
        );
        if (banned.results.length > 0) {
            return Response.json({ success: false, error: 'You are banned from this room' }, { status: 403, headers: corsHeaders });
        }

        // ৪. পার্টিসিপ্যান্ট যোগ বা আপডেট
        await run(env,
            `INSERT OR REPLACE INTO live_participants (room_id, user_id, user_name, role, joined_at) VALUES (?, ?, ?, 'viewer', ?)`,
            [room_id, user_id, user_name, Date.now()]
        );

        return Response.json({
            success: true,
            data: { host_id: roomData.host_id, host_name: roomData.host_name }
        }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ===== ৩. পাবলিক রুম লিস্ট =====
export async function handleGetLiveRooms(request, env) {
    try {
        const now = Date.now();
        // ৫ মিনিট নিষ্ক্রিয় রুম বন্ধ করুন (হোস্ট হার্টবিট)
        await run(env,
            `UPDATE live_rooms SET is_active = 0 WHERE is_active = 1 AND ? - created_at > 300000`,
            [now]
        );

        const rooms = await query(env,
            `SELECT r.room_id, r.room_name, r.host_name, COUNT(p.user_id) as viewers 
             FROM live_rooms r 
             LEFT JOIN live_participants p ON r.room_id = p.room_id 
             WHERE r.type = 'public' AND r.is_active = 1 
             GROUP BY r.room_id 
             ORDER BY r.created_at DESC`
        );

        return Response.json({ success: true, data: rooms.results }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ===== ৪. পার্টিসিপ্যান্ট লিস্ট =====
export async function handleLiveParticipants(request, env) {
    try {
        const url = new URL(request.url);
        const roomId = url.searchParams.get('room_id');
        if (!roomId) {
            return Response.json({ success: false, error: 'Missing room_id' }, { status: 400, headers: corsHeaders });
        }

        const participants = await query(env,
            `SELECT user_id, user_name, role FROM live_participants WHERE room_id = ?`,
            [roomId]
        );

        return Response.json({ success: true, data: participants.results }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ===== ৫. ব্যান ইউজার =====
export async function handleLiveBan(request, env) {
    try {
        const body = await request.json();
        const { room_id, host_id, user_id } = body;

        if (!room_id || !host_id || !user_id) {
            return Response.json({ success: false, error: 'Missing fields' }, { status: 400, headers: corsHeaders });
        }

        // হোস্ট ভেরিফাই
        const room = await query(env,
            `SELECT host_id FROM live_rooms WHERE room_id = ? AND is_active = 1`,
            [room_id]
        );
        if (room.results.length === 0 || room.results[0].host_id !== host_id) {
            return Response.json({ success: false, error: 'Unauthorized' }, { status: 403, headers: corsHeaders });
        }

        await run(env,
            `INSERT OR REPLACE INTO live_bans (room_id, user_id) VALUES (?, ?)`,
            [room_id, user_id]
        );
        await run(env,
            `DELETE FROM live_participants WHERE room_id = ? AND user_id = ?`,
            [room_id, user_id]
        );

        return Response.json({ success: true }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ===== ৬. রুম ডিলিট =====
export async function handleDeleteLive(request, env) {
    try {
        const body = await request.json();
        const { room_id, host_id } = body;

        if (!room_id || !host_id) {
            return Response.json({ success: false, error: 'Missing fields' }, { status: 400, headers: corsHeaders });
        }

        await run(env, `DELETE FROM live_participants WHERE room_id = ?`, [room_id]);
        await run(env, `DELETE FROM live_bans WHERE room_id = ?`, [room_id]);
        await run(env, `DELETE FROM live_signals WHERE room_id = ?`, [room_id]);
        await run(env, `DELETE FROM live_rooms WHERE room_id = ? AND host_id = ?`, [room_id, host_id]);

        return Response.json({ success: true }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ===== ৭. সিগন্যাল সেভ =====
export async function handleSaveLiveSignal(request, env) {
    try {
        const body = await request.json();
        const { room_id, from, to, data } = body;
        if (!room_id || !from || !to || !data) {
            return Response.json({ success: false, error: 'Missing fields' }, { status: 400, headers: corsHeaders });
        }
        const now = Date.now();
        await run(env,
            `INSERT INTO live_signals (room_id, to_user_id, from_user_id, data, created_at) VALUES (?, ?, ?, ?, ?)`,
            [room_id, to, from, JSON.stringify(data), now]
        );
        await run(env, `DELETE FROM live_signals WHERE created_at < ?`, [now - 30000]);
        return Response.json({ success: true }, { headers: corsHeaders });
    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ===== ৮. সিগন্যাল পোল =====
export async function handleGetLiveSignals(request, env) {
    try {
        const url = new URL(request.url);
        const roomId = url.searchParams.get('room_id');
        const userId = url.searchParams.get('user_id');
        if (!roomId || !userId) {
            return Response.json({ success: false, error: 'Missing params' }, { status: 400, headers: corsHeaders });
        }
        const signals = await query(env,
            `SELECT from_user_id, data FROM live_signals WHERE room_id = ? AND to_user_id = ? ORDER BY created_at ASC`,
            [roomId, userId]
        );
        if (signals.results.length > 0) {
            await run(env, `DELETE FROM live_signals WHERE room_id = ? AND to_user_id = ?`, [roomId, userId]);
        }
        const result = signals.results.map(row => ({
            from: row.from_user_id,
            data: JSON.parse(row.data)
        }));
        return Response.json({ success: true, data: result }, { headers: corsHeaders });
    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}