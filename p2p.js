// ============================================================
// 📁 p2p.js - P2P Signaling Server & API (Complete)
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';

// ============================================================
// ১. রুম ক্রিয়েট
// ============================================================
export async function handleCreateRoom(request, env) {
    try {
        const body = await request.json();
        const { host_id, host_name } = body;

        if (!host_id || !host_name) {
            return Response.json({ success: false, error: 'Host ID and Name required' }, { status: 400, headers: corsHeaders });
        }

        const room_id = crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).substr(2);
        const token = crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).substr(2);
        const now = Date.now();

        await run(env,
            `INSERT INTO p2p_rooms (room_id, host_id, host_name, token, last_seen, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
            [room_id, host_id, host_name, token, now, now]
        );

        // হোস্টকে নিজেই অ্যাপ্রুভড করে দিন
        await run(env,
            `INSERT INTO p2p_participants (room_id, user_id, user_name, status, joined_at) VALUES (?, ?, ?, 'approved', ?)`,
            [room_id, host_id, host_name, now]
        );

        return Response.json({
            success: true,
            data: { room_id, token }
        }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================
// ২. রুম জয়েন (টোকেন ভেরিফাই + অ্যাপ্রুভাল পেন্ডিং)
// ============================================================
export async function handleJoinRoom(request, env) {
    try {
        const body = await request.json();
        const { room_id, token, user_id, user_name } = body;

        if (!room_id || !token || !user_id || !user_name) {
            return Response.json({ success: false, error: 'Missing fields' }, { status: 400, headers: corsHeaders });
        }

        // ১. রুম ও টোকেন ভেরিফাই
        const room = await query(env,
            `SELECT host_id, host_name, last_seen, is_active FROM p2p_rooms WHERE room_id = ? AND token = ? AND is_active = 1`,
            [room_id, token]
        );

        if (room.results.length === 0) {
            return Response.json({ success: false, error: 'Invalid room or token' }, { status: 404, headers: corsHeaders });
        }

        // ২. ৫ মিনিট অফলাইন চেক (রুম নিষ্ক্রিয়)
        const lastSeen = room.results[0].last_seen;
        if (Date.now() - lastSeen > 5 * 60 * 1000) {
            await run(env, `UPDATE p2p_rooms SET is_active = 0 WHERE room_id = ?`, [room_id]);
            return Response.json({ success: false, error: 'Room expired (Host offline > 5 min)' }, { status: 410, headers: corsHeaders });
        }

        // ৩. কিক তালিকা চেক
        const kicked = await query(env,
            `SELECT user_id FROM p2p_kicks WHERE room_id = ? AND user_id = ?`,
            [room_id, user_id]
        );
        if (kicked.results.length > 0) {
            return Response.json({ success: false, error: 'You have been kicked from this room' }, { status: 403, headers: corsHeaders });
        }

        // ৪. ইতিমধ্যে যোগ দিয়েছে কিনা
        const existing = await query(env,
            `SELECT status FROM p2p_participants WHERE room_id = ? AND user_id = ?`,
            [room_id, user_id]
        );

        if (existing.results.length > 0) {
            if (existing.results[0].status === 'approved') {
                return Response.json({ success: true, data: { host_id: room.results[0].host_id, status: 'approved' } });
            }
            if (existing.results[0].status === 'pending') {
                return Response.json({ success: true, data: { host_id: room.results[0].host_id, status: 'pending' } });
            }
        }

        // ৫. পেন্ডিং রিকোয়েস্ট যোগ করুন
        await run(env,
            `INSERT INTO p2p_participants (room_id, user_id, user_name, status, joined_at) VALUES (?, ?, ?, 'pending', ?)`,
            [room_id, user_id, user_name, Date.now()]
        );

        return Response.json({
            success: true,
            data: { host_id: room.results[0].host_id, host_name: room.results[0].host_name, status: 'pending' }
        }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================
// ৩. অ্যাক্টিভ রুম লিস্ট (অটো ক্লিনআপ সহ)
// ============================================================
export async function handleGetRooms(request, env) {
    try {
        const now = Date.now();
        // ৫ মিনিটের বেশি পুরনো রুম ডিলিট করুন (অটো ক্লিনআপ)
        await run(env,
            `UPDATE p2p_rooms SET is_active = 0 WHERE is_active = 1 AND ? - last_seen > 300000`,
            [now]
        );

        const rooms = await query(env,
            `SELECT r.room_id, r.host_name, COUNT(p.user_id) as members 
             FROM p2p_rooms r 
             LEFT JOIN p2p_participants p ON r.room_id = p.room_id AND p.status = 'approved' 
             WHERE r.is_active = 1 
             GROUP BY r.room_id 
             ORDER BY r.created_at DESC`
        );

        return Response.json({ success: true, data: rooms.results }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================
// ৪. হার্টবিট (হোস্ট অনলাইন রাখে)
// ============================================================
export async function handleHeartbeat(request, env) {
    try {
        const body = await request.json();
        const { room_id, host_id } = body;

        if (!room_id || !host_id) {
            return Response.json({ success: false, error: 'Missing fields' }, { status: 400, headers: corsHeaders });
        }

        const now = Date.now();
        await run(env,
            `UPDATE p2p_rooms SET last_seen = ? WHERE room_id = ? AND host_id = ?`,
            [now, room_id, host_id]
        );

        return Response.json({ success: true }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================
// ৫. রুম ডিলিট (হোস্ট লিভ করলে)
// ============================================================
export async function handleDeleteRoom(request, env) {
    try {
        const body = await request.json();
        const { room_id, host_id } = body;

        if (!room_id || !host_id) {
            return Response.json({ success: false, error: 'Missing fields' }, { status: 400, headers: corsHeaders });
        }

        await run(env, `DELETE FROM p2p_participants WHERE room_id = ?`, [room_id]);
        await run(env, `DELETE FROM p2p_kicks WHERE room_id = ?`, [room_id]);
        await run(env, `DELETE FROM p2p_signals WHERE room_id = ?`, [room_id]);
        await run(env, `DELETE FROM p2p_rooms WHERE room_id = ? AND host_id = ?`, [room_id, host_id]);

        return Response.json({ success: true }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================
// ৬. সিগন্যাল সেভ (HTTP POST)
// ============================================================
export async function handleSaveSignal(request, env) {
    try {
        const body = await request.json();
        const { room_id, from, to, data } = body;

        if (!room_id || !from || !to || !data) {
            return Response.json({ success: false, error: 'Missing fields' }, { status: 400, headers: corsHeaders });
        }

        const now = Date.now();
        await run(env,
            `INSERT INTO p2p_signals (room_id, to_user_id, from_user_id, data, created_at) VALUES (?, ?, ?, ?, ?)`,
            [room_id, to, from, JSON.stringify(data), now]
        );

        // পুরনো সিগন্যাল (৩০ সেকেন্ডের বেশি) ডিলিট করুন
        await run(env,
            `DELETE FROM p2p_signals WHERE created_at < ?`,
            [now - 30000]
        );

        return Response.json({ success: true }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================
// ৭. সিগন্যাল পোল (HTTP GET)
// ============================================================
export async function handleGetSignals(request, env) {
    try {
        const url = new URL(request.url);
        const roomId = url.searchParams.get('room_id');
        const userId = url.searchParams.get('user_id');

        if (!roomId || !userId) {
            return Response.json({ success: false, error: 'Missing room_id or user_id' }, { status: 400, headers: corsHeaders });
        }

        const signals = await query(env,
            `SELECT from_user_id, data FROM p2p_signals WHERE room_id = ? AND to_user_id = ? ORDER BY created_at ASC`,
            [roomId, userId]
        );

        // সিগন্যাল পড়ার পর ডিলিট করুন (একবার পড়া হলে আর দরকার নেই)
        if (signals.results.length > 0) {
            await run(env,
                `DELETE FROM p2p_signals WHERE room_id = ? AND to_user_id = ?`,
                [roomId, userId]
            );
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

// ============================================================
// ৮. অ্যাপ্রুভ ইউজার
// ============================================================
export async function handleApproveUser(request, env) {
    try {
        const body = await request.json();
        const { room_id, host_id, user_id } = body;

        // চেক করুন host_id মিলে কিনা
        const room = await query(env,
            `SELECT host_id FROM p2p_rooms WHERE room_id = ? AND is_active = 1`,
            [room_id]
        );
        if (room.results.length === 0 || room.results[0].host_id !== host_id) {
            return Response.json({ success: false, error: 'Unauthorized' }, { status: 403, headers: corsHeaders });
        }

        await run(env,
            `UPDATE p2p_participants SET status = 'approved' WHERE room_id = ? AND user_id = ?`,
            [room_id, user_id]
        );

        return Response.json({ success: true }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================
// ৯. কিক ইউজার
// ============================================================
export async function handleKickUser(request, env) {
    try {
        const body = await request.json();
        const { room_id, host_id, user_id } = body;

        const room = await query(env,
            `SELECT host_id FROM p2p_rooms WHERE room_id = ? AND is_active = 1`,
            [room_id]
        );
        if (room.results.length === 0 || room.results[0].host_id !== host_id) {
            return Response.json({ success: false, error: 'Unauthorized' }, { status: 403, headers: corsHeaders });
        }

        // কিক টেবিলে যোগ করুন
        await run(env,
            `INSERT OR REPLACE INTO p2p_kicks (room_id, user_id) VALUES (?, ?)`,
            [room_id, user_id]
        );
        // পার্টিসিপ্যান্ট থেকে সরান
        await run(env,
            `DELETE FROM p2p_participants WHERE room_id = ? AND user_id = ?`,
            [room_id, user_id]
        );

        return Response.json({ success: true }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================
// ১০. পার্টিসিপ্যান্ট লিস্ট (হোস্টের জন্য)
// ============================================================
export async function handleGetParticipants(request, env) {
    try {
        const url = new URL(request.url);
        const roomId = url.searchParams.get('room_id');

        if (!roomId) {
            return Response.json({ success: false, error: 'Missing room_id' }, { status: 400, headers: corsHeaders });
        }

        const participants = await query(env,
            `SELECT user_id, user_name, status FROM p2p_participants WHERE room_id = ? ORDER BY joined_at ASC`,
            [roomId]
        );

        return Response.json({ success: true, data: participants.results }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ============================================================
// ১১. WebSocket (ঐচ্ছিক – ডেমোর জন্য HTTP Polling-ই ভালো)
// ============================================================
export async function handleP2PWebSocket(request, env) {
    // ডেমোতে আমরা WebSocket ব্যবহার করছি না – HTTP Polling ব্যবহার করছি
    return new Response('WebSocket not implemented. Use HTTP polling.', { status: 501 });
}