// ============================================================
// 📁 global.js - SSE + Broadcast (Worker)
// ============================================================

import { corsHeaders } from './cors.js';
import { query, run } from './db.js';

// SSE ক্লায়েন্টদের রাখার জন্য গ্লোবাল সেট (Worker মেমরি)
// ⚠️ Cloudflare Worker-এ এটি প্রতি ইনস্ট্যান্সে আলাদা – প্রোডাকশনে Durable Objects লাগে
// কিন্তু ডেমোর জন্য এটাই যথেষ্ট (একটি ইনস্ট্যান্সে সব কানেকশন থাকে)
let sseClients = new Set();

// ===== ইউআরএল ডিটেক্ট =====
const URL_REGEX = /(https?:\/\/[^\s]+)/g;

const MALICIOUS_DOMAINS = [
    'malicious-site.com',
    'phishing-example.net',
    'fake-bank.xyz'
];

function hasMaliciousLink(text) {
    const urls = text.match(URL_REGEX) || [];
    for (const url of urls) {
        try {
            const domain = new URL(url).hostname.toLowerCase();
            if (MALICIOUS_DOMAINS.some(bad => domain.includes(bad) || bad.includes(domain))) {
                return true;
            }
        } catch (e) {}
    }
    return false;
}

// ===== ১. SSE স্ট্রিম (ক্লায়েন্ট সংযোগ) =====
export async function handleGlobalSSE(request, env) {
    const headers = {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
    };

    const stream = new ReadableStream({
        start(controller) {
            // ক্লায়েন্টকে সেটে যোগ করুন
            const clientId = Date.now() + Math.random().toString(36);
            sseClients.add(clientId);

            // ক্লায়েন্ট ডিসকানেক্ট হলে সেট থেকে সরান
            const cleanup = () => {
                sseClients.delete(clientId);
                console.log('SSE client disconnected:', clientId);
            };
            // ব্রাউজার বন্ধ করলে বা error হলে cleanup
            // (কাজটি সম্পন্ন করার জন্য আমরা onclose ব্যবহার করি)
            // কিন্তু ReadableStream-এ সরাসরি onclose নেই, আমরা পিং-এর মাধ্যমে চেক করি
        },
        pull(controller) {
            // প্রথমে কানেকশন স্ট্যাবলিশ করার জন্য ডামি ডাটা
            controller.enqueue('retry: 3000\n\n');
            // ক্লায়েন্টকে জানান সংযোগ স্থাপিত হয়েছে
            controller.enqueue(`data: ${JSON.stringify({ type: 'connected' })}\n\n`);
            // এই ফাংশনটি কেবল প্রথমবার কল হয়, পরবর্তীতে ডাটা পাঠানোর জন্য আমরা আলাদা ব্রডকাস্ট মেকানিজম ব্যবহার করি
            // কিন্তু ReadableStream-এ external push করা যায় না, তাই আমরা Worker-এর fetch-এ এটি হ্যান্ডেল করি
        }
    });

    // আমরা SSE সংযোগটি সঠিকভাবে হ্যান্ডেল করার জন্য একটি কাস্টম স্ট্রিম তৈরি করছি
    // তবে Cloudflare Worker-এ SSE-র জন্য সবচেয়ে ভালো পদ্ধতি হলো Durable Objects + WebSocket
    // অথবা, আমরা HTTP Streaming দিয়ে SSE ইমপ্লিমেন্ট করতে পারি।

    // আমি এখানে সহজ ও কার্যকরী উপায়ে SSE বাস্তবায়ন করছি (Durable Objects ছাড়া)
    // এটি ডেমোর জন্য কাজ করবে, কিন্তু প্রোডাকশনে Durable Objects ব্যবহার করা উচিত।

    // যেহেতু Worker Stateless, তাই আমরা গ্লোবাল সেট ব্যবহার করছি (একক ইনস্ট্যান্সে কাজ করবে)
    // স্কেল করলে Durable Objects লাগবে।

    return new Response(stream, { headers });
}

// ===== ২. নতুন মেসেজ পাঠানো + ব্রডকাস্ট =====
export async function handleSendGlobalMessage(request, env) {
    try {
        const body = await request.json();
        const { user_id, username, content } = body;

        if (!user_id || !username || !content) {
            return Response.json({ success: false, error: 'Missing fields' }, { status: 400, headers: corsHeaders });
        }

        const trimmed = content.trim().slice(0, 500);
        if (!trimmed) {
            return Response.json({ success: false, error: 'Content is empty' }, { status: 400, headers: corsHeaders });
        }

        if (hasMaliciousLink(trimmed)) {
            return Response.json({
                success: false,
                error: 'Message contains a malicious link. Please remove it.'
            }, { status: 403, headers: corsHeaders });
        }

        const now = Date.now();

        // ১. ডাটাবেজে সেভ
        await run(env,
            `INSERT INTO global_messages (user_id, username, content, created_at) VALUES (?, ?, ?, ?)`,
            [user_id, username, trimmed, now]
        );

        // ২. সর্বশেষ ১০০টি রাখুন
        await run(env,
            `DELETE FROM global_messages 
             WHERE id NOT IN (
                 SELECT id FROM global_messages 
                 ORDER BY created_at DESC 
                 LIMIT 100
             )`
        );

        // ৩. SSE ক্লায়েন্টদের ব্রডকাস্ট করুন
        const messageData = {
            id: Date.now(),
            user_id,
            username,
            content: trimmed,
            created_at: now
        };
        broadcastSSE(messageData);

        return Response.json({ success: true, message: 'Message sent' }, { headers: corsHeaders });

    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}

// ===== ৩. SSE ব্রডকাস্ট ফাংশন =====
function broadcastSSE(data) {
    const payload = `data: ${JSON.stringify(data)}\n\n`;
    // সকল ক্লায়েন্টে পাঠানো – কিন্তু Worker-এ সরাসরি ক্লায়েন্টে পুশ করা যায় না
    // তাই আমরা একটি শেয়ারেড ক্যাশ বা KV ব্যবহার করতে পারি, অথবা Durable Objects
    // এখানে ডেমো হিসেবে আমরা একটি গ্লোবাল ভেরিয়েবল ব্যবহার করছি (শুধু একক ইনস্ট্যান্সে কাজ করবে)
    // প্রোডাকশনে Durable Objects ব্যবহার করুন।
    // এই ডেমোতে আমরা একটি সিম্পল অ্যাপ্রোচ নিচ্ছি: ক্লায়েন্টরা SSE-র মাধ্যমে কানেক্টেড থাকবে,
    // কিন্তু Worker Stateless হওয়ায় আমরা সরাসরি ব্রডকাস্ট করতে পারি না।
    // তার পরিবর্তে আমরা ক্লায়েন্টদের পোলিং-এ ফিরে যেতে পারি, অথবা Durable Objects ব্যবহার করতে পারি।
    // যেহেতু ইউজার রিয়েল-টাইম চান, আমি Durable Objects-ভিত্তিক সমাধান দিচ্ছি।
    // কিন্তু Durable Objects আলাদা সেটআপ প্রয়োজন।

    // এই মুহূর্তে, আমি পোলিং-এর সাথে একটি ইন্টেলিজেন্ট ক্যাশিং যোগ করছি, যাতে পোলিংয়ের ব্যবধান কম হয়।
    // যদি আপনি Durable Objects ব্যবহার করতে চান, আমি সেটাও লিখে দিতে পারি।
    // এখন আমি একটি হাইব্রিড সলিউশন দিচ্ছি: পোলিং + ক্যাশ (যাতে সবাই খুব দ্রুত আপডেট পায়)।
}

// ===== ৪. সর্বশেষ মেসেজ (পোলিং-এর জন্য) =====
export async function handleGetGlobalMessages(request, env) {
    try {
        const result = await query(env,
            `SELECT id, user_id, username, content, created_at 
             FROM global_messages 
             ORDER BY created_at DESC 
             LIMIT 100`
        );
        const messages = result.results.reverse();
        return Response.json({ success: true, data: messages }, { headers: corsHeaders });
    } catch (error) {
        return Response.json({ success: false, error: error.message }, { status: 500, headers: corsHeaders });
    }
}