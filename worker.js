// Cloudflare Worker：简约网站导航 数据后端
// 接口：
//   GET  /api/bookmarks  -> 校验口令 -> 从 KV 解密 -> 返回 { bookmarks: [...] }
//   PUT  /api/bookmarks  -> 校验口令 -> AES-GCM 加密 -> 写入 KV
// 鉴权：请求头 X-Auth-Token = sha256(口令) 的 hex 字符串
// 加密：AES-GCM 256，密钥来自 secret ENC_KEY；数据以 JSON { iv, data } 存 KV

const KV_KEY = 'bookmarks';

function corsHeaders() {
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, X-Auth-Token',
        'Access-Control-Max-Age': '86400'
    };
}

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            ...corsHeaders()
        }
    });
}

// 定时安全的字符串比较，避免时序攻击
function safeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const len = Math.max(a.length, b.length);
    let diff = a.length ^ b.length;
    for (let i = 0; i < len; i++) {
        diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
    }
    return diff === 0;
}

function b64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
}

function bytesToB64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

async function getEncKey(env) {
    const raw = b64ToBytes(env.ENC_KEY);
    return crypto.subtle.importKey(
        'raw',
        raw,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encrypt(env, plaintext) {
    const key = await getEncKey(env);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        new TextEncoder().encode(plaintext)
    );
    return JSON.stringify({
        iv: bytesToB64(iv),
        data: bytesToB64(new Uint8Array(enc))
    });
}

async function decrypt(env, payload) {
    const key = await getEncKey(env);
    const { iv, data } = JSON.parse(payload);
    const dec = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64ToBytes(iv) },
        key,
        b64ToBytes(data)
    );
    return new TextDecoder().decode(dec);
}

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        if (request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: corsHeaders() });
        }

        if (url.pathname !== '/api/bookmarks') {
            return jsonResponse({ error: 'not found' }, 404);
        }

        // 鉴权：前端已把口令做 sha256，直接比对 secret AUTH_HASH
        const token = request.headers.get('X-Auth-Token') || '';
        if (!safeEqual(token, env.AUTH_HASH)) {
            return jsonResponse({ error: 'unauthorized' }, 401);
        }

        if (request.method === 'GET') {
            const stored = await env.BOOKMARKS_KV.get(KV_KEY);
            if (!stored) {
                return jsonResponse({ bookmarks: [] });
            }
            try {
                const plain = await decrypt(env, stored);
                return jsonResponse(JSON.parse(plain));
            } catch (e) {
                return jsonResponse({ error: 'decrypt failed' }, 500);
            }
        }

        if (request.method === 'PUT') {
            try {
                const body = await request.json();
                if (!body || !Array.isArray(body.bookmarks)) {
                    return jsonResponse({ error: 'invalid body' }, 400);
                }
                const ciphertext = await encrypt(env, JSON.stringify(body));
                await env.BOOKMARKS_KV.put(KV_KEY, ciphertext);
                return jsonResponse({ ok: true, count: body.bookmarks.length });
            } catch (e) {
                return jsonResponse({ error: 'save failed' }, 500);
            }
        }

        return jsonResponse({ error: 'method not allowed' }, 405);
    }
};
