// 简约网站导航 · 多用户共享库（functions 目录下划线前缀文件不生成路由）
// 功能：CORS / JSON 响应 / base64 / 每用户密钥派生 / AES-GCM / 会话与验证码工具

export function corsHeaders() {
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, PUT, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Auth-Token',
        'Access-Control-Max-Age': '86400'
    };
}

export function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            ...corsHeaders()
        }
    });
}

export function handleOptions() {
    return new Response(null, { status: 204, headers: corsHeaders() });
}

export function b64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
}

export function bytesToB64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

export function safeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const len = Math.max(a.length, b.length);
    let diff = a.length ^ b.length;
    for (let i = 0; i < len; i++) {
        diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
    }
    return diff === 0;
}

export function validEmail(email) {
    return typeof email === 'string' &&
        email.length >= 5 && email.length <= 254 &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export function normEmail(email) {
    return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

// 由主密钥 ENC_KEY + 用户邮箱派生每用户 AES-GCM 密钥
async function deriveKey(env, email) {
    const master = await crypto.subtle.importKey(
        'raw',
        b64ToBytes(env.ENC_KEY),
        { name: 'HKDF' },
        false,
        ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: new TextEncoder().encode(email),
            info: new TextEncoder().encode('nav-bookmarks-v1')
        },
        master,
        256
    );
    return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// 加密：密文中内嵌 email，解密时校验，防止 key 错配
export async function encryptFor(env, email, obj) {
    const key = await deriveKey(env, email);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payload = JSON.stringify({ email, ...obj });
    const enc = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        new TextEncoder().encode(payload)
    );
    return JSON.stringify({ iv: bytesToB64(iv), data: bytesToB64(new Uint8Array(enc)) });
}

export async function decryptFor(env, email, ciphertext) {
    const key = await deriveKey(env, email);
    const { iv, data } = JSON.parse(ciphertext);
    const dec = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64ToBytes(iv) },
        key,
        b64ToBytes(data)
    );
    const parsed = JSON.parse(new TextDecoder().decode(dec));
    if (parsed.email !== email) {
        throw new Error('key mismatch');
    }
    return parsed;
}

export function randomHex(bytes) {
    const arr = crypto.getRandomValues(new Uint8Array(bytes));
    return [...arr].map(b => b.toString(16).padStart(2, '0')).join('');
}

export function randomCode() {
    return String(Math.floor(100000 + Math.random() * 900000));
}

// 从 Authorization: Bearer <token> 解析会话，返回 { token, email } 或 null
export async function resolveSession(request, env) {
    const auth = request.headers.get('Authorization') || '';
    const m = auth.match(/^Bearer\s+([A-Za-z0-9]+)$/);
    if (!m) return null;
    const token = m[1];
    const raw = await env.BOOKMARKS_KV.get('session:' + token);
    if (!raw) return null;
    try {
        const sess = JSON.parse(raw);
        if (!sess.email || (sess.exp && sess.exp < Date.now())) return null;
        return { token, email: sess.email };
    } catch (e) {
        return null;
    }
}

export const SESSION_TTL = 60 * 60 * 24 * 30;   // 30 天
export const CODE_TTL = 10 * 60;                 // 验证码 10 分钟
export const RATE_TTL = 60;                      // 重发间隔 60 秒
