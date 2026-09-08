// 简约网站导航 · 共享库（functions 目录下划线前缀文件不生成路由）
// 职责：CORS/JSON/base64、AES-GCM 每用户密钥派生、会话与验证码工具、PBKDF2 密码哈希
// 账号相关键（user/session/code/sent/pwfail）统一存 ACCOUNTS_KV（中央账号库，供未来多应用复用）

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

// ---------- 每用户书签加密密钥：主密钥 ENC_KEY + 邮箱 HKDF 派生 ----------
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

// ---------- 随机数与验证码 ----------
export function randomHex(bytes) {
    const arr = crypto.getRandomValues(new Uint8Array(bytes));
    return [...arr].map(b => b.toString(16).padStart(2, '0')).join('');
}

export function randomCode() {
    return String(Math.floor(100000 + Math.random() * 900000));
}

// ---------- PBKDF2 密码哈希（6 位数字专用，加盐防彩虹表） ----------
// 注意：workerd 上限 100000 次迭代
const PBKDF2_ITER = 100000;

function bufToB64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

export async function hashPassword(password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const hash = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITER },
        key,
        256
    );
    return { s: bufToB64(salt), h: bufToB64(hash), i: PBKDF2_ITER };
}

export async function verifyPassword(password, record) {
    if (!record || !record.s || !record.h) return false;
    const salt = b64ToBytes(record.s);
    const iterations = record.i || PBKDF2_ITER;
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const hash = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
        key,
        256
    );
    return safeEqual(bufToB64(hash), record.h);
}

export function validPassword(pwd) {
    return typeof pwd === 'string' && /^\d{6}$/.test(pwd);
}

// ---------- 会话 ----------
// 从 Authorization: Bearer <token> 解析会话（读中央账号库 ACCOUNTS_KV）
export async function resolveSession(request, env) {
    const auth = request.headers.get('Authorization') || '';
    const m = auth.match(/^Bearer\s+([A-Za-z0-9]+)$/);
    if (!m) return null;
    const token = m[1];
    const raw = await env.ACCOUNTS_KV.get('session:' + token);
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
export const PWD_LOCK_MAX = 5;                   // 密码连续错误上限
export const PWD_LOCK_TTL = 15 * 60;             // 锁定 15 分钟
