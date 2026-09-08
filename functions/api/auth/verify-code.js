// POST /api/auth/verify-code -> 校验验证码，签发会话 token（未注册自动建号）
// 账号数据存中央账号库 ACCOUNTS_KV；返回 hasPassword 供前端引导设置密码
import { json, handleOptions, validEmail, normEmail, safeEqual, randomHex, SESSION_TTL } from '../../_lib.js';

export async function onRequest(context) {
    const { request, env } = context;
    if (request.method === 'OPTIONS') return handleOptions();
    if (request.method !== 'POST') return json({ error: 'method not allowed' }, 405);

    try {
        const body = await request.json();
        const email = normEmail(body && body.email);
        const code = String((body && body.code) || '').trim();
        if (!validEmail(email) || !/^\d{6}$/.test(code)) {
            return json({ error: 'invalid_input', message: '邮箱或验证码格式不正确' }, 400);
        }

        const stored = await env.ACCOUNTS_KV.get('code:' + email);
        if (!stored || !safeEqual(stored, code)) {
            return json({ error: 'bad_code', message: '验证码错误或已过期' }, 401);
        }

        await env.ACCOUNTS_KV.delete('code:' + email);
        await env.ACCOUNTS_KV.delete('sent:' + email);

        // 建号（幂等）：已有用户直接登录
        const existing = await env.ACCOUNTS_KV.get('user:' + email);
        const isNewUser = !existing;
        let user = null;
        if (existing) {
            try { user = JSON.parse(existing); } catch (e) {}
        }
        if (!user || !user.email) {
            user = { email, created_at: new Date().toISOString() };
            await env.ACCOUNTS_KV.put('user:' + email, JSON.stringify(user));
        }

        const token = randomHex(32);
        const exp = Date.now() + SESSION_TTL * 1000;
        await env.ACCOUNTS_KV.put('session:' + token, JSON.stringify({ email, exp }), {
            expirationTtl: SESSION_TTL
        });

        const hasPassword = !!(user.pwd && user.pwd.h);
        return json({ ok: true, token, email, isNewUser, hasPassword });
    } catch (e) {
        return json({ error: 'bad_request', message: '请求格式错误' }, 400);
    }
}
