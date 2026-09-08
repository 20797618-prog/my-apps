// POST /api/auth/set-password -> 登录会话内设置/修改 6 位数字密码
// 需 Authorization: Bearer <sessionToken>（先验证码登录拿到会话）
import { json, handleOptions, resolveSession, hashPassword, validPassword } from '../../_lib.js';

export async function onRequest(context) {
    const { request, env } = context;
    if (request.method === 'OPTIONS') return handleOptions();
    if (request.method !== 'POST') return json({ error: 'method not allowed' }, 405);

    const sess = await resolveSession(request, env);
    if (!sess) {
        return json({ error: 'unauthorized', message: '请先登录' }, 401);
    }
    const email = sess.email;

    try {
        const body = await request.json();
        const password = String((body && body.password) || '');
        if (!validPassword(password)) {
            return json({ error: 'invalid_password', message: '密码需为 6 位数字' }, 400);
        }

        const raw = await env.ACCOUNTS_KV.get('user:' + email);
        let user = null;
        if (raw) { try { user = JSON.parse(raw); } catch (e) {} }
        if (!user || !user.email) {
            user = { email, created_at: new Date().toISOString() };
        }

        user.pwd = await hashPassword(password);
        user.pwd_set_at = new Date().toISOString();
        await env.ACCOUNTS_KV.put('user:' + email, JSON.stringify(user));

        return json({ ok: true, hasPassword: true });
    } catch (e) {
        console.error('set-password error', String(e));
        return json({ error: 'bad_request', message: '请求格式错误', detail: String(e && e.message ? e.message : e).slice(0, 160) }, 400);
    }
}
