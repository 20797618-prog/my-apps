// GET /api/auth/me -> 校验当前会话，返回登录用户
import { json, handleOptions, resolveSession } from '../../_lib.js';

export async function onRequest(context) {
    const { request, env } = context;
    if (request.method === 'OPTIONS') return handleOptions();
    if (request.method !== 'GET') return json({ error: 'method not allowed' }, 405);

    const sess = await resolveSession(request, env);
    if (!sess) return json({ error: 'unauthorized' }, 401);

    const raw = await env.ACCOUNTS_KV.get('user:' + sess.email);
    let user = { email: sess.email, hasPassword: false };
    if (raw) {
        try {
            const u = JSON.parse(raw);
            user = Object.assign({}, u, { email: u.email || sess.email, hasPassword: !!(u.pwd && u.pwd.h) });
        } catch (e) {}
    }
    return json({ ok: true, user });
}
