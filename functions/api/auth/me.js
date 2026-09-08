// GET /api/auth/me -> 校验当前会话，返回登录用户
import { json, handleOptions, resolveSession } from '../../_lib.js';

export async function onRequest(context) {
    const { request, env } = context;
    if (request.method === 'OPTIONS') return handleOptions();
    if (request.method !== 'GET') return json({ error: 'method not allowed' }, 405);

    const sess = await resolveSession(request, env);
    if (!sess) return json({ error: 'unauthorized' }, 401);

    const raw = await env.BOOKMARKS_KV.get('user:' + sess.email);
    let user = { email: sess.email };
    if (raw) {
        try { user = JSON.parse(raw); } catch (e) {}
    }
    return json({ ok: true, user });
}
