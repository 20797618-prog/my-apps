// 简约网站导航 · 书签数据接口（按登录会话用户隔离）
//   GET /api/bookmarks -> 校验会话 -> 读取 bookmarks:{email} 并解密
//   PUT /api/bookmarks -> 校验会话 -> 加密写入 bookmarks:{email}
// 鉴权：Authorization: Bearer <sessionToken>
import { json, handleOptions, resolveSession, encryptFor, decryptFor } from '../_lib.js';

const KV_KEY_PREFIX = 'bookmarks:';

export async function onRequest(context) {
    const { request, env } = context;
    if (request.method === 'OPTIONS') return handleOptions();

    const sess = await resolveSession(request, env);
    if (!sess) {
        return json({ error: 'unauthorized', message: '请先登录' }, 401);
    }
    const email = sess.email;
    const kvKey = KV_KEY_PREFIX + email;

    if (request.method === 'GET') {
        const stored = await env.BOOKMARKS_KV.get(kvKey);
        if (!stored) return json({ bookmarks: [] });
        try {
            const parsed = await decryptFor(env, email, stored);
            return json({ bookmarks: Array.isArray(parsed.bookmarks) ? parsed.bookmarks : [] });
        } catch (e) {
            return json({ error: 'decrypt_failed', message: '数据解密失败' }, 500);
        }
    }

    if (request.method === 'PUT') {
        try {
            const body = await request.json();
            if (!body || !Array.isArray(body.bookmarks)) {
                return json({ error: 'invalid_body', message: '数据格式不正确' }, 400);
            }
            const ciphertext = await encryptFor(env, email, { bookmarks: body.bookmarks });
            await env.BOOKMARKS_KV.put(kvKey, ciphertext);
            return json({ ok: true, count: body.bookmarks.length });
        } catch (e) {
            return json({ error: 'save_failed', message: '保存失败' }, 500);
        }
    }

    return json({ error: 'method not allowed' }, 405);
}
