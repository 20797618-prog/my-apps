// 简约网站导航 · 书签数据接口（按登录会话用户隔离）
//   GET /api/bookmarks -> 校验会话 -> 读取 bookmarks:{email} 并解密
//   PUT /api/bookmarks -> 校验会话 -> 加密写入 bookmarks:{email}
// 存储对象：{ bookmarks: [...], categories: { groups: [...], subs: { groupName: [...] } } }
// 分类清单与书签同对象存储，向后兼容老数据（无 categories 字段时返回默认）。
// 鉴权：Authorization: Bearer <sessionToken>
import { json, handleOptions, resolveSession, encryptFor, decryptFor } from '../_lib.js';

const KV_KEY_PREFIX = 'bookmarks:';

function defaultCategories() {
    return { groups: ['默认'], subs: { '默认': [] } };
}

function normalizeCategories(c) {
    if (c && Array.isArray(c.groups) && c.subs && typeof c.subs === 'object') {
        return { groups: c.groups, subs: c.subs };
    }
    return defaultCategories();
}

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
        if (!stored) return json({ bookmarks: [], categories: defaultCategories() });
        try {
            const parsed = await decryptFor(env, email, stored);
            const bookmarks = Array.isArray(parsed.bookmarks) ? parsed.bookmarks : [];
            const categories = normalizeCategories(parsed.categories);
            return json({ bookmarks, categories });
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
            const categories = body.categories ? normalizeCategories(body.categories) : defaultCategories();
            const ciphertext = await encryptFor(env, email, { bookmarks: body.bookmarks, categories });
            await env.BOOKMARKS_KV.put(kvKey, ciphertext);
            return json({ ok: true, count: body.bookmarks.length });
        } catch (e) {
            return json({ error: 'save_failed', message: '保存失败' }, 500);
        }
    }

    return json({ error: 'method not allowed' }, 405);
}
