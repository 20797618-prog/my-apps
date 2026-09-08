// POST /api/auth/login-password -> 邮箱 + 6位数字密码登录（密码未设置则提示走验证码）
// 防爆破：同一邮箱连续错误 PWD_LOCK_MAX 次锁定 PWD_LOCK_TTL 秒
import { json, handleOptions, validEmail, normEmail, verifyPassword, validPassword, randomHex, SESSION_TTL, PWD_LOCK_MAX, PWD_LOCK_TTL } from '../../_lib.js';

export async function onRequest(context) {
    const { request, env } = context;
    if (request.method === 'OPTIONS') return handleOptions();
    if (request.method !== 'POST') return json({ error: 'method not allowed' }, 405);

    try {
        const body = await request.json();
        const email = normEmail(body && body.email);
        const password = String((body && body.password) || '');
        if (!validEmail(email) || !validPassword(password)) {
            return json({ error: 'invalid_input', message: '请输入邮箱和 6 位数字密码' }, 400);
        }

        // 是否已锁定
        const lockRaw = await env.ACCOUNTS_KV.get('pwfail:' + email);
        const fails = lockRaw ? parseInt(lockRaw, 10) || 0 : 0;
        if (fails >= PWD_LOCK_MAX) {
            return json({ error: 'locked', message: '错误次数过多已临时锁定，请 15 分钟后再试，或改用验证码登录' }, 429);
        }

        const raw = await env.ACCOUNTS_KV.get('user:' + email);
        let user = null;
        if (raw) { try { user = JSON.parse(raw); } catch (e) {} }
        if (!user || !user.email) {
            return json({ error: 'user_not_found', message: '该邮箱尚未注册，请先用验证码登录' }, 400);
        }
        if (!(user.pwd && user.pwd.h)) {
            return json({ error: 'no_password', message: '该账号尚未设置密码，请先用验证码登录' }, 400);
        }

        const ok = await verifyPassword(password, user.pwd);
        if (!ok) {
            const next = fails + 1;
            await env.ACCOUNTS_KV.put('pwfail:' + email, String(next), { expirationTtl: PWD_LOCK_TTL });
            const remain = PWD_LOCK_MAX - next;
            return json({
                error: 'bad_password',
                message: remain > 0 ? '密码错误，还可尝试 ' + remain + ' 次' : '错误次数过多已临时锁定，请 15 分钟后再试',
                attemptsLeft: Math.max(remain, 0)
            }, 401);
        }

        await env.ACCOUNTS_KV.delete('pwfail:' + email);

        const token = randomHex(32);
        const exp = Date.now() + SESSION_TTL * 1000;
        await env.ACCOUNTS_KV.put('session:' + token, JSON.stringify({ email, exp }), {
            expirationTtl: SESSION_TTL
        });

        return json({ ok: true, token, email, hasPassword: true });
    } catch (e) {
        return json({ error: 'bad_request', message: '请求格式错误' }, 400);
    }
}
