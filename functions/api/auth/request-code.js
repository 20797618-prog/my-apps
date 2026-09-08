// POST /api/auth/request-code  -> 发送登录验证码
import { corsHeaders, json, handleOptions, validEmail, normEmail, safeEqual, randomCode, CODE_TTL, RATE_TTL } from '../../_lib.js';
import { sendCode } from '../../_mail.js';

export async function onRequest(context) {
    const { request, env } = context;
    if (request.method === 'OPTIONS') return handleOptions();
    if (request.method !== 'POST') return json({ error: 'method not allowed' }, 405);

    try {
        const body = await request.json();
        const email = normEmail(body && body.email);
        if (!validEmail(email)) {
            return json({ error: 'invalid_email', message: '邮箱格式不正确' }, 400);
        }

        // 限流：同一邮箱 60 秒内只能发一次
        const last = await env.BOOKMARKS_KV.get('sent:' + email);
        if (last) {
            return json({ error: 'rate_limited', message: '发送太频繁，请 60 秒后再试' }, 429);
        }

        const code = randomCode();
        await env.BOOKMARKS_KV.put('code:' + email, code, { expirationTtl: CODE_TTL });
        await env.BOOKMARKS_KV.put('sent:' + email, '1', { expirationTtl: RATE_TTL });

        const mailEnabled = env.MAIL_ENABLED === 'true' && !!(env.MAIL_PASS && env.MAIL_USER);

        if (mailEnabled) {
            try {
                await sendCode(env, email, code);
                return json({ ok: true, dev: false });
            } catch (e) {
                // 发送失败：清除限流标记，允许重试
                await env.BOOKMARKS_KV.delete('sent:' + email);
                console.error('send mail failed', String(e));
                const detail = String(e && e.message ? e.message : e).slice(0, 160);
                return json({ error: 'mail_failed', message: '邮件发送失败，请稍后重试或检查邮箱', detail }, 500);
            }
        }

        // 开发模式（未配置 SMTP）：直接返回验证码，便于联调
        console.warn('[dev] 邮件未配置，验证码直接返回:', email, code);
        return json({ ok: true, dev: true, code });
    } catch (e) {
        return json({ error: 'bad_request', message: '请求格式错误' }, 400);
    }
}
