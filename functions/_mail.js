// 验证码邮件发送：QQ 邮箱 SMTP（465 隐式 TLS / 587 STARTTLS）
// 通过 Workers TCP socket (cloudflare:sockets) 实现最小 SMTP 客户端
// 未配置 MAIL_PASS / MAIL_ENABLED!=='true' 时由调用方走开发模式

import { connect } from 'cloudflare:sockets';

function b64utf8(str) {
    // UTF-8 安全的 base64
    const bytes = new TextEncoder().encode(str);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

function wrapB64(b64, width = 76) {
    const out = [];
    for (let i = 0; i < b64.length; i += width) out.push(b64.slice(i, i + width));
    return out.join('\r\n');
}

function encodeWord(str) {
    return '=?UTF-8?B?' + b64utf8(str) + '?=';
}

async function readLine(reader, buf) {
    while (buf.s.indexOf('\r\n') === -1) {
        const { value, done } = await reader.read();
        if (done) break;
        buf.s += new TextDecoder().decode(value);
    }
    const idx = buf.s.indexOf('\r\n');
    if (idx === -1) return { line: buf.s, closed: true };
    const line = buf.s.slice(0, idx);
    buf.s = buf.s.slice(idx + 2);
    return { line, closed: false };
}

async function readResponse(reader, buf) {
    let lastCode = 0;
    for (;;) {
        const { line, closed } = await readLine(reader, buf);
        if (closed) break;
        if (line.length >= 3 && /^\d{3}/.test(line)) lastCode = parseInt(line.slice(0, 3), 10);
        if (line.length > 3 && line[3] === ' ') break; // 最后一行
    }
    return lastCode;
}

async function cmd(writer, str) {
    await writer.write(new TextEncoder().encode(str + '\r\n'));
}

function withTimeout(promise, ms, label) {
    let timer;
    const t = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(label + ' 超时')), ms);
    });
    return Promise.race([promise, t]).finally(() => clearTimeout(timer));
}

export async function sendCode(env, to, code) {
    const host = env.MAIL_HOST || 'smtp.qq.com';
    const port = parseInt(env.MAIL_PORT || '465', 10);
    const user = env.MAIL_USER || '';
    const pass = env.MAIL_PASS || '';
    const fromAddr = env.MAIL_FROM || user;
    const fromName = env.MAIL_FROM_NAME || '简约网站导航';

    if (!user || !pass) throw new Error('SMTP 未配置');

    const isStartTls = port === 587; // 587=STARTTLS(明文先握手)；465=隐式TLS
    // connect(address, options)：secureTransport 必须放在第二个参数，否则不生效
    const socket = connect(
        { hostname: host, port },
        { secureTransport: isStartTls ? 'starttls' : 'on' }
    );
    await withTimeout(socket.opened, 15000, 'TCP/TLS 连接');

    const buf = { s: '' };
    // startTls() 会返回新的 TLS Socket，之后需操作新 socket 的流
    let writer = socket.writable.getWriter();
    let reader = socket.readable.getReader();
    let closed = socket;

    try {
        // 首条问候
        const greet = await withTimeout(readResponse(reader, buf), 15000, '读取问候');
        if (greet !== 220) {
            throw new Error('SMTP 连接失败(greet=' + greet + ', recv="' + buf.s.slice(0, 120).replace(/\r|\n/g, ' ') + '")');
        }

        await withTimeout(cmd(writer, 'EHLO nav.pages.dev'), 10000, 'EHLO');
        await withTimeout(readResponse(reader, buf), 10000, 'EHLO响应');

        if (isStartTls) {
            await withTimeout(cmd(writer, 'STARTTLS'), 10000, 'STARTTLS');
            const st = await withTimeout(readResponse(reader, buf), 10000, 'STARTTLS响应');
            if (st !== 220) throw new Error('STARTTLS 被拒(code ' + st + ')');
            const tls = await withTimeout(socket.startTls(), 15000, 'TLS 升级');
            // 切换到 TLS socket 的新流
            try { await writer.close(); } catch (e) {}
            closed = tls;
            writer = tls.writable.getWriter();
            reader = tls.readable.getReader();
            buf.s = '';
            await withTimeout(cmd(writer, 'EHLO nav.pages.dev'), 10000, 'EHLO(2)');
            await withTimeout(readResponse(reader, buf), 10000, 'EHLO响应(2)');
        }

        await withTimeout(cmd(writer, 'AUTH PLAIN ' + b64utf8('\u0000' + user + '\u0000' + pass)), 10000, 'AUTH');
        const authCode = await withTimeout(readResponse(reader, buf), 15000, 'AUTH响应');
        if (authCode !== 235) throw new Error('SMTP 认证失败(code ' + authCode + ')');

        await withTimeout(cmd(writer, 'MAIL FROM:<' + fromAddr + '>'), 10000, 'MAIL FROM');
        if (await withTimeout(readResponse(reader, buf), 10000, 'MAIL FROM响应') !== 250) throw new Error('MAIL FROM 被拒');

        await withTimeout(cmd(writer, 'RCPT TO:<' + to + '>'), 10000, 'RCPT TO');
        if (await withTimeout(readResponse(reader, buf), 10000, 'RCPT TO响应') !== 250) throw new Error('RCPT TO 被拒');

        await withTimeout(cmd(writer, 'DATA'), 10000, 'DATA');
        if (await withTimeout(readResponse(reader, buf), 10000, 'DATA响应') !== 354) throw new Error('DATA 被拒');

        const subject = '【简约网站导航】您的登录验证码：' + code;
        const text = '您的登录验证码是：' + code + '\r\n验证码 10 分钟内有效。若非本人操作请忽略本邮件。';
        const headers =
            'From: ' + encodeWord(fromName) + ' <' + fromAddr + '>\r\n' +
            'To: <' + to + '>\r\n' +
            'Subject: ' + encodeWord(subject) + '\r\n' +
            'Date: ' + new Date().toUTCString() + '\r\n' +
            'MIME-Version: 1.0\r\n' +
            'Content-Type: text/plain; charset=UTF-8\r\n' +
            'Content-Transfer-Encoding: base64\r\n' +
            '\r\n' +
            wrapB64(b64utf8(text)) + '\r\n.\r\n';

        await withTimeout(writer.write(new TextEncoder().encode(headers)), 15000, '写入邮件');
        if (await withTimeout(readResponse(reader, buf), 20000, '发送响应') !== 250) throw new Error('发送被拒');

        await cmd(writer, 'QUIT').catch(() => {});
        return { ok: true };
    } finally {
        try { await writer.close(); } catch (e) {}
        try { socket.close(); } catch (e) {}
        if (closed !== socket) { try { closed.close(); } catch (e) {} }
    }
}
