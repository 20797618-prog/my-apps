# 账号体系 · 新项目接入步骤

> 目标：让你以后开发的每一个新程序，都能用这套账号体系，用户用同一邮箱登录、无需重复注册。
> 全程照做即可，预计 5 分钟。

---

## 第 0 步：前提

- 新程序部署在 **Cloudflare Pages**（和当前「简约网站导航」一样，用 Pages Functions）。
- 你在 Cloudflare 里已登录同一个账号（这样 KV 和 secrets 都在同一账号下，跨项目可绑定）。

---

## 第 1 步：复制后端代码

把资料包里的 `backend/` 目录**整个复制**到新项目的 `functions/` 目录下：

```
新项目/
├── index.html
├── wrangler.jsonc
└── functions/                    ← 复制到这里（若没有 functions 目录就新建）
    ├── _account_lib.js
    ├── _mail.js
    └── api/
        └── auth/
            ├── request-code.js
            ├── verify-code.js
            ├── login-password.js
            ├── set-password.js
            └── me.js
```

> 复制后，新项目会自动获得这些接口：`/api/auth/request-code`、`/api/auth/verify-code`、
> `/api/auth/login-password`、`/api/auth/set-password`、`/api/auth/me`。
> 注意 `_account_lib.js`、`_mail.js` 以 `_` 开头，不会生成路由，是内部共享库。

---

## 第 2 步：绑定中央账号库 KV

打开新项目的 `wrangler.jsonc`，把资料包 `wrangler.snippet.jsonc` 里的 `ACCOUNTS_KV` 绑定合并进去：

```jsonc
{
  "name": "你的新项目",
  "pages_build_output_dir": ".",
  "compatibility_date": "2024-12-01",
  "kv_namespaces": [
    // 账号库（必须用这个固定 id，账号才互通）
    { "binding": "ACCOUNTS_KV", "id": "e8d41d4739e94a80b3f566fc0d549e96" }
    // 下面可以继续加你自己的业务 KV，例如：
    // { "binding": "MY_DATA_KV", "id": "你的业务kv-id" }
  ]
}
```

> ⚠️ **最重要的一步**：`ACCOUNTS_KV` 的 `id` 必须保持 `e8d41d4739e94a80b3f566fc0d549e96` 不变，
> 这正是「多应用共用一套账号」的原因。

---

## 第 3 步：配置环境变量（Secrets）

登录 Cloudflare，进入新项目 → **Settings → Environment variables**，添加以下变量
（值可从「简约网站导航」项目的同位置复制，或参考 `SECRETS.md`）：

| 变量名 | 值（示例） | 说明 |
| --- | --- | --- |
| `MAIL_ENABLED` | `true` | 开启邮件验证码 |
| `MAIL_USER` | 你的发件邮箱 | 如 `123456@qq.com` |
| `MAIL_PASS` | 邮箱授权码 | **敏感**，16 位授权码 |
| `MAIL_PORT` | `465` | 推荐 465（隐式 TLS） |
| `MAIL_FROM_NAME` | 你的应用名 | 会显示在邮件标题里 |

> 若只是本地联调、暂不真实发邮件，把 `MAIL_ENABLED` 设为 `false`，
> 验证码会直接在接口响应里返回（开发模式）。

---

## 第 4 步：前端接入

在新项目的 HTML 里引入前端认证模块，然后调用 `AccountAuth`：

```html
<script src="auth.js"></script>
<script>
    // 1. 发送验证码
    await AccountAuth.requestCode('user@example.com');

    // 2. 校验验证码并登录（成功后自动保存会话 token）
    var r = await AccountAuth.verifyCode('user@example.com', '123456');
    console.log(r.token, r.email, r.hasPassword);

    // 3. 密码登录（用户已设置密码时）
    await AccountAuth.loginPassword('user@example.com', '666888');

    // 4. 设置/修改 6 位数字密码（需已登录）
    await AccountAuth.setPassword('666888');

    // 5. 校验当前会话是否有效
    var me = await AccountAuth.me();
    console.log(me.user.email);
</script>
```

把 `auth.js` 放到你的项目里（如 `frontend/auth.js`），并确认 `AUTH_API_BASE` 默认留空
（同域部署）。若账号中心独立部署，则设置 `window.AUTH_API_BASE = 'https://你的账号中心域名'`。

---

## 第 5 步：验证

1. 本地或部署后，打开新程序，走一遍「发送验证码 → 输入验证码登录」。
2. 用一个**在「简约网站导航」里已经注册过的邮箱**登录，看是否直接成功（无需再注册）——成功即代表账号体系已打通。
3. 再注册一个新邮箱，回到「简约网站导航」用同一邮箱登录，也应能直接进入。

---

## 附：如何保护新程序的业务数据（可选）

账号体系只负责「登录身份」，你的业务数据（如书签、笔记）存在**你自己的 KV** 里。
若想让业务数据也加密存储，可复用 `_account_lib.js` 里现成的 `encryptFor` / `decryptFor`：

```js
import { encryptFor, decryptFor } from '../_account_lib.js';

// 写入（每个用户用自己邮箱派生密钥，info 用你的应用唯一标识）
const cipher = await encryptFor(env, email, { items: [...] }, 'my-app-data-v1');
await env.MY_DATA_KV.put('data:' + email, cipher);

// 读取
const plain = await decryptFor(env, email, cipher, 'my-app-data-v1');
```

> `encryptFor` 需要配置环境变量 `ENC_KEY`（AES 主密钥，见 `SECRETS.md`）。
> 不同应用请用**不同的 info 字符串**，实现密钥隔离。
