# 账号体系 · 环境变量（Secrets）配置清单

> 账号体系需要配置的环境变量。这些值属于**敏感信息**，应配置在
> Cloudflare Pages/Worker 的 **Settings → Environment variables**（或用 `wrangler secret put`），
> **不要写进代码、不要提交到公开仓库**。

新项目接入时，请登录 Cloudflare，到当前项目（如「简约网站导航」my-apps）的
**Settings → Environment variables** 里查看现有值，再复制到新项目即可。

## 一、账号认证必需

| 变量名 | 用途 | 格式/示例 | 是否敏感 |
| --- | --- | --- | --- |
| `MAIL_ENABLED` | 是否启用邮件验证码 | `"true"`（填 `"false"` 则进入开发模式，验证码直接返回，不真实发邮件） | 否 |
| `MAIL_USER` | 发件邮箱账号 | 你的 QQ 邮箱，如 `123456@qq.com` | 否 |
| `MAIL_PASS` | 发件邮箱授权码 | QQ 邮箱「授权码」（16 位，非登录密码） | **是** |
| `MAIL_PORT` | SMTP 端口 | `465`（推荐，隐式 TLS）或 `587`（STARTTLS） | 否 |
| `MAIL_HOST` | SMTP 服务器 | 默认 `smtp.qq.com`（可省略） | 否 |
| `MAIL_FROM` | 发件地址 | 默认等于 `MAIL_USER`（可省略） | 否 |
| `MAIL_FROM_NAME` | 发件人显示名（会出现在邮件标题/发件人里） | 你的应用名，如 `我的导航` | 否 |

## 二、业务数据加密（可选）

> 仅当你的新应用需要「加密存储业务数据」时才需要（参考 `_account_lib.js` 里的
> `encryptFor` / `decryptFor`）。纯登录认证**不需要**此项。

| 变量名 | 用途 | 格式/示例 | 是否敏感 |
| --- | --- | --- | --- |
| `ENC_KEY` | AES 主密钥（base64，32 字节），用于派生每用户加密密钥 | 32 字节随机值的 base64，形如 `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`（**这是占位示例，请从 Cloudflare 面板复制真实值**） | **是** |

## 三、安全提醒

1. **`MAIL_PASS`、`ENC_KEY` 是核心敏感信息**，一旦泄露，别人可冒用你的邮箱发信、或解密业务数据。
   请只在 Cloudflare 面板里配置，不要把真实值写进任何会提交到 Git 的文件。
2. 本资料包（`account-system/`）可被复制到多个项目，复制时**不会**自动携带 secrets，
   secrets 需在每个新项目里单独配置（这正是 Cloudflare 环境变量与代码分离的好处）。
3. 若怀疑授权码泄露，请到 QQ 邮箱 → 设置 → 账户 里**重新生成授权码**，并同步更新所有项目的 `MAIL_PASS`。
