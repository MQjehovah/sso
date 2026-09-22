# SSO 忘记密码/重置密码 设计（2026-09-22）

## 背景

员工日常登录 SSO（`auth.xzrobot.com`）使用工号 + 密码或钉钉扫码。目前密码遗忘只能找 IT 人工重置。
本设计新增自助「忘记密码」：**邮箱验证码 + 自助重置密码**，不改动现有登录/改密链路。

## 现状（证据）

- 密码登录：`POST /login/password`（`src/protocol.ts:178-208`）；登录后改密：`GET /profile` +
  `POST /profile/password`（`protocol.ts:487-...`），写路径在 `src/password.ts`（LDAP `userPassword`
  replace / 文件目录 scrypt hash），密码规则集中在 `password.ts:8` 起的校验函数。
- 用户目录：LDAP（生产）`src/directory.ts`；`mail` 属性已映射为 `email`（`directory.ts:62`，
  `LDAP_ATTR_MAIL` 默认 `mail`，生产已配）。文件目录（开发/测试）同结构。
- 会话/凭据作废能力现成：`store.ts` 的 `destroySessionsForSub(sub)`（:102）、
  `revokeRefreshTokens(sub)`（:219）；限流 `ratelimit.ts` 的 `rateLimit(key, limit, windowMs)`（:9）。
- 审计：`src/audit.ts`（`audit.jsonl`），事件名自由传入。
- **无任何邮件发送代码**；依赖仅 `jose` + `ldapts`（`package.json`）。
- 可用 SMTP：`smtp.qiye.aliyun.com:465`（阿里企业邮箱，账号/口令现配在 agent 的发信 MCP 中）。

## 非目标

- 不做管理员代重置/后台入口（YAGNI）。
- 不做短信/钉钉验证码（用户明确要邮件）。
- 不改登录、改密、SSO 协议（token/refresh）行为。
- 不做魔链（客户端预览预取会导致链接失效）。

## 流程与页面

1. 登录页（`render.ts:loginPage`）新增「忘记密码？」链接 → `GET /reset`。
2. `GET /reset` 渲染两步表单页 `resetPage`（无登录态，沿用现有页面风格）：
   - 第一步：输入**工号** → `POST /reset/request`
   - 第二步：输入**验证码 + 新密码 + 确认** → `POST /reset/confirm`
3. `POST /reset/request`：
   - 按工号查目录（LDAP/文件）；**无论是否存在**都返回统一文案「若该工号存在，验证码已发送至其
     企业邮箱」；存在且邮箱非空时生成 6 位数字码、存哈希、发信到该用户官方 `mail`。
   - 工号不存在 / 无邮箱 / 邮件服务未配置 → 统一文案 + 审计，不暴露差异。
4. `POST /reset/confirm`：
   - 校验：码存在且未过期（10 分钟）、哈希匹配、尝试次数 ≤5、单次有效（校验通过即删除记录）。
   - 通过后：按 `password.ts` 写新密码（LDAP/文件目录）→ 作废该 sub 的全部 SSO 会话与
     refresh token（强制重新登录）→ 发「密码已变更」通知邮件 → 审计 → 页面提示成功并回登录页。
   - 失败（码错/过期/尝试超限）→ 同一错误文案「验证码无效或已过期」，审计记录失败原因（服务端）。

## 存储

新增 `<SSO_DATA_DIR>/reset_codes.json`（复用 `store.ts` 的 JSON 持久化风格）：

```
{ "<sub>": { email, codeHash, salt, expiresAt, attempts, sentAt, ip } }
```

- `codeHash`：`scrypt(code, salt)`（不存明文码）。
- 清理：读写时顺手清理 `expiresAt <= now` 的条目；文件权限 0600（沿用数据目录约定）。

## 发信（`src/mailer.ts`）

- 依赖 `nodemailer`（`package.json` 新增；容器构建 `npm ci` 走镜像源）。
- 配置（`src/config.ts`，全部可选）：
  - `SSO_SMTP_HOST`（如 `smtp.qiye.aliyun.com`）、`SSO_SMTP_PORT`（默认 465）、
    `SSO_SMTP_SECURE`（默认 true，465 走 SMTPS）
  - `SSO_SMTP_USERNAME`、`SSO_SMTP_PASSWORD`、`SSO_SMTP_FROM_NAME`（显示名，默认「零号员工」）
  - `SSO_SMTP_FROM`（发件地址，默认 = `SSO_SMTP_USERNAME`）
- `isMailerConfigured()`：缺 host/username/password 即视为未配置 → 自助重置降级提示
  「邮件服务未配置，请联系 IT」，**不影响 SSO 启动**（不加入 `check-strict-config` 强制项）。
- 发送接口：`sendVerificationCode({ to, code })`、`sendPasswordChangedNotice({ to })`；
  失败抛错由调用方转统一文案 + 审计（不把 SMTP 原始错误返回给用户）。
- 测试注入：mailer 以依赖注入方式进入 reset 处理器，smoke/单测用假发信器捕获验证码。

## 防滥用与安全

| 项 | 值/做法 |
|---|---|
| 同工号发送冷却 | 60 秒（`rateLimit('reset:send:'+sub, 1, 60_000)`） |
| 同工号发送上限 | 5 次/小时 |
| 同 IP 发送上限 | 10 次/小时（`reset:ip:<ip>`） |
| 验证码尝试 | ≤5 次，超限作废该记录 |
| 有效期 | 10 分钟（`SSO_RESET_CODE_TTL_SECONDS` 可配，默认 600） |
| 收件人 | 仅 LDAP/目录里该工号的 `mail`，用户不可指定 |
| 枚举防护 | 统一响应文案 + 统一错误文案 |
| 重置后 | 踢全部会话 + 作废全部 refresh token |
| 审计 | `reset_request`（ok/sub/ip，含是否存在/是否发送）、`reset_confirm`（ok/fail 原因/sub/ip） |

## 改动清单

- 新增：`src/mailer.ts`、`src/reset.ts`
- 修改：`src/render.ts`（登录页链接 + `resetPage`）、`src/index.ts`（`GET /reset`、
  `POST /reset/request`、`POST /reset/confirm` 路由）、`src/config.ts`（SMTP/码 TTL 配置）、
  `package.json`/`package-lock.json`（nodemailer）、`README.md`（端点与 env 表）、`.env.example`
- 测试：`test/` 单测（码存储/校验/限流/重置编排，假发信器）+ `test/run-smoke.mjs` 增端到端用例
  （请求 → 假发信器捕获码 → 确认 → 登录旧密码失败/新密码成功 → 会话被踢）

## 部署

- 45：SSO 源码上传 → 重建镜像（`npm ci` 带上 nodemailer）→ 新增 env `SSO_SMTP_*`（从 agent 现有
  阿里邮箱账号迁移，不打印明文）→ 重启容器。
- 验证：`POST /reset/request` 对测试工号返回统一文案；SMTP 返回 messageId（服务端日志/审计）；
  单测与 smoke 覆盖 confirm 全链路；真实收信由管理员抽查一次。

## 风险与回滚

- 风险：邮件被限流/进垃圾箱（企业邮箱发信量小，可接受）；SMTP 口令需与 agent 保持一致，
  否则改密后要同步两处。
- 回滚：还原上一版 `sso:prev-*` 镜像即可（功能入口在登录页链接，回滚即消失）。
