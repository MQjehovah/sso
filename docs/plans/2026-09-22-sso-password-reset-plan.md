# SSO 忘记密码/重置密码 实施计划

> **REQUIRED SUB-SKILL:** superpowers:executing-plans（本会话按 subagent-driven 执行）

**Goal:** SSO 登录页新增自助「忘记密码」：工号 → 企业邮箱收 6 位验证码 → 校验后重置密码，并踢掉该用户全部会话。

**Architecture:** 新增 `src/mailer.ts`（nodemailer，依赖注入可测试）与 `src/reset.ts`（验证码存储 + 请求/确认编排，复用 `password.ts` 写路径、`store.ts` 的会话/refresh 作废、`ratelimit.ts` 限流）；`index.ts` 加 3 条无登录态路由；`render.ts` 加重置页与登录页链接。SMTP 未配置时功能降级但不影响 SSO 启动。

**Tech Stack:** Node 22+ 原生 TS（`--experimental-strip-types`）、jose/ldapts、新增 nodemailer、node:test 单测 + `test/run-smoke.mjs` 冒烟。

**设计文档:** `E:\workspace_ai\sso\docs\plans\2026-09-22-sso-password-reset-design.md`

---

### Task 1: 依赖与配置

**Files:** `package.json`、`package-lock.json`、`src/config.ts`（`:100` exchangeTtlSeconds 之后）、`.env.example`

1. `npm install nodemailer` + `npm install -D @types/nodemailer`（走 npmmirror 源，提交 package.json + lock）。
2. `config.ts` 追加（照 `posIntEnv`/既有风格）：
```ts
  /** 邮件发送(SMTP,可选;未配置时自助重置降级提示,不影响启动) */
  smtp: {
    host: (process.env.SSO_SMTP_HOST ?? '').trim(),
    port: posIntEnv('SSO_SMTP_PORT', 465, 1),
    secure: (process.env.SSO_SMTP_SECURE ?? 'true').trim().toLowerCase() !== 'false',
    username: (process.env.SSO_SMTP_USERNAME ?? '').trim(),
    password: process.env.SSO_SMTP_PASSWORD ?? '',
    fromName: (process.env.SSO_SMTP_FROM_NAME ?? '零号员工').trim(),
    /** 发件地址,默认与登录账号相同 */
    from: (process.env.SSO_SMTP_FROM ?? '').trim()
  },
  /** 自助重置验证码有效期(秒),默认 10 分钟 */
  resetCodeTtlSeconds: posIntEnv('SSO_RESET_CODE_TTL_SECONDS', 600, 60)
```
3. `.env.example` 追加 `SSO_SMTP_*`（注释说明可选）与 `SSO_RESET_CODE_TTL_SECONDS`。
4. Run: `npm run typecheck` → 干净。Commit: `feat(sso): 引入 nodemailer 与重置相关配置`.

### Task 2: `src/mailer.ts`（可注入发信）

**Files:** Create `src/mailer.ts`；Test `test/mailer.test.ts`

接口：
```ts
export interface Mailer {
  isConfigured(): boolean
  sendVerificationCode(input: { to: string; code: string; ttlMinutes: number }): Promise<void>
  sendPasswordChangedNotice(input: { to: string }): Promise<void>
}
export function createMailer(deps?: { cfg?: typeof config; sendMailImpl?: (msg: {...}) => Promise<unknown> }): Mailer
```
- 默认实现用 `nodemailer.createTransport({ host, port, secure, auth: { user, pass } })`。
- **测试捕获钩子**：`process.env.SSO_SMTP_FAKE_CAPTURE` 有值时，不建 transport，而是把 `{ to, subject, text }` 以 JSON 行追加到该文件（供 smoke 用；生产不设）。
- `isConfigured()`：host && username && password 均非空。
- 验证码邮件：主题「【零号员工】密码重置验证码」；正文含 6 位码与 `ttlMinutes` 分钟有效期、以及「非本人操作请忽略」。
- 变更通知：主题「【零号员工】登录密码已变更」。

Test（先写失败用例）：未配置 → `isConfigured()===false` 且 `sendVerificationCode` 抛「邮件服务未配置」；注入 `sendMailImpl` → 断言收件人/主题/正文含 code；FAKE_CAPTURE 落盘含 code。
Run: `npm test`（node:test）。Commit: `feat(sso): mailer(nodemailer, 可注入/可捕获)`.

### Task 3: `src/reset.ts` 验证码存储

**Files:** Create `src/reset.ts`；Test `test/reset-codes.test.ts`

```ts
export type VerifyResult = 'ok' | 'missing' | 'expired' | 'mismatch' | 'too_many'
export interface ResetCodeRecord { sub: string; email: string; codeHash: string; salt: string; expiresAt: number; attempts: number; sentAt: number; ip: string }
export function createResetCodeStore(dir: string, opts?: { now?: () => number; ttlSeconds?: number; maxAttempts?: number }): {
  issue(sub: string, email: string, code: string, ip: string): void
  verifyAndConsume(sub: string, code: string): VerifyResult   // 成功即删除记录(单次有效)
  peek(sub: string): ResetCodeRecord | undefined             // 测试用
}
```
- 存储 `<dir>/reset_codes.json`（0600 权限），读写时清理过期条目；`scrypt(code, salt)` + `timingSafeEqual` 比对。
- 测试：issue→ok 且记录被删；错码 → mismatch 且 attempts+1；错 5 次 → too_many 且记录作废；过期 → expired；不存在 → missing；重启（新 store 实例）仍可校验（持久化）。
Run: `npm test`。Commit: `feat(sso): 重置验证码存储(哈希/TTL/尝试次数)`.

### Task 4: 请求/确认编排

**Files:** `src/reset.ts` 追加；Test `test/reset-flow.test.ts`

```ts
export interface ResetDeps {
  directory: { findByIdentifier(id: string): Promise<DirectoryUser | null> }
  mailer: Mailer
  codes: ReturnType<typeof createResetCodeStore>
  password: PasswordVerifier
  rateLimit: (key: string, limit: number, windowMs: number) => boolean
  now?: () => number
}
/** 统一文案(不泄露账号存在性) */
export const RESET_REQUEST_MESSAGE = '若该工号存在, 验证码已发送至其企业邮箱'
export const RESET_FAIL_MESSAGE = '验证码无效或已过期, 请重新获取'
export async function requestReset(input: { sub: string; ip: string }, deps: ResetDeps): Promise<{ message: string }>
export async function confirmReset(input: { sub: string; code: string; newPassword: string; ip: string }, deps: ResetDeps): Promise<{ ok: true } | { ok: false; message: string }>
```
- requestReset：校验工号非空 → 限流（`reset:send:<sub>` 1/60s + 5/h；`reset:ip:<ip>` 10/h）→ 目录查用户 → 有 email 且 mailer.isConfigured() 才生成 6 位码（`crypto.randomInt(0, 1e6)` 补零）→ `codes.issue` → 发信（失败仅审计）→ 一律返回统一文案；审计 `reset_request`。
- confirmReset：`codes.verifyAndConsume` → 非 ok 返回统一失败文案 + 审计 `reset_confirm(ok=false, reason)`；ok → 目录查用户（没有则统一失败）→ `password.setPassword(user, null, newPassword)`（新密码校验：长度 ≥8）→ 审计成功后由调用方（路由）执行踢会话/通知：为可测这里一并做：
  `destroySessionsForSub`、`revokeRefreshTokens`、`mailer.sendPasswordChangedNotice`（best-effort）→ 审计 `reset_confirm(ok=true)`。

测试（注入假目录/假 mailer/临时目录/可注入 now）：工号不存在 → 统一文案且**未发信**；无 email → 未发信；mailer 未配置 → 未发信；冷却/小时限流 → 第 2 次不发信；确认成功链路 → `setPassword` 收到 `(user, null, 新密码)`、回调用到踢会话与通知、审计 2 条；错码/超次 → 统一失败文案。
Run: `npm test`。Commit: `feat(sso): 重置编排(请求/确认 + 限流 + 踢会话)`.

### Task 5: 路由与页面

**Files:** `src/render.ts`（登录页链接 + `resetPage`）、`src/index.ts`（路由）、`test/run-smoke.mjs`（端到端）

- `render.ts`：`loginPage` 的密码表单下加「忘记密码?」链接 `/reset`；新增
  `resetPage(opts: { step: 1 | 2; sub?: string; notice?: string; error?: string })`：
  - step1：工号输入 + 「发送验证码」按钮（`POST /reset/request`）
  - step2：隐藏域 sub + 验证码 + 新密码 + 确认 + 「重置密码」（`POST /reset/confirm`）
  - 沿用现有页面内联样式风格与错误/提示块。
- `index.ts`：`GET /reset`（step1）、`POST /reset/request`（表单 `sub` → requestReset → step2 + notice）、
  `POST /reset/confirm`（表单 → confirmReset → 成功渲染 loginPage 并带成功提示；失败回 step2 + 错误）。
  依赖装配：模块级单例 `directory/mailer/codes/password/rateLimit`。
- smoke：起服务前设 `SSO_SMTP_FAKE_CAPTURE=<tmp>`，用文件目录用户（含 email）：
  1) `POST /reset/request` → 200 且含统一文案；捕获文件里出现验证码（从 JSON 行提取 6 位码）
  2) `POST /reset/confirm` 用错码 → 失败文案
  3) 用正确码 + 新密码 → 成功；随后旧密码 `POST /login/password` 失败、新密码成功
  4) 无邮箱用户/不存在工号 → 统一文案且捕获文件无新增
Run: `node test/run-smoke.mjs` 全绿。Commit: `feat(sso): /reset 页面与路由(自助重置)`.

### Task 6: 文档与全量校验

**Files:** `README.md`（端点表、env 表）、`.env.example`
- README 增加 `/reset`、`/reset/request`、`/reset/confirm` 说明与 `SSO_SMTP_*`/`SSO_RESET_CODE_TTL_SECONDS`；
- Run: `npm run typecheck && npm test && node test/run-smoke.mjs` 全绿。Commit: `docs(sso): 自助重置端点与 SMTP 配置说明`.

### Task 7: 部署 45 + 验收（控制方执行）

1. 本地 `npm install` 后上传 `src/(mailer|reset|render|index|config).ts`、`package.json`、`package-lock.json` 到 45 新构建目录（基于 `sso-build-token-20260922_160115` 复制）。
2. 迁移 SMTP 凭据：从本机 agent 的 `mcp_servers.json`（服务器上的同款配置）读取 `SMTP_HOST/PORT/USERNAME/PASSWORD/FROM_NAME`，写入 45 的 `/home/xzrobot/apps/sso/env.runtime`（脚本写值不打印）。
3. `docker build -t sso:reset-<ts>` → 备份现镜像 `sso:prev-reset-<ts>` → 重建容器（同上次参数，env-file 用更新后的 env.runtime）。
4. 验证：`GET /reset` 200；`POST /reset/request` 对不存在工号返回统一文案；对真实工号发信 → 审计含 `reset_request ok`（不打印验证码）；真实收信由管理员/用户抽查一次；`POST /reset/confirm` 走 smoke 已验证。
5. 回滚：`docker run` 回 `sso:prev-reset-<ts>`（或上一版 `sso:token-20260922_160115`）。

## 验收清单

- [ ] 登录页出现「忘记密码?」；`/reset` 两步表单可用
- [ ] 统一文案防枚举；无邮箱/未配置 SMTP/限流均不暴露差异
- [ ] 正确码可重置（文件目录 smoke 验证），重置后旧密码失效、新密码可登录
- [ ] 重置成功踢掉该用户全部会话与 refresh token
- [ ] `npm run typecheck`、`npm test`、`node test/run-smoke.mjs` 全绿
- [ ] 45 部署完成：`/reset` 可访问、SMTP 发信成功（审计可见）、回滚镜像已备份
