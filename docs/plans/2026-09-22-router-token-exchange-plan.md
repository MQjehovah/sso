# Router Token Exchange Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 员工端用 SSO 交换来的 router token 查询用量与获取自己的 sk- key，共享密钥 `internalSecret` 从客户端/安装包中彻底消失。

**Architecture:** SSO 新增 RFC 8693 token-exchange grant（`aud=router`，1h TTL，无 refresh）；router admin 新增 `authenticateSso` 装饰器与 `/api/me/usage`、`/api/me/key` 两个用户态接口（JWKS 离线验签，按 `sub`=工号定位用户）；gateway 不动，LLM 继续用 `/api/me/key` 取到的 sk-。

**Tech Stack:** SSO = Node 22 原生 TS + jose（无框架）；router admin = Fastify + Prisma(PostgreSQL) + jose + Node test runner；dashboard = Electron 主进程 TS + vitest。

**设计文档:** `sso/docs/plans/2026-09-22-router-token-exchange-design.md`

---

## 阶段 A：SSO（先做，增量不影响现有 grant）

### Task 1: 客户端新增 `allowed_audiences` 字段

**Files:**
- Modify: `E:\workspace_ai\sso\src\clients.ts:8-19`
- Modify: `E:\workspace_ai\sso\clients.example.json`

**Step 1: 加字段**

`OidcClient` 接口追加（放在 `refresh_ttl_hours` 之后）：

```ts
  /** 允许本客户端通过 token-exchange 换取的目标受众(如 ["router"]);未配置=禁止交换 */
  allowed_audiences?: string[]
```

**Step 2: 更新示例模板**

`clients.example.json` 的 `dashboard-gateway` 条目录入 `"allowed_audiences": ["router"]`（其它客户端不加）。

**Step 3: 校验语法**

Run: `node --experimental-strip-types --check src/clients.ts`（若 --check 不支持 TS，则跑 `npx tsc --noEmit -p .` 或直接跳到 Task 2 的 smoke 验证）
Expected: 无错误

**Step 4: Commit**

```bash
git add src/clients.ts clients.example.json
git commit -m "feat(sso): 客户端支持 allowed_audiences(为 token exchange 做准备)"
```

---

### Task 2: `/token` 支持 token-exchange grant（测试先行）

**Files:**
- Test: `E:\workspace_ai\sso\test\run-smoke.mjs`（按现有用例风格追加；先读该文件了解 harness/断言方式）
- Modify: `E:\workspace_ai\sso\src\protocol.ts:288-326`（在 refresh_token 分支前插入新分支）

**Step 1: 写失败测试**

在 `test/run-smoke.mjs` 追加 5 个场景（沿用文件内既有的“拿授权码→换 token”辅助流程，先用 `client_id=dashboard-gateway` 拿到 `id_token`，再交换）：

| 场景 | 请求 | 期望 |
|---|---|---|
| 正常交换 | `grant_type=...token-exchange&subject_token=<id_token>&subject_token_type=urn:ietf:params:oauth:token-type:id_token&audience=router` | 200，响应含 `access_token`、`issued_token_type`、`expires_in`；解出的 JWT `aud === 'router'`、`sub === 工号`、`act === 'dashboard-gateway'` |
| audience 未授权 | 同上但 `audience=market` | 400 `invalid_target` |
| subject_token 篡改 | `subject_token` 换成随手字符串 | 400 `invalid_grant` |
| subject_token 受众不符 | 用 `market` 客户端的 id_token 交换 | 400 `invalid_grant` |
| 客户端未认证 | 不带 `client_secret` | 401 `invalid_client` |

Run: `node test/run-smoke.mjs`
Expected: 新用例 FAIL（400 invalid_grant / 未实现分支）

**Step 2: 实现**

`protocol.ts` 顶部确认已导入 `decodeProtectedHeader`、`jwtVerify`、`getPublicKeyFor`（`handleUserinfo` 已在用，`:391-394`）。在客户端认证之后（`:287` 后）、`refresh_token` 分支之前插入：

```ts
  // token-exchange grant(RFC 8693):把本客户端自己的 token 换成目标受众的短期 token
  if (form.get('grant_type') === 'urn:ietf:params:oauth:grant-type:token-exchange') {
    const subjectToken = form.get('subject_token') ?? ''
    const audience = (form.get('audience') ?? '').trim()
    const allowed = client.allowed_audiences ?? []
    if (!subjectToken || !audience) {
      return json(res, 400, { error: 'invalid_request', error_description: '缺少 subject_token 或 audience' })
    }
    if (!allowed.includes(audience)) {
      audit({ event: 'token_exchange', ok: false, client_id: clientId, ip, detail: `audience 未授权: ${audience}` })
      return json(res, 400, { error: 'invalid_target' })
    }

    let payload: import('jose').JWTPayload
    try {
      const header = decodeProtectedHeader(subjectToken)
      const pub = getPublicKeyFor(header.kid)
      if (!pub) throw new Error('unknown kid')
      const verified = await jwtVerify(subjectToken, pub, { issuer: config.issuer, algorithms: ['RS256'] })
      payload = verified.payload
    } catch {
      audit({ event: 'token_exchange', ok: false, client_id: clientId, ip, detail: 'subject_token 无效/过期' })
      return json(res, 400, { error: 'invalid_grant', error_description: 'subject_token 无效或已过期' })
    }
    if (payload.aud !== clientId || !payload.sub) {
      audit({ event: 'token_exchange', ok: false, client_id: clientId, ip, detail: 'subject_token 受众不符' })
      return json(res, 400, { error: 'invalid_grant', error_description: 'subject_token 受众与客户端不符' })
    }

    const configured = Number(process.env.SSO_EXCHANGE_TTL ?? 3600)
    const ttl = Number.isFinite(configured) && configured > 0 ? Math.floor(configured) : 3600
    const now = Math.floor(Date.now() / 1000)
    const { privateKey, kid } = await getSigningKey()
    const accessToken = await new SignJWT({
      scope: 'openid profile',
      dept: payload.dept,
      roles: payload.roles,
      name: payload.name,
      ...(payload.email ? { email: payload.email } : {}),
      ...(payload.dingtalk ? { dingtalk: payload.dingtalk } : {}),
      act: clientId
    })
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuer(config.issuer)
      .setSubject(payload.sub)
      .setAudience(audience)
      .setIssuedAt(now)
      .setExpirationTime(now + ttl)
      .sign(privateKey)

    audit({ event: 'token_exchange', ok: true, sub: payload.sub, client_id: clientId, ip })
    return json(res, 200, {
      access_token: accessToken,
      issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      token_type: 'Bearer',
      expires_in: ttl,
      scope: 'openid profile'
    })
  }
```

**Step 3: 跑测试**

Run: `node test/run-smoke.mjs`
Expected: 全部 PASS（含既有用例）

**Step 4: Commit**

```bash
git add src/protocol.ts test/run-smoke.mjs
git commit -m "feat(sso): /token 支持 RFC 8693 token-exchange(aud=router)"
```

---

### Task 3: 部署 SSO 到 45 并验证

**Files:** 服务器 `192.168.31.45`（`xzrobot`/`xzyz2022!`）

**Step 1: 备份并上传**

按 `sso/docs/plans/2026-09-21-client-sso-login-rollout.md:282-283` 的流程：备份现镜像为 `sso:prev-<ts>`、备份 `src/protocol.ts`/`src/clients.ts`，上传两份改动文件到 SSO 构建目录并重建镜像、重启容器。

**Step 2: 生产 clients.json 加白名单**

容器使用 30 秒热更新：给 `dashboard-gateway` 加 `"allowed_audiences": ["router"]`，`docker cp` 进容器（同步宿主机构建目录），等 30s。

**Step 3: 验证**

1. `curl -s https://auth.xzrobot.com/.well-known/openid-configuration` → 200。
2. 用临时铸 token 脚本 `C:\Users\mqjeh\AppData\Local\Temp\opencode\mint.mjs` 铸一个 `dashboard-gateway` 的 id_token，再：

```bash
curl -s -X POST https://auth.xzrobot.com/token \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  -d "subject_token=<id_token>" -d 'subject_token_type=urn:ietf:params:oauth:token-type:id_token' \
  -d 'audience=router' -d 'client_id=dashboard-gateway' -d 'client_secret=<secret>'
```
Expected: 200 且 JWT 解出 `aud=router`

**Step 4:** 无需提交（服务器操作）

---

## 阶段 B：router admin（纯新增 + 一处重构）

### Task 4: 抽出通用 SSO 验签 `verifySsoToken`

**Files:**
- Modify: `E:\workspace_ai\router\admin\src\oidc.ts:55-73`（保留 `verifyIdToken`，追加新函数）

**Step 1: 实现**

```ts
/// 校验员工端交换来的 router token(签名/iss/aud/exp)；aud 取 SSO_ROUTER_AUDIENCE，默认 router
export async function verifySsoToken(token: string): Promise<JWTPayload> {
  const audience = process.env.SSO_ROUTER_AUDIENCE || 'router';
  if (!isOidcConfigured(audience)) {
    throw new Error('SSO router audience not configured');
  }
  const jwks = await getJwksFetcher();
  const { payload } = await jwtVerify(token, jwks, {
    issuer: process.env.OIDC_ISSUER,
    audience,
    clockTolerance: 30
  });
  return payload;
}
```
（`getJwksFetcher` 已是模块内私有函数，直接复用；`isOidcConfigured(audience)` 支持传参。）

**Step 2: 编译**

Run（在 `E:\workspace_ai\router\admin`）：`npm run build`
Expected: 无 TS 错误

**Step 3: Commit**

```bash
git add src/oidc.ts
git commit -m "feat(admin): 新增 verifySsoToken(校验员工端 router token)"
```

---

### Task 5: 抽出「按用户 find-or-create key」为可复用服务

**Files:**
- Create: `E:\workspace_ai\router\admin\src\services\user-key.ts`（若 `services/` 目录不存在则新建）
- Modify: `E:\workspace_ai\router\admin\src\routes\sso.ts:124-166`（改为调用新服务）

**Step 1: 写单测（先测后改）**

Create: `E:\workspace_ai\router\admin\test\user-key.test.ts`（先读 `admin/test/` 下任一现有用例，沿用其 Prisma mock 方式）。用例：

1. 无 key → 创建，返回 `created=true`、`key` 以 `sk-` 开头、`keyId>0`；
2. 已有带 `keyEncrypted` 的 key → 返回同一把明文 key，`created=false`、不产生新行；
3. 已有无 `keyEncrypted` 的历史 key → 轮换同一行（`rotated=true`），旧 key 哈希被覆盖。

Run: `npm run test`（在 `router/admin`）
Expected: FAIL（模块不存在）

**Step 2: 实现服务**

把 `sso.ts:124-166` 的逻辑原样搬入（含 `SSO_KEY_NAME`、`decrypt/encrypt`、`bcrypt`、`keyVerifyCache.clear()`）：

```ts
export interface EnsureUserKeyOptions {
  rateLimit?: number;
  dailyQuota?: number;
  monthlyQuota?: number;
}

export interface EnsuredUserKey {
  key: string; keyId: number; created: boolean; rotated: boolean;
  rateLimit: number; dailyQuota: number; monthlyQuota: number;
}

export async function ensureUserKey(prisma: PrismaClient, userId: number, opts: EnsureUserKeyOptions = {}): Promise<EnsuredUserKey>
```

`sso.ts` 改为调用它（返回值拼装原有响应字段，保持对外响应不变）。

Run: `npm run test` → 全部 PASS（含既有 32 项）
Run: `npm run build` → 无错

**Step 3: Commit**

```bash
git add src/services/user-key.ts src/routes/sso.ts test/user-key.test.ts
git commit -m "refactor(admin): 抽出 ensureUserKey 服务(sso 交换与 /api/me/key 复用)"
```

---

### Task 6: 新增 `GET /api/me/usage`

**Files:**
- Create: `E:\workspace_ai\router\admin\src\routes\me.ts`
- Modify: `E:\workspace_ai\router\admin\src\index.ts:61-70`（注册 `meRoutes`）

**Step 1: 写失败测试**

Create: `E:\workspace_ai\router\admin\test\me-usage.test.ts`，覆盖：

1. 带有效 router token → 200，响应字段与 dashboard `UsageSummary` 对齐（`balance/rateLimit/quota/today/month/models/truncated/fetchedAt`）；
2. 无 Authorization → 401；
3. token `aud` 错误 → 401；
4. `sub` 在库中不存在用户 → 403。

（构造有效 token：测试内用 jose 生成 RSA 密钥对，起本地 JWKS HTTP 服务，把 `OIDC_ISSUER`/`OIDC_JWKS_URI` 指过去——沿用 admin 现有测试如何注入 env；若现成 harness 不便，可把 `verifySsoToken` 用 `vi.mock`/`mock.module` 替身，重点测路由层聚合与 401/403 分支。）

Run: `npm run test`
Expected: FAIL

**Step 2: 实现路由**

`me.ts`（`preHandler: [fastify.authenticateSso]` 由 Task 7 提供，先按此签名写）：

```ts
import type { FastifyInstance } from 'fastify';

const MAX_MODEL_BREAKDOWN = 10;

export async function meRoutes(fastify: FastifyInstance) {
  fastify.get('/api/me/usage', { preHandler: [fastify.authenticateSso] }, async (req) => {
    // 复用 internal.ts:123-176 的聚合方式, 把 where: { keyId } 换成按 userId 过滤:
    //   - 今日/本月 tokensIn/tokensOut/cost 聚合
    //   - 模型分布: ApiKeyAllowedModel 取授权模型(无授权=全部 ACTIVE), 每模型今日/本月 token
    //   - balance 取 User.balance, rateLimit/quota 取该用户 sso key(ensureUserKey 复用)的字段
    // 返回结构与 dashboard/src/api/types.ts:231-241 的 UsageSummary 完全一致
  });
}
```

`index.ts` 在 `usageRoutes` 之后注册：`await fastify.register(meRoutes);`（import 同风格）。

**Step 3: 跑测试 + 编译**

Run: `npm run test` → PASS；`npm run build` → 无错

**Step 4: Commit**

```bash
git add src/routes/me.ts src/index.ts test/me-usage.test.ts
git commit -m "feat(admin): GET /api/me/usage(router token 鉴权的用量聚合)"
```

---

### Task 7: `authenticateSso` 装饰器

**Files:**
- Modify: `E:\workspace_ai\router\admin\src\index.ts:51-59`

**Step 1: 实现**

在 `fastify.decorate('authenticate', ...)` 之后追加：

```ts
fastify.decorate('authenticateSso', async (req: any, reply: any) => {
  const auth = String(req.headers.authorization ?? '');
  if (!auth.startsWith('Bearer ')) {
    return reply.status(401).send({ error: 'Unauthorized' });
  }
  try {
    const claims = await verifySsoToken(auth.slice(7));
    const employeeId = extractEmployeeId(claims);
    if (!employeeId) return reply.status(403).send({ error: 'Forbidden' });
    const user = await prisma.user.findUnique({ where: { employeeId } });
    if (!user) return reply.status(403).send({ error: 'Forbidden', detail: '用户未开通' });
    req.ssoUser = user;
  } catch {
    return reply.status(401).send({ error: 'Unauthorized' });
  }
});
```

（`verifySsoToken`、`extractEmployeeId` 从 `./oidc.js` 导入——沿用项目 ESM `.js` 后缀风格。）

**Step 2: 编译 + 测试**

Run: `npm run build && npm run test` → 无错、全绿（Task 6 的 401/403 用例此时可真实跑通）

**Step 3: Commit**

```bash
git add src/index.ts
git commit -m "feat(admin): authenticateSso 装饰器(JWKS 验签 + 工号定位用户)"
```

---

### Task 8: 新增 `GET /api/me/key`

**Files:**
- Modify: `E:\workspace_ai\router\admin\src\routes\me.ts`
- Test: `E:\workspace_ai\router\admin\test\me-key.test.ts`

**Step 1: 写失败测试**

1. 首次调用 → 200，返回 `{ key, keyId, created: true, rateLimit, dailyQuota, monthlyQuota }`；
2. 再次调用 → 返回同一把 key（`created: false`）；
3. 未认证 → 401。

Run: `npm run test` → FAIL

**Step 2: 实现**

```ts
  fastify.get('/api/me/key', { preHandler: [fastify.authenticateSso] }, async (req) => {
    const user = (req as any).ssoUser;
    const ensured = await ensureUserKey(fastify.prisma, user.id);
    return { ...ensured, employeeId: user.employeeId, name: user.name, email: user.email };
  });
```

**Step 3: 跑测试 + 编译**

Run: `npm run test && npm run build` → 全绿

**Step 4: Commit**

```bash
git add src/routes/me.ts test/me-key.test.ts
git commit -m "feat(admin): GET /api/me/key(身份自取/自建默认 sk- key)"
```

---

### Task 9: 部署 admin 到 34 并验证

**Step 1:** 备份 `34:/home/xzrobot/ai-gateway/`（沿用 `.bak-*` 约定）→ 上传改动文件（`src/oidc.ts`、`src/index.ts`、`src/routes/me.ts`、`src/services/user-key.ts`、`src/routes/sso.ts`）→ 重建 admin 镜像/重启容器（保持 `.env` 不变；`SSO_ROUTER_AUDIENCE` 默认即 `router`，可不加）。

**Step 2: 验证（用 Task 3 交换到的 router token）**

```bash
curl -s -H "Authorization: Bearer <router_token>" https://ai.xzrobot.com/router/api/me/usage
curl -s -H "Authorization: Bearer <router_token>" https://ai.xzrobot.com/router/api/me/key
```
Expected: 200；`me/key` 返回的 `sk-` 与管理员在控制台看到的该用户 `sso` key 一致；用该 key 调一次 `/router/v1/chat/completions` 成功。

**Step 3:** 服务器操作，无提交

---

## 阶段 C：dashboard（切流 + 清理 + 发版）

### Task 10: identity.ts 换成 token-exchange + `/api/me/key`

**Files:**
- Modify: `E:\workspace_ai\dashboard\electron\main\identity.ts:181-227`（替换 `exchangeRouterKey`/`ensureRouterKey`）
- Modify: `E:\workspace_ai\dashboard\electron\main\identity.ts:27-40`（`Identity` 结构加 `routerToken`/`routerTokenExpiresAt`）
- Modify: `E:\workspace_ai\dashboard\electron\main\identity.ts:303-316`（登录流程改调新函数）

**Step 1: 写失败测试**

在 dashboard 现有测试目录（`npm test` 基线 206 项，先找 `identity` 相关测试文件）补：

1. `freshRouterToken()` 在 token 未过期时不再请求 SSO（fetch spy 调用 0 次）；
2. 快过期（<60s）时先 refresh OIDC 再 exchange，请求体含 `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` 与 `audience=router`；
3. `fetchRouterKey()` 401 时重换 token 并重试一次，成功返回 key 并落盘 `routerKey`。

Run: `npm test`
Expected: FAIL

**Step 2: 实现**

`Identity` 增加 `routerToken?: string`、`routerTokenExpiresAt?: number`。

```ts
const ROUTER_AUDIENCE = 'router'

async function exchangeRouterToken(): Promise<void> {
  const identity = getIdentity()
  if (!identity) throw new Error('请先完成企业 SSO 登录')
  await ensureFreshOidc()
  const idToken = identity.oidc?.idToken
  if (!idToken) throw new Error('当前身份无 SSO 凭据,请退出后重新 SSO 登录')
  const { clientId, clientSecret } = oidcClient()
  const res = await fetch(`${issuer()}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: idToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      audience: ROUTER_AUDIENCE,
      client_id: clientId,
      client_secret: clientSecret
    })
  })
  if (!res.ok) throw new Error(`router token 交换失败(HTTP ${res.status})`)
  const data = (await res.json()) as { access_token?: string; expires_in?: number }
  if (!data.access_token) throw new Error('router token 交换响应缺少 access_token')
  identity.routerToken = data.access_token
  identity.routerTokenExpiresAt = Date.now() + (data.expires_in ?? 3600) * 1000
  saveIdentity(identity)
}

let routerTokenInflight: Promise<void> | null = null
export async function freshRouterToken(): Promise<string> {
  const identity = getIdentity()
  if (!identity) throw new Error('请先完成企业 SSO 登录')
  if (identity.routerToken && (identity.routerTokenExpiresAt ?? 0) - Date.now() > 60_000) {
    return identity.routerToken
  }
  if (!routerTokenInflight) {
    routerTokenInflight = exchangeRouterToken().finally(() => { routerTokenInflight = null })
  }
  await routerTokenInflight
  const token = getIdentity()?.routerToken
  if (!token) throw new Error('router token 获取失败,请重新登录')
  return token
}

async function fetchRouterKey(retry = true): Promise<string> {
  const identity = getIdentity()
  if (!identity) throw new Error('请先完成企业 SSO 登录')
  if (identity.routerKey) return identity.routerKey
  const cfg = getConfig()
  const token = await freshRouterToken()
  const res = await fetch(`${cfg.routerAdminUrl.replace(/\/+$/, '')}/api/me/key`, {
    headers: { Authorization: `Bearer ${token}` }
  })
  if (res.status === 401 && retry) {
    identity.routerTokenExpiresAt = 0
    saveIdentity(identity)
    return fetchRouterKey(false)
  }
  if (!res.ok) throw new Error(`算力网关凭证获取失败(HTTP ${res.status})`)
  const data = (await res.json()) as { key?: string }
  if (!data.key) throw new Error('算力网关凭证响应缺少 key')
  identity.routerKey = data.key
  saveIdentity(identity)
  return data.key
}

export async function ensureRouterKey(): Promise<string> {
  return fetchRouterKey()
}
```

登录流程（`:303-308`）里 `exchangeRouterKey(tokens.id_token)` 改调 `freshRouterToken()`（失败仍降级告警）。

**Step 3: 跑测试**

Run: `npm test && npm run typecheck`
Expected: PASS

**Step 4: Commit**

```bash
git add electron/main/identity.ts tests
git commit -m "feat(dashboard): router 凭证改为 SSO token 交换 + /api/me/key 自取"
```

---

### Task 11: usage.ts 改单请求 + 清理 internalSecret

**Files:**
- Modify: `E:\workspace_ai\dashboard\electron\main\usage.ts:40-125`
- Modify: `E:\workspace_ai\dashboard\electron\main\store.ts`（删 `internalSecret` 默认值与接口字段）
- Modify: `E:\workspace_ai\dashboard\electron\main\index.ts:40-43`（seed 字段列表删 `internalSecret`）
- Modify: `E:\workspace_ai\dashboard\build\enterprise.example.json`（删 internalSecret）

**Step 1: 写失败测试**（沿用现有 usage 测试文件：`makeAdminFetch` 单测改为“Bearer token + 单端点”）

1. `buildUsageSummary` 只发出 1 个请求：`GET /api/me/usage`，且带 `Authorization: Bearer <token>`；
2. 服务端返回的 JSON 原样映射为 `UsageSummary`（含 `fetchedAt` 由本地补）；
3. 401/403 翻译为“请重新登录企业账号”文案。

Run: `npm test` → FAIL

**Step 2: 实现**

```ts
export function makeAdminFetch(
  base: string,
  tokenProvider: () => Promise<string>,
  fetchImpl: typeof fetch = fetch
): (path: string, init?: { method?: string }) => Promise<Record<string, unknown>> { ... }

export async function getUsageSummary(): Promise<UsageSummary> {
  const [{ getConfig }, { getIdentity, freshRouterToken }] = await Promise.all([import('./store'), import('./identity')])
  const identity = getIdentity()
  if (!identity) throw new Error('请先完成企业 SSO 登录')
  const cfg = getConfig()
  const base = (cfg.routerAdminUrl ?? '').replace(/\/+$/, '')
  if (!base) throw new Error('未配置路由管理端地址')
  const res = await fetchImpl(`${base}/api/me/usage`, { headers: { Authorization: `Bearer ${await freshRouterToken()}` } })
  ... // 状态码 → 文案; 响应体 → UsageSummary(fetchedAt: new Date().toISOString())
}
```

删除 `X-Internal-Secret`、`routerKey` 依赖与多请求拼装。

**Step 3: 配置清理**

- `store.ts`：`AppConfig` 删 `internalSecret`；`DEFAULTS`/`normalize` 中相关行删除。
- `index.ts`：seed 字段数组（`:40-43`）删 `'internalSecret'`。
- `enterprise.example.json`：删 `internalSecret`；本机 `build/enterprise.json` 同步删（该文件 gitignored）。

**Step 4: 跑测试 + 类型检查**

Run: `npm test && npm run typecheck && npm run build`
Expected: 206±项 全绿、无 TS 错误

**Step 5: Commit**

```bash
git add electron/main/usage.ts electron/main/store.ts electron/main/index.ts build/enterprise.example.json
git commit -m "refactor(dashboard): 用量改单请求 Bearer token; 移除 internalSecret"
```

---

### Task 12: 45 nginx 内部端点恢复全 404

**Step 1:** 删除 `ai-services.conf` 与 `ai.xzrobot.com.conf` 中所有 `location = /router/internal/...` / `usage/` 放行块（保留单一 `location ^~ /router/internal/ { return 404; }`），`docker exec nginx nginx -t && nginx -s reload`。

**Step 2: 验证**

```bash
curl -s -o /dev/null -w '%{http_code}\n' --resolve ai.xzrobot.com:443:36.154.118.170 \
  https://ai.xzrobot.com/router/internal/sso/exchange   # 期望 404
curl -s -o /dev/null -w '%{http_code}\n' --resolve ai.xzrobot.com:443:36.154.118.170 \
  https://ai.xzrobot.com/router/api/me/usage            # 期望 401(未带 token)
```

**Step 3:** 服务器操作，无提交

---

### Task 13: 重打安装包 + 新机器端到端验证

**Step 1:** `npm run dist:win`（dashboard）

**Step 2: 新机器模拟**（沿用既有手法：备份并移除 `%APPDATA%\dashboard\config.json` → 启动 `win-unpacked\Dashboard.exe` → 断言自动注入的配置**不含** `internalSecret` → 关闭并恢复）

**Step 3: 端到端**

1. 登录企业账号 → Profile 用量正常显示（走 `/api/me/usage`）；
2. 发一条对话 → 成功（内部自动 `/api/me/key` 取 key 后调 gateway）；
3. 把 `SSO_EXCHANGE_TTL` 临时改成 60 → 等 token 过期 → 再查用量/对话 → 自动重换成功；
4. 回滚 TTL 到 3600。

**Step 4: 提交与推送**

```bash
git add -A && git commit -m "chore(dashboard): 发布 0.1.0(router token exchange 版)"  # 如无新增文件则跳过
git push origin HEAD:refs/heads/master   # 双远端
```

---

## 验收清单

- [ ] `/router/internal/*` 公网全 404；`internalSecret` 不在安装包与 config.json 中
- [ ] 用量页数据正确（与 admin 控制台同一用户数据一致）
- [ ] 新装/重装后对话可用，且 key 与该用户 `sso` key 一致
- [ ] token 过期后自动重换（TTL=60s 场景验证）
- [ ] SSO/admin 各自测试全绿；dashboard 测试与 typecheck 全绿
- [ ] 三个仓库提交并双推
