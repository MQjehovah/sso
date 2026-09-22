# Router Token Exchange 设计（2026-09-22）

## 背景与动机

员工端 Dashboard 目前通过 `POST /internal/sso/exchange`（header `X-Internal-Secret` 共享密钥）用 SSO 的
id_token 换一把**长期 sk- 密钥**，用于 LLM 调用与用量查询。共享密钥 `internalSecret` 必须随安装包下发
（`build/enterprise.json` → `%APPDATA%\dashboard\config.json`），任何拿到安装包的人都能提取它调用
router admin 的内部端点（换取自己的网关密钥、查用量）。这是当前最大的凭据暴露面。

目标：把**身份**（查用量/额度）改为 SSO 颁发的 router token 直接鉴权；把**LLM 凭据**从"共享密钥交换"
改为"用户用自己身份自取"。共享密钥从客户端与安装包中彻底消失。

## 现状（证据）

- SSO 仅支持 `authorization_code` + `refresh_token`，`aud` 恒等于发起认证的 client_id；不支持 RFC 8693
  token-exchange，也无 `resource`/`audience` 参数（`sso/src/protocol.ts:78,305`）。客户端全部为机密客户端
  （启动强制非空 secret，`sso/src/clients.ts:59-61`）。
- router gateway 仅认 sk- 密钥：任何 `Authorization: Bearer` 都被当作 sk- 送 admin
  `POST /internal/keys/verify` 做 bcrypt 比对（`router/gateway/src/middleware/auth.ts:36-48`）；gateway
  无任何 JWT 依赖。
- router admin 只认自己签的本地 JWT（`router/admin/src/index.ts:46-59`）；`/internal/*` 以共享密钥保护
  （`router/admin/src/routes/internal.ts:113-116`；`sso.ts:28-31`）。
- dashboard 交换逻辑在 `dashboard/electron/main/identity.ts:182-227`；用量查询在
  `dashboard/electron/main/usage.ts:40-124`（5+ 次 `/internal/*` 调用）。
- admin 已有 SSO JWKS 验签能力：`router/admin/src/oidc.ts:14-73`（discovery 缓存 1h，
  `SSO_JWKS_URI=http://192.168.31.45:8091/.well-known/jwks.json`）。
- 用户模型：`User.employeeId`（唯一，SSO 自动开通标识）、`User.balance`、`balanceResetAt`
  （`router/admin/prisma/schema.prisma:10-28`）；`ApiKey.keyEncrypted` 为"重复发放同一把 key"设计
  （`schema.prisma:83-84`，`admin/src/routes/sso.ts:135-150`）。

## 非目标

- 不改 gateway 鉴权：LLM 调用继续用 sk-（方案 2 留待后续演进）。
- 不改计费模型：仍按 `User.balance` 扣费、`employeeId` 账号月度重置 100 元。
- 不引入 introspection/revocation：沿用 SSO 的离线验签 + 短 TTL 收敛（分钟级）。
- 不动 `/internal/*` 服务间端点（gateway→admin 的 verify/models/resolve/report 照旧）。

## 方案总览

```
Dashboard ──(1) 授权码+PKCE(现状:secret)──> SSO        : 拿到 id_token(aud=dashboard-gateway)
Dashboard ──(2) token-exchange            ──> SSO        : 换到 router token(aud=router, TTL 1h)
Dashboard ──(3) Bearer router token       ──> admin /api/me/usage   : 用量/额度
Dashboard ──(3) Bearer router token       ──> admin /api/me/key     : 取/建默认 sk- key
Dashboard ──(4) Bearer sk- key            ──> gateway /v1/*         : LLM 调用(不变)
```

## ① SSO：token exchange

文件：`sso/src/protocol.ts`（新增 grant 分支 + 处理函数）、`sso/src/clients.ts`（新增可选字段）。

- 请求：`POST /token`，表单：

  | 参数 | 值 |
  |---|---|
  | `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
  | `subject_token` | dashboard 的 id_token 或 access_token |
  | `subject_token_type` | `urn:ietf:params:oauth:token-type:id_token` / `...:access_token`（均接受） |
  | `audience` | `router` |

  客户端认证沿用现有 Basic/form secret（`protocol.ts:273-286`）。

- 校验顺序：
  1. subject_token 为本服务签发、未过期（本地公钥验签 + `iss`）。
  2. subject_token 的 `aud` === 发起交换的 `client_id`（禁止跨客户端换 token）。
  3. `audience` ∈ 该客户端新增字段 `allowed_audiences`（`clients.json`：`dashboard-gateway` →
     `["router"]`）。未配置该字段 = 禁止交换。

- 签发：RS256 access_token，TTL `SSO_EXCHANGE_TTL`（默认 3600s）；
  claims：从 subject_token 复制 `sub/name/dept/roles/email/dingtalk`，`aud=audience`，
  `iss/iat/exp` 新签，`act=client_id`（RFC 8693 actor）；`scope='openid profile'`（保持一致）。
  **不签发 id_token / refresh_token**（客户端重新交换即可）。
- 响应：`{ access_token, issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
  token_type: 'Bearer', expires_in, scope }`。
- 错误：subject_token 无效/过期 → 400 `invalid_grant`；audience 不在白名单 → 400 `invalid_target`；
  客户端未认证 → 401 `invalid_client`。
- 审计：复用 `sso/src/audit.ts` 追加 `action: 'token_exchange'`（记录 client_id/sub/audience，不记 token）。
- `clients.ts` 变更：`OidcClient` 增加可选 `allowed_audiences?: string[]`（30s 热更新自动生效）；
  `clients.example.json` 同步示例。

## ② router admin：SSO token 鉴权 + `/api/me/*`

文件：`router/admin/src/oidc.ts`（抽出通用验签）、`router/admin/src/index.ts`（新装饰器）、
新增 `router/admin/src/routes/me.ts`、`router/admin/src/routes/sso.ts`（把 key find-or-create 抽成可复用函数）。

- `verifySsoToken(token, audience)`：复用现有 JWKS + discovery 缓存，验 `iss`/`aud`/`exp`；
  新 env `SSO_ROUTER_AUDIENCE`（默认 `router`）。
- `fastify.authenticateSso` preHandler：取 `Authorization: Bearer` → `verifySsoToken` → 按
  `sub`（工号）查 `User.employeeId`；查不到 403；挂 `req.ssoUser`。
- 路由（公网走已存在的 `/router/api/` → admin `/api/`）：

  | 路由 | 鉴权 | 行为 |
  |---|---|---|
  | `GET /api/me/usage` | SSO token | 单次返回：今日/本月 `tokensIn/tokensOut/cost`、`balance`、`rateLimit`、按模型分布（≤10 个模型）|
  | `GET /api/me/key` | SSO token | find-or-create 该用户 `name='sso'` 的 ACTIVE key；命中 `keyEncrypted` 直接解密复用，否则轮换 + 返回明文 `{ key, keyId, quota… }` |

- `/api/me/usage` 服务端按 `userId` 聚合（替代客户端传 `keyId`），实现复用现有聚合 SQL 逻辑；
  返回结构与 dashboard `UsageSummary` 对齐，避免客户端 5+ 次请求。
- `/internal/sso/exchange` 保留但不再被 dashboard 调用（公网 404；无调用方，后续可删）。

## ③ dashboard：切到 token + 取 key + 清理

文件：`dashboard/electron/main/identity.ts`、`usage.ts`、`store.ts`、`index.ts`、`electron-builder.yml`、
`build/enterprise.json`（gitignored）。

- `identity.ts`：
  - `exchangeRouterToken()`：`ensureFreshOidc()` 后 `POST {issuer}/token`（token-exchange，
    `audience=router`，client_id/secret 同授权码流程）；单飞（并发合并）。
  - `freshRouterToken()`：`routerTokenExpiresAt - 60s` 内直接返回；过期重新交换。
  - 删除 `exchangeRouterKey` / `ensureRouterKey`。
  - `fetchRouterKey()`：`GET {routerAdminUrl}/api/me/key` + `Bearer freshRouterToken()`；401 时重换 token
    重试一次；结果存 `identity.routerKey`（沿用字段，供 gateway 与本地 agent 使用）。
  - `identity.json` 增加 `routerToken` / `routerTokenExpiresAt`。
- `usage.ts`：`getUsageSummary()` 改为单次 `GET {routerAdminUrl}/api/me/usage`（Bearer token）；
  删除 `X-Internal-Secret` 与多请求拼装。
- 配置清理：`AppConfig` 删除 `internalSecret`（`store.ts` 默认值、`index.ts` seed 字段列表、
  settings store 默认值）；旧 `config.json` 的残留字段忽略不清洗。
- 安装包：`build/enterprise.json` 删除 `internalSecret`；`build/enterprise.example.json` 同步删除。
- 45 nginx：删除 5 个 `/router/internal/*` 放行块，恢复 `location ^~ /router/internal/ { return 404; }`
  单一规则（两处 server 块 + `ai-services.conf` 一处）。

## 数据流与错误处理

- token 交换失败（SSO 不可达 / 客户端配置缺失）：dashboard 保留旧 token 继续用（未过期时）；
  使用侧报错文案"企业认证暂不可用"。
- `/api/me/*` 401（token 过期）：自动重换一次；仍失败则提示重新登录。
- `/api/me/key` 返回的 key 轮换（无 `keyEncrypted` 的历史 key）：`rotated=true` 时覆盖本地缓存，
  旧 key 即时失效（沿用现有语义）。
- admin 按 `sub` 找不到用户（LDAP 新员工尚未 JIT 建号）：403 + 明确文案（引导先登录一次企业账号，
  触发 SSO 侧用户开通流程不变）。

## 测试与验收

- SSO：`test/run-smoke.mjs` 增加 token-exchange 用例（成功 / subject_token 过期 / aud 不符 /
  audience 未授权 / 客户端未认证）；`clients.example.json` 更新。
- router admin：新增单测覆盖 `authenticateSso`（有效/过期/错 aud/未知工号）与两个 `/api/me/*` 路由
  的聚合与 find-or-create 幂等；`npm run test`（Node test runner）全绿。
- dashboard：`usage.ts` 改为单请求后更新既有测试（206 项基线）；`npm run typecheck && npm test`。
- 端到端（真机）：新机器首启 → 企业登录 → Profile 用量显示 → 自动取到 sk- → 对话一次成功 →
  将 `SSO_EXCHANGE_TTL` 临时调成 60s 验证自动重换。

## 部署与回滚

- 顺序：SSO（`45`，增量、不影响现有 grant）→ router admin（`34`，纯新增路由）→ dashboard
  （重打安装包）→ 45 nginx 恢复内部端点 404。
- 回滚：SSO 与 admin 回滚皆可仅还原上一版容器/镜像（`.bak-*` 备份沿用现有约定）；
  dashboard 回滚旧安装包；nginx 配置有 `.bak-ssopx*` 备份。
- 过渡：安装包尚未对外分发，旧客户端兼容不考虑（内部端点直接全 404）。

## 开放项（后续演进）

- 方案 2：gateway 支持 JWT Bearer（客户端不留长期密钥），需解本地 agent 长任务续期与计费归因。
- SSO 支持公共客户端 + PKCE，使安装包不再携带 client_secret。
