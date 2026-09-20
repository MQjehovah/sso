# SSO 密钥轮换 / 吊销收紧 / Secret 清理 — 设计

日期：2026-09-20
状态：已确认，待实施

## 背景与问题

自研 SSO（`sso/`，OIDC Provider）是零号员工平台的身份地基，agent / market / rag / router / dashboard 全部依赖它。当前存在三类问题：

1. **密钥无法轮换**：`src/keys.ts` 只有单把 RS256 密钥（`keys/private.pem` + `keys/kid`），JWKS 只返回一把公钥。轮换意味着替换私钥，会立刻废掉验证期内所有 token。
2. **吊销形同虚设**：
   - 登出只销毁会话 + 吊销该 sub 的 refresh token；**已签发的 access_token / id_token 在到期前完全有效**。
   - `handleProfilePassword` 改密后**没有**吊销 refresh token（`src/protocol.ts:428`），改密无法踢下线。
   - access_token 寿命偏长（3600s）。
   - 更关键：agent / rag / market / router 在 SSO 登录成功后会**各自签发本地会话 token 且不再与 SSO 交互**，本地会话 TTL 分别长达 7 天 / 24h / 24h / 未显式设置。因此即使 SSO 侧 token 立即失效，用户仍可凭本地会话长期使用。
3. **密钥泄露**：`clients.json` 中的真实 `client_secret`（具体值已抹除，不再记录于仓库）已被提交，且 GitHub 上的 `MQjehovah/agent|market|rag|router|sso` **5 个仓库全部为 public**。这些密钥已泄露到公网，必须视作已失陷。

## 目标

- 密钥可轮换且**轮换零中断**（旧 token 在验证窗口内继续可验签）。
- 登出 / 改密 / 离职后的失效时间从「最长 7 天」收敛到「**最长 12 小时**」。
- 泄露的 client_secret 全部作废并改为外部注入，仓库内不再出现明文。
- 不改动 OIDC 协议交互方式，不引入 introspect/revoke 端点，不做多实例/DB 化，不重写 git 历史。

## 非目标（YAGNI）

- RFC 7662 introspection / RFC 7009 revocation 端点
- 会话存储 DB 化 / 多副本部署
- 客户端鉴权中间件跨仓库改造
- git 历史清理（旧密钥通过轮换作废）

## 关键约束（现状事实，来自代码）

| 系统 | 登录后会话形态 | 位置 | 现值 |
|---|---|---|---|
| agent | 自签 HS256 JWT | `src/web/server.py:58` | 7 天 |
| rag | 自签 HS256 JWT | `backend/app/config.py:63` | 1440 min |
| market | 自签 JWT | `backend/app/config.py:31` | 1440 min |
| router | fastify.jwt 自签 | `admin/src/auth.ts:31` | 未显式 |
| dashboard | 持有 SSO refresh_token 并自动续期 | `electron/main/identity.ts:102` | refresh 7 天（硬编码 `store.ts`）|

结论：**只有 dashboard 实现 refresh**，其余四个客户端在 SSO 登录后即与 SSO 解耦。因此「吊销」必须同时收紧 SSO token TTL 与各客户端本地会话 TTL，二者取最大值才是实际失效时间。

## 设计

### 1. 密钥环（重新实现 `src/keys.ts`，新增 `src/keyring.ts`）

目录结构（`SSO_KEYS_DIR`）：

```
keys/
  active                # 文本，内容为当前签名 kid
  <kid>.pem             # PKCS8 私钥，权限 0600
  <kid>.meta.json       # { kid, createdAt, status: "active" | "verifying" | "retired" }
```

- **首次启动**：无 `active` 时生成一把 RSA-2048 并置为 active。
- **平滑迁移**：检测到旧布局（`private.pem` + `kid`）时，自动改写为 `<kid>.pem` + `<kid>.meta.json` + `active`，行为对调用方透明。
- **JWKS**：`/.well-known/jwks.json` 返回所有 `active` 与 `verifying` 状态的公钥（`use=sig`、`alg=RS256`），签发始终使用 active 私钥。客户端 JWKS 缓存 300s，轮换后自动收敛。
- **验签**：`/userinfo` 按 token 的 `kid` 在环内查找公钥；找不到即 401。
- **退休窗口**：`SSO_KEY_RETIRE_AFTER_HOURS`（默认 2，覆盖 access token 寿命 + 时钟偏移）。`verifying` 密钥超过窗口由 `key:prune` 转 `retired` 并移出 JWKS。

CLI（新增 `src/cli/keys.ts`，挂到 `package.json` scripts）：

| 命令 | 行为 |
|---|---|
| `npm run key:rotate` | 生成新密钥 → 切 active 指针 → 旧 active 转 verifying |
| `npm run key:list` | 列出 kid / createdAt / status |
| `npm run key:prune` | 将超出退休窗口的 verifying → retired（移出 JWKS） |
| `npm run key:retire <kid>` | 手动将指定 kid 置 retired |

### 2. 吊销收紧

**SSO 侧（`src/config.ts` / `src/protocol.ts` / `src/store.ts`）**

- `access_token` TTL：3600s → **600s**（`SSO_ACCESS_TOKEN_TTL_SECONDS`，可配）
- `id_token` TTL：600s 保持（`SSO_ID_TOKEN_TTL_SECONDS`，可配）
- SSO 会话：保持 8h 滑动（`SSO_SESSION_TTL_HOURS`）
- **修复**：`handleProfilePassword` 改密成功后调用 `revokeRefreshTokens(sub)`，踢掉所有 refresh。
- 登出：保持清会话 + 吊销该 sub 全部 refresh。
- refresh token TTL 改为**每客户端可配**：`clients.json` 新增 `refresh_ttl_hours`（默认 12）。
- **绝对会话上限**：refresh token 记录新增 `auth_time`（首次授权时间），轮换时**继承不重置**；新 refresh 的 `expires_at = auth_time + refresh_ttl_hours`。避免旋转导致 TTL 无限滑动。

**客户端侧（本地会话 TTL → 12h 可配）**

| 系统 | 改动 | 新默认 |
|---|---|---|
| agent | `server.py` `create_jwt` 默认值参数化，env `AGENT_SESSION_TTL_SECONDS` | 43200 |
| rag | `config.py` `jwt_expire_minutes` 默认值 | 720 |
| market | `config.py` `jwt_expire_minutes` 默认值 | 720 |
| router | `admin/src/auth.ts` 的 `fastify.jwt.sign` 加 `expiresIn`，env 可配 | 12h |
| dashboard | 无自签会话；其 refresh TTL 由 SSO 侧 `refresh_ttl_hours` 控制 | 12h |

- 效果：登出/改密/离职后，最迟在 `max(SSO 短 token, 客户端本地会话)` = **12h** 内失效。
- 副作用与缓解：客户端本地会话过期后需重新走 SSO 授权；SSO 会话（8h 滑动）仍在时免密。各前端在收到 401 时跳转 `…/api/auth/sso/start` 完成静默重登。

### 3. Secret 清理与轮换

- `clients.json` 从仓库移除：加入 `.gitignore` 并 `git rm --cached`；保留 `clients.example.json` 作为模板（值全部为占位符）。
- `clients.json` 的 `client_secret` 支持 **`${ENV:VAR}` 占位**（`src/clients.ts` 解析），由部署 env 注入；本地 `clients.json` 权限 0600，不入库。
- **轮换**：为 `agent`、`market`、`rag`、`router`、`dashboard-gateway` 各生成新的 32 字节 base64url 随机 secret，同步写入各部署环境变量与 SSO 的 env；旧值全部作废。
- **移除硬编码兜底**：dashboard `electron/main/identity.ts:98` 的默认硬编码 `client_secret`；实现前逐一核实 rag / market / router 获取 client_secret 的路径并改为纯 env 读取。
- 不做 git 历史重写（轮换后历史值已无效）。

### 4. 测试与 CI

- 新增 SSO 单元测试（`node:test` + `tsx`，当前仅有 smoke 脚本）覆盖：
  - 密钥环：首次生成、轮换后 JWKS 含新旧两把、按 kid 验签、prune 后旧 key 移出
  - `clients.ts` 的 `${ENV:}` 占位展开与缺失变量报错
  - token TTL 断言（access = 配置值）
  - refresh：绝对会话上限不因旋转而延长
- 扩展 `test/run-smoke.mjs`：登出后 refresh 失效；改密后 refresh 失效。
- 新增 `sso/.gitlab-ci.yml`：`npm ci` → `npm run typecheck` → `npm test`。

### 5. 文档

- 新增 `sso/README.md`：架构、环境变量一览、部署、**密钥轮换运维手册**（轮换节奏 / 回滚 / 退休窗口）、secret 管理与泄露处置。
- 补全 `.env.example`：新增 `SSO_ACCESS_TOKEN_TTL_SECONDS`、`SSO_ID_TOKEN_TTL_SECONDS`、`SSO_KEY_RETIRE_AFTER_HOURS`、`SSO_SECRET_*` 等。

## 验收标准

1. `npm run key:rotate` 后，旧 token 在退休窗口内仍可通过 `/userinfo` 验签，新 token 使用新 kid。
2. `/userinfo` 在登出后，refresh 立即失效；改密后 refresh 立即失效。
3. access_token 的 `exp - iat` 等于配置值（默认 600s）。
4. `clients.json` 不在 `git ls-files` 中，仓库内 grep 不到任何真实 client_secret。
5. 5 个客户端本地会话最长 12h（可配），且配置项有默认值与文档。
6. sso 的 `typecheck` 与新增测试在本地通过。

## 风险与回滚

- **密钥环迁移**：旧布局自动迁移，迁移前复制 `keys/` 备份；回滚即恢复备份目录。
- **access TTL 缩短**：仅 dashboard 会自动刷新；其余客户端不受影响（自签本地会话）。
- **secret 轮换**：必须与 5 个客户端部署同步进行，否则会 401。建议先更新 SSO 的 env（同时接受新旧 secret 的过渡期），再逐个切换客户端。
