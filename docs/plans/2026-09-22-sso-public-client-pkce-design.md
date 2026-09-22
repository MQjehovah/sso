# SSO 公共客户端 + PKCE（去安装包 client_secret）设计（2026-09-22）

## 背景

员工端 Dashboard 的 OIDC 登录依赖 `client_secret`，而该 secret 随安装包下发
（`build/enterprise.json` → 用户配置），可被提取。目标：把 `dashboard-gateway` 改为**公共客户端**，
用 **PKCE（S256）** 保护授权码流程，安装包不再包含任何客户端密钥。

## SSO 现状（证据）

- 客户端注册：`src/clients.ts`（`OidcClient`，启动强制每个客户端 `client_secret` 非空，
  `expandSecret` 支持 `${ENV:NAME}`）。
- `/authorize` 已支持可选 PKCE：`code_challenge` + `code_challenge_method=S256`
  （`src/protocol.ts:160-165`），并在 `/token` 校验 `code_verifier`（`:504-511`）。
- `/token` 客户端认证：`safeEqual(client.client_secret, clientSecret)`（`:283-286`），
  之后分派 refresh / code / token-exchange 三种 grant。
- `scripts/check-strict-config.mjs` 校验 `clients.json` 的 secret 占位符。

## 设计

### SSO（向后兼容；机密客户端行为完全不变）

1. `OidcClient` 新增可选 `public?: boolean`；`loadClients()`：
   - `public === true` → **不要求** `client_secret`（有值也不解析，避免误用）；
   - 否则维持现状（缺失/空串即启动失败）。
2. `/authorize`：`client.public === true` 时**必须**带 `code_challenge`
   （且 method 必须 S256，现有校验复用）→ 否则 400 `invalid_request`。
3. `/token` 客户端认证：
   - `client.public === true` → 跳过 secret 校验（仅凭 `client_id` 识别客户端）；
   - 其余客户端不变（Basic/form secret）。
4. `authorization_code` 分支：`client.public === true` 且授权码记录无 `code_challenge`
   → 400 `invalid_grant`（纵深防御；正常路径已被 2 拦截）。
5. `refresh_token` 与 `token-exchange`：对公共客户端同样开放（除 secret 校验外逻辑不变：
   `allowed_audiences` 白名单、subject_token `aud === client_id` 均保留）。
6. `clients.example.json`：`dashboard-gateway` 标 `"public": true` 且不带 secret；其它保持
   `${ENV:...}`。`check-strict-config.mjs` 跳过公共客户端的 secret 校验。
7. README：客户端字段与 PKCE 说明。

### Dashboard（员工端）

- 登录（`startSsoLogin`）：生成 `code_verifier`（`randomBytes(32)` base64url，43 字符），
  authorize URL 带 `code_challenge`（S256）+ `code_challenge_method=S256`；verifier 存内存，
  回环回调换 token 时带 `code_verifier`。
- 所有 token 请求（code 换 token、refresh、token-exchange）：**`client_secret` 仅在配置了非空值时携带**
  （兼容机密部署），否则不带。
- 安装包模板 `build/enterprise.json` / `enterprise.example.json` 移除 `oidcClientSecret`；
  `AppConfig` 保留该可选字段（兼容手工配置的机密客户端）。
- 重打安装包。

## 切换顺序与兼容

1. SSO 代码上线（公共支持 + 机密兼容；**此时无人受影响**）。
2. Dashboard 新版本上线（总是带 PKCE；有 secret 则带，没有则不带）——新旧 SSO 均可工作。
3. 生产 `clients.json` 把 `dashboard-gateway` 改为 `"public": true` 并去掉 secret 引用
   （30 秒热更新）。**此后旧版 dashboard（无 PKCE）登录会被拒**；当前安装包未分发，风险可控；
   若已分发需先升级。
4. 新安装包分发（不含 secret）。

回滚：clients.json 改回机密 + 恢复 secret 引用即可（SSO 代码双向兼容）；SSO 镜像亦可回滚
`sso:prev-pkce-*`。

## 测试

- SSO 单测：`clients.ts` 公共客户端允许空 secret、非 public 仍强制。
- SSO smoke：fixture 增公共客户端（如 `test-public`）——
  authorize 无 challenge → 400；带 S256 challenge → 正常登录换 code；
  `/token` 不带 secret + 正确 verifier → 200；缺/错 verifier → 400；
  refresh_token（不带 secret）→ 200；token-exchange（公共）→ 200（audience 白名单内）。
- Dashboard 单测：authorize URL 含 `code_challenge(S256)`；token 请求带 `code_verifier`、
  无 secret（未配置时）；配置了 secret 时仍携带（兼容）；refresh/exchange 不带 secret。
- 全量：SSO `npm run typecheck && npm test && node test/run-smoke.mjs`；
  Dashboard `npm run typecheck && npm test && npm run build`。
