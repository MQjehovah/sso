# SSO 会话确认页（换账号）设计（2026-09-22）

## 背景

`/authorize` 检测到 SSO 会话时**静默签发 code**（`src/protocol.ts:168-173`），没有换账号入口；
业务系统「退出登录」只清本地凭据，SSO 会话 Cookie 仍在，重新登录仍是同一账号。
需求：**每次登录都显示确认页**，用户可选择「继续以该账号登录」或「使用其他账号」。

## 现状（证据）

- `handleAuthorize`：`session = getSession(cookies['sso_sid'])`，存在即 `issueCodeRedirect`（静默）。
- `takeTx` 只做 TTL 校验、**不删除** tx（`src/store.ts:239-247`），`finishTx` 才删除；`issueCode`
  在签发 code 时消费 tx。→ 确认页渲染与后续 POST 可共用同一 tx。
- CSRF：`issueCsrf(txId)` / `verifyCsrf(txId, token)`（`src/csrf.ts`），登录表单即用此模式
  （`protocol.ts:227`）。
- `destroySession(sid)` + `clearCookie()`（logout 在用，`protocol.ts:507,516`）；
  `GET /logout` 会额外 revoke 该账号 refresh token —— 换账号**不应** revoke（否则把该账号在
  其他业务系统的登录也踢了）。

## 设计

**`/authorize`**（`handleAuthorize`）：
- 有会话 且 `prompt=login` → 跳过确认页，302 `/login?tx=<id>&tab=qr`（标准语义，客户端可强制重登）
- 有会话 → 渲染**会话确认页**（不再静默发码）
- 无会话 → 现状不变（302 登录页）

**确认页**（`render.ts` 新增 `sessionConfirmPage`，沿用卡片风格）：
```
已登录为  季明清
工号 202202100024 · 平台组
[ 继续以该账号登录 ]   [ 使用其他账号 ]
```
- 「继续」`POST /authorize/continue`：表单 `tx` + `csrf`（`issueCsrf(tx.id)`）
- 「使用其他账号」`POST /authorize/switch`：表单 `tx` + `csrf`
- 两表单都带隐藏 `tx`（tx 不被渲染消费）

**`POST /authorize/continue`**：校验 tx 存在 + `verifyCsrf(txId, csrf)` → 取当前会话（无会话则回
登录页）→ `issueCodeRedirect(res, tx, session)`（与原静默路径完全等价）。

**`POST /authorize/switch`**：校验 tx + CSRF → `destroySession(cookies['sso_sid'])` + `clearCookie()`
→ 302 `/login?tx=<id>&tab=qr`。**不 revoke refresh token**（只退出 SSO 会话，不影响该账号在其他
业务系统的登录态）；审计 `event: 'session_switch'`。

**失败路径**：tx 缺失/过期 → `messagePage('登录请求已过期', ...)`（同登录页现有文案）；
CSRF 失败 → 400「请求已过期，请重新打开登录页」。

**兼容**：无会话流程、钉钉扫码、密码登录、`/reset`、`/logout` 行为均不变；dashboard 无需改动
（员工端退出后重新登录即见确认页，一键换号）。

## 测试

- smoke（`test/run-smoke.mjs`）：
  1. 完成一次密码登录（获得 `sso_sid`）后，对新的 `/authorize` 请求 → 返回确认页 HTML（含
     「已登录为」「继续以该账号登录」「使用其他账号」），且**无 302 Location**；
  2. 从确认页提取 tx 与 csrf → `POST /authorize/continue` → 302 且 Location 带 `code=`；
     该 code 可正常换 token（沿用既有断言方式）；
  3. 另起一轮：`POST /authorize/switch` → 302 到 `/login?tx=...`；随后带旧 Cookie 再访问
     `/authorize` → 应回登录页（302），证明会话已清；
  4. CSRF 错/缺失 → 400；`prompt=login` → 302 登录页（不渲染确认页）。
- 单测：`render.ts` 的 `sessionConfirmPage` 输出包含必要元素与转义（XSS：name/dept 注入）。
- 全量：`npm run typecheck`、`npm test`、`node test/run-smoke.mjs` 全绿。

## 部署

45：复制现构建目录 → 上传 `src/render.ts`、`src/protocol.ts`、`src/index.ts`（可能含 `src/store.ts`
如无改动则不动）→ 重建镜像 `sso:confirm-<ts>` → 备份旧镜像/容器 → 切换 → 公网验证
（带会话访问 authorize 见确认页；continue/switch 正常）。回滚同既有方式。
