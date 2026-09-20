# sso — 自研统一认证服务

## 项目定位

本仓库是公司内部的 OIDC Provider(OpenID Connect 认证中心),基于 Node.js 原生 HTTP 实现,不依赖任何 Web 框架。它实现授权码模式(Authorization Code)+ PKCE S256,提供钉钉扫码与 LDAP(或开发/烟测用的文件目录)账号密码两种登录通道,统一为 agent(零号员工)、market(能力市场)、rag(企业知识库)、router(算力网关控制台)、dashboard(员工 AI 工作台)提供单点登录与身份令牌。签名采用 RS256 密钥环(active 签发、verifying 继续验签),客户端密钥由环境变量注入。

## 快速开始

```bash
npm ci
cp .env.example .env   # Windows: Copy-Item .env.example .env
# 编辑 .env,至少填写 SSO_ISSUER;启用扫码时填 DINGTALK_*;使用 LDAP 时填 LDAP_*
npm start
```

- **Node 版本要求**:Node ≥ 22.18 原生支持类型擦除(`type stripping`),可直接运行 `.ts`;在更早的 22.x 上,`npm` 脚本内置的 `--experimental-strip-types` 标志是必需的。脚本已统一带上该标志,在 ≥ 22.18 上为无害的空操作,请勿自行增删其它标志。
- 默认监听 `SSO_PORT`(8091),启动时会做客户端注册文件自检(`loadClients()`),配置错误会快速失败。

npm 脚本:

| 脚本 | 作用 |
|---|---|
| `npm start` | 启动服务(`--env-file-if-exists=.env`) |
| `npm run dev` | 监听文件变更自动重启 |
| `npm run typecheck` | `tsc --noEmit` 类型检查 |
| `npm test` | 单元测试(`node:test`) |
| `npm run test:smoke` | 端到端 OIDC 流程烟测(会拉起 mock 钉钉与 SSO 进程) |
| `npm run test:mock-dingtalk` | 单独启动 mock 钉钉服务 |
| `npm run key:rotate` | 生成新密钥并切换 active,旧密钥转 verifying |
| `npm run key:list` | 列出密钥环中的密钥及状态 |
| `npm run key:prune` | 把超过退休窗口的 verifying 密钥置 retired |
| `npm run key:retire -- <kid>` | 立即退休指定 kid(不能退休 active) |

## 环境变量一览

以下变量均取自 `src/config.ts`(标注来源的除外):

| 变量 | 默认值 | 说明 |
|---|---|---|
| `SSO_ISSUER` | 无(必填) | 签发者标识与对外地址,生产如 `https://sso.company.internal`;末尾 `/` 会被去除。缺失则启动/求值失败 |
| `SSO_PORT` | `8091` | HTTP 监听端口 |
| `SSO_DATA_DIR` | `./data` | 运行时状态目录:`sessions.json`、`refresh_tokens.json`、`audit.jsonl` |
| `SSO_KEYS_DIR` | `./keys` | RS256 密钥环目录(见下文) |
| `SSO_CLIENTS_PATH` | `./clients.json` | 客户端注册文件路径 |
| `SSO_SESSION_TTL_HOURS` | `8` | SSO 会话(`sso_sid`)有效期(小时),访问时滑动续期 |
| `SSO_ACCESS_TOKEN_TTL_SECONDS` | `600` | access_token 寿命(秒),须为 ≥1 的整数,否则快速失败 |
| `SSO_ID_TOKEN_TTL_SECONDS` | `600` | id_token 寿命(秒),须为 ≥1 的整数,否则快速失败 |
| `SSO_KEY_RETIRE_AFTER_HOURS` | `2` | 密钥退休窗口(小时),可为 0(立即退休) |
| `LDAP_URL` | 未设置 | 设置后启用真实 LDAP;未设置则使用 `FILE_USERS_PATH` 文件目录 |
| `LDAP_BIND_DN` | 无 | 配置 `LDAP_URL` 时必填,读账号 bind DN |
| `LDAP_BIND_PASSWORD` | 无 | 配置 `LDAP_URL` 时必填 |
| `LDAP_BASE_DN` | 无 | 配置 `LDAP_URL` 时必填,目录根 |
| `LDAP_PEOPLE_BASE` | `ou=people,<LDAP_BASE_DN>` | 用户条目搜索 base |
| `LDAP_ATTR_SUB` | `employeeNumber` | 工号属性名 |
| `LDAP_ATTR_NAME` | `cn` | 姓名属性名 |
| `LDAP_ATTR_DEPT` | `departmentNumber` | 部门属性名 |
| `LDAP_ATTR_MOBILE` | `mobile` | 手机号属性名 |
| `LDAP_ATTR_DINGTALK` | `dingtalkUserId` | 钉钉号属性名 |
| `LDAP_ATTR_STATUS` | `aiStatus` | 账号状态属性名 |
| `LDAP_STATUS_DISABLED_FLAG` | `disabled` | status 属性中出现该子串即视为禁用 |
| `FILE_USERS_PATH` | `./data/users.json` | 未配置 LDAP 时使用的文件目录 |
| `DINGTALK_APP_KEY` | 未设置 | 钉钉扫码应用 Key;与 Secret 同时存在才算「已配置扫码」 |
| `DINGTALK_APP_SECRET` | 未设置 | 钉钉扫码应用 Secret |
| `DINGTALK_API_BASE` | `https://api.dingtalk.com` | 钉钉新版 API 基地址 |
| `DINGTALK_OAPI_BASE` | `https://oapi.dingtalk.com` | 钉钉旧版 OAPI 基地址 |
| `DINGTALK_LOGIN_BASE` | `https://login.dingtalk.com` | 扫码授权页基地址 |
| `SSO_DINGTALK_REDIRECT_URI` | 无 | 启用扫码时必填,须与钉钉后台回流域名一致,如 `http://127.0.0.1:8091/dingtalk/callback` |
| `SSO_DEBUG` | 未设置 | 任意非空值开启调试日志(如 PKCE、userinfo 校验细节),生产留空 |
| `SSO_SECRET_*` | 无 | 客户端密钥,由 `src/clients.ts` 在展开 `clients.json` 的 `${ENV:...}` 占位时读取;未设置或为空串会导致启动失败。示例见 `.env.example`:`SSO_SECRET_AGENT`、`SSO_SECRET_DASHBOARD`、`SSO_SECRET_MARKET`、`SSO_SECRET_RAG`、`SSO_SECRET_ROUTER`、`SSO_SECRET_ZHONGTAI_OA`、`SSO_SECRET_TEST_WEB` |

> 说明:`authorize` 事务 TTL 固定 10 分钟、授权码 TTL 固定 5 分钟,不可通过环境变量调整。

## clients.json 与 secret 管理

- **不入版本库**:`clients.json` 已加入 `.gitignore`,`clients.example.json` 是模板。请在部署环境本地创建 `clients.json`。
- **`${ENV:NAME}` 占位**:`client_secret` 支持形如 `${ENV:SSO_SECRET_AGENT}` 的占位,服务启动时由 `src/clients.ts` 展开。**若引用的环境变量缺失或为空串,服务直接启动失败**(避免空 secret 造成鉴权绕过);`${ENV:...}` 格式非法时同样抛错,不会被当作字面量 secret 静默生效。
- **空/非字符串 secret 被拒绝**:`client_secret` 缺失、为空串或非字符串都会在加载时抛错并阻止启动。
- **`refresh_ttl_hours`**:设置该客户端的 refresh token 有效期(小时),默认 `12`;非法值回退为 12。该值决定从**首次授权时间**起算的绝对会话上限,刷新轮换不会延长。
- **生成 secret**:

  ```bash
  node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
  ```

  为每个客户端生成各自的随机值,写入 SSO 的 `.env`(或部署环境变量),并同步到对应客户端的运行环境。
- **泄露处置**:立刻为受影响客户端生成新 secret,同时更新 SSO 的 `SSO_SECRET_*` **和该客户端自身的配置**,然后一并重启,使新旧值同步切换,避免过渡期 401。

## 密钥轮换运维手册

密钥环目录布局(`SSO_KEYS_DIR`,默认 `./keys`):

```
keys/active            文本文件,内容为当前签发密钥的 kid
keys/<kid>.pem         PKCS8 私钥(权限 0600)
keys/<kid>.meta.json   { kid, createdAt, status, verifyingSince? }(权限 0600)
```

`status` 取值:

- `active`:当前签发密钥,签名始终使用它。
- `verifying`:已停止签发,但仍发布公钥用于验签历史 token。
- `retired`:已移出 JWKS。

常用命令与工作示例:

```bash
npm run key:rotate      # 例:[keys] 轮换完成: ab12... -> cd34...
npm run key:list        # 输出每把密钥的 status / kid / 创建时间
# 等待退休窗口(默认 2 小时)过去
npm run key:prune       # 例:[keys] 已退休: ab12...
```

退休窗口语义:`SSO_KEY_RETIRE_AFTER_HOURS`(默认 2 小时)从密钥**停止签发**(`rotate` 写入 `verifyingSince`)的那一刻起算;`prune` 只退休 `verifying` 且已超过窗口的密钥。`key:retire <kid>` 可跳过窗口立即退休指定密钥,但不能退休 `active`。

为什么轮换零中断:`/.well-known/jwks.json` 同时发布 `active` + `verifying` 公钥,客户端缓存 JWKS 最长约 600 秒(rag/market/agent 自实现缓存 TTL 为 300 秒;router 控制台与 dashboard 用 jose `createRemoteJWKSet` 默认 `cacheMaxAge` 为 600 秒)。轮换后新 token 用新密钥签名、旧 token 仍可被旧公钥验签,客户端最迟约 10 分钟收敛,期间不中断。JWKS 每次请求实时构建,保证从**独立 CLI 进程**发起的轮换立即对服务进程可见。

约束:退休窗口必须大于 access_token TTL 加上客户端最坏 JWKS 缓存。默认值下为 `600s + 600s = 1200s`,远小于默认窗口 2 小时(7200s),安全。

**紧急流程(私钥疑似泄露)**:先 `npm run key:rotate`,再**立即** `npm run key:retire -- <old-kid>`,立刻把旧公钥移出 JWKS、使基于旧私钥的历史 token 失效。

**回滚**:轮换前备份整个 `SSO_KEYS_DIR`;回滚即停止服务、还原目录(含 `active`、`*.pem`、`*.meta.json`)后重启。注意:紧急退休后若直接还原,会重新信任已泄露的旧私钥,仅在确认泄露误报时使用。

## 吊销语义

需要明确的是:本服务的吊销是**收敛窗口**,不是瞬时失效。

- 登出(`/logout`)会立即销毁该用户的 SSO 会话,并吊销其全部 refresh token。
- 修改密码成功后,会立即吊销该用户的全部 refresh token,并销毁其它端的 SSO 会话;**当前会话保留**,不影响本次操作。
- 但**已签发的 access_token / id_token 在过期前仍然有效**(默认 10 分钟)。因为资源服务是**离线验签** JWT,不回调 SSO,SSO 无法收回已发出的令牌。
- 每个客户端自身的本地会话另按其 TTL 到期:agent / rag / market / router 默认 12 小时;dashboard 通过 12 小时的 refresh 续期。
- 因此,吊销机制 = 较短的 access_token TTL(默认 10 分钟)+ 有上限的客户端本地会话 TTL(默认 12 小时),把离职/登出/改密后的残留窗口限制在可接受范围内。
- **秒级吊销当前做不到**:除非把客户端改成每次请求都调用 SSO 的 introspection / 在线校验端点,但本服务**未实现**该端点,所以请以「分钟级收敛」预期使用。

## 接口清单

| 端点 | 方法 | 说明 |
|---|---|---|
| `/.well-known/openid-configuration` | GET | OIDC discovery 元数据 |
| `/.well-known/jwks.json` | GET | 发布 active + verifying 公钥(RS256) |
| `/authorize` | GET | 授权入口;校验 client 与 redirect_uri,已登录则直接发 code,否则跳登录页。**提供 `code_challenge` 时必须 `code_challenge_method=S256`** |
| `/login` | GET | 登录页(扫码 / 账号密码双通道) |
| `/login/password` | POST | 账号密码登录(LDAP / 文件目录),成功后发 code |
| `/dingtalk/start` | GET | 跳转钉钉扫码授权页;未配置扫码时返回友好提示 |
| `/dingtalk/callback` | GET | 钉钉回调,换取身份并完成登录 |
| `/token` | POST | 授权码或 refresh_token 换取令牌。**refresh token 一次性使用,每次刷新都会轮换**;刷新沿用首次授权时间,受绝对会话上限约束(`refresh_ttl_hours`) |
| `/userinfo` | GET | 用 Bearer access_token 返回 `sub/name/dept/roles`(有钉钉号时含 `dingtalk`) |
| `/logout` | GET | 销毁会话并吊销该用户 refresh token,可跳回已登记的 `post_logout_redirect_uri` |
| `/profile` | GET | 账号设置页(需已登录);扫码后 10 分钟内可免当前密码激活 |
| `/profile/password` | POST | 设置/修改密码,成功后吊销该用户 refresh token 与其它端会话 |
| `/healthz` | GET | 健康检查,返回 `{"status":"ok"}` |

## 测试

```bash
npm run typecheck   # tsc --noEmit
npm test            # 单元测试(28 个用例)
npm run test:smoke  # 端到端烟测,需 test/fixtures/clients.json 与 test/data/users.json 夹具
```

烟测会在本地拉起 mock 钉钉与 SSO 进程,覆盖:密码登录、扫码登录、密码激活、禁用账号扫码被拒、授权码一次性、单点登录、登出、refresh token 轮换与复用拒绝、refresh 绝对上限、access/id token TTL(含环境变量覆盖)、改密后 refresh token 与其它端会话的吊销。
