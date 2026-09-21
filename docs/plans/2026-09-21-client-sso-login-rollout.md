# 各业务系统「企业 SSO 登录」接入实施结果（agent / rag / market / router / dashboard）

**目标：** 让 agent、rag、market、router 控制台都同时提供「本系统账号密码登录」与「企业 SSO 登录」，
dashboard 桌面端沿用统一认证；SSO 侧只需为每个系统登记公网回调地址。

**完成时间：** 2026-09-21
**SSO 服务端：** 192.168.31.45:8091（`https://auth.xzrobot.com`），issuer=公网、JWKS=内网
**公网入口：** `https://ai.xzrobot.com/<svc>`（36.154.118.170 终结 TLS，回源 45:80，45 剥前缀转发到 34）

---

## 一、接入方式（两条轨，互不影响）

| 轨 | 用途 | 需要的配置 |
|---|---|---|
| **资源轨**（原有） | 接受别人（dashboard）传来的 SSO token，自动建号 | `SSO_ISSUER` + `SSO_JWKS_URI` + `SSO_AUDIENCE` |
| **登录轨**（本次新增） | 浏览器点「企业 SSO 登录」→ 跳 SSO → 回调换 token → 建本地会话 | 追加 `SSO_CLIENT_ID` + `SSO_CLIENT_SECRET` + `SSO_REDIRECT_URI` + `SSO_REDIRECT_TARGET` |

两轨的受众不同，务必区分：登录轨的 id_token `aud` 是本系统自己的 client_id，
资源轨的 `aud` 是调用方（dashboard-gateway）的 client_id。代码里用「显式受众覆盖」处理。

### 统一的回调与跳转约定

| 系统 | client_id | 公网回调（registered in clients.json） | 登录页（回跳目标） | SSO 登录入口 |
|---|---|---|---|---|
| agent | `agent` | `https://ai.xzrobot.com/agent/api/auth/sso/callback` | `/agent/#/login` | `/agent/api/auth/sso/start` |
| rag | `rag` | `https://ai.xzrobot.com/rag/api/auth/oidc/callback` | `/rag/login` | `/rag/api/auth/sso/start` |
| market | `market` | `https://ai.xzrobot.com/market/api/auth/oidc/callback` | `/market/login` | `/market/api/auth/sso/start` |
| router 控制台 | `router-admin` | `https://ai.xzrobot.com/router/api/auth/oidc/callback` | `/router/login` | `/router/api/auth/sso/start` |
| dashboard 桌面端 | `dashboard-gateway` | `http://127.0.0.1:8090/api/auth/oidc/callback`（回环，无需公网） | — | 应用内「企业 SSO 登录」 |

## 二、各系统改动与状态

### agent（零号员工）
- **代码：无新增**（`/api/auth/sso/start`、`/api/auth/sso/callback`、前端「企业 SSO 登录」按钮早已存在，部署的 Vue 产物含 `sso/start`/`sso_token`）。
- **只补配置**（34 上 `/home/xzrobot/agent/.env` 与容器 `--env-file`）：
  ```
  SSO_ISSUER=https://auth.xzrobot.com
  SSO_JWKS_URI=http://192.168.31.45:8091/.well-known/jwks.json
  SSO_CLIENT_ID=agent
  SSO_CLIENT_SECRET=<SSO_SECRET_AGENT>
  SSO_REDIRECT_URI=https://ai.xzrobot.com/agent/api/auth/sso/callback
  SSO_REDIRECT_TARGET=/agent/#/login
  SSO_AUDIENCE=agent
  ```
- **容器重建**：`--add-host auth.xzrobot.com:192.168.31.45`（容器内无法解析公网域名，见「四、DNS」）。
  已固化进 `/home/xzrobot/agent/build.sh`（并改用绝对路径挂载，根除 `$(pwd)` 老坑）。
- **附带修复**：`X-Service-Token` 之前只在 `_get_admin` 被识别，`_require_perm`/`_get_authz`
  端点（`/api/rbac/users` 等）一律 401，导致 dashboard 网关 JIT 走服务令牌时失败。
  已让 `_get_authz` 对服务请求返回服务账号（与 `_get_admin` 语义一致）。

### rag（企业知识库）
- **新增授权码流程**：`app/core/sso_auth.py`（`build_authorize_url` / `exchange_code` / 一次性 state /
  `verify_sso_token(token, audience=None)` 显式受众）、`app/api/auth.py`（`GET /api/auth/sso/start`、
  `GET /api/auth/oidc/callback`）、`app/config.py`（4 个新配置项）。
- **组/角色映射**：SSO 只签发 `roles`（无 `groups`）。`_normalize_claims_groups` 现同时采纳
  `groups` 与 `roles`，且 `roles` 含 `admin` 时补 rag 内部管理员标记 `__local_admin__`
  与 `ldap_group_map_admin` —— 使 SSO 管理员与本地/LDAP 管理员同权（全库管理端点均按该标记判定）。
- **前端**：`stores/auth.ts`（`loginWithSso` / `adoptSsoToken`）、`views/Login.vue`（「企业 SSO 登录」
  按钮 + 处理回跳的 `?sso_token=` / `?error=`）。
- 部署：`docker compose --profile pg up -d --build backend frontend`；compose 增加 4 个环境变量 +
  `extra_hosts: auth.xzrobot.com:192.168.31.45`；`.env` 写入对应值。
- 测试：新增 11 个用例（state 一次性/过期、受众覆盖、回调建号与管理员组、错误分支、404 分支），
  全量 `pytest` 154 passed。

### market（能力市场）
- **无代码改动**（登录轨早已实现），本次只需 SSO 侧登记公网回调 + 轮换后的新 secret + `extra_hosts`。
- 前端产物已含 `sso_token` 处理。

### router（算力网关控制台）
- **新增授权码流程**：`admin/src/oidc.ts`（`isSsoLoginConfigured` / `newSsoState` / `consumeSsoState` /
  `buildSsoAuthorizeUrl` / `exchangeCodeForIdToken` / `verifyIdToken(idToken, audience?)`）、
  `admin/src/routes/auth.ts`（`GET /api/auth/sso/start`、`GET /api/auth/oidc/callback`，
  按工号 find-or-create 用户、写审计 `sso_login`、签发控制台 JWT 后 302 回登录页）。
- **前端**：`stores/auth.ts`（`loginWithSso` / `adoptSsoToken`）、`views/Login.vue`（SSO 按钮 +
  `?token=` / `?error=` 处理）。
- 新账号默认角色 `USER`；需要直接给管理员时设 `SSO_DEFAULT_ROLE=ADMIN`。
- 部署：compose 增加 5 个环境变量 + `extra_hosts`；`docker compose up -d --build admin web`。
- 测试：新增 7 个用例（含 state 一次性/过期、授权 URL 构造），`npm test` 32 passed；`tsc` 通过。

### dashboard（员工 AI 工作台，桌面端）
- **无代码改动**：issuer / client_id / client_secret 均为安装期注入（环境变量或设置页），
  无内置兜底（缺失即报可操作错误）。
- **每个安装需要更新**（见「三、待你执行」）。

## 三、域名定案:`auth.xzrobot.com`（原 `sso.xzrobot.com` 已被别的服务占用）

`sso.xzrobot.com` 在内网由另一台 nginx(192.168.31.252) 提供（证书无效），属别的服务；
本套 SSO 的公网域名最终定为 **`https://auth.xzrobot.com`** —— 该名字的三件事都已就绪：

| 项 | 状态 |
|---|---|
| 公网入口回源 | ✅ 已回源到 45（在 45 的 access.log 里用探测路径确认过） |
| 内网 DNS | ✅ 已指向 192.168.31.45 |
| 证书 | ✅ `*.xzrobot.com` 泛域名覆盖，浏览器直访 `https://auth.xzrobot.com/` 返回 200 无警告 |
| 45 的 nginx server 块 | ✅ 本次新增（80+443，转发本机 8091），并已**撤回对 `sso.xzrobot.com` 的占用** |

`SSO_ISSUER` 已切到 `https://auth.xzrobot.com`，四个客户端（agent/rag/market/router）的 issuer 与
`auth.xzrobot.com:192.168.31.45` 映射同步切换完毕；旧 `sso.xzrobot.com` 已不再被本套服务占用。

## 四、待你执行

1. **dashboard 桌面端配置**（每台安装）：
   - `OIDC_ISSUER=https://auth.xzrobot.com` ← 注意是 auth，不是 sso
   - `OIDC_CLIENT_ID=dashboard-gateway`（默认值，可省）
   - `OIDC_CLIENT_SECRET=<SSO_SECRET_DASHBOARD_GATEWAY 新值>`（在 45 的
     `/home/xzrobot/apps/sso/.secrets-new` 内；**该值不再入库，请通过安装包/企业配置下发**）
   - 若走服务令牌：确认 agent 侧 `AGENT_SERVICE_TOKEN`（已修复覆盖范围）与该值一致；
     若走管理员口令：填 `AGENT_ADMIN_USER` / `AGENT_ADMIN_PASSWORD`。
2. **zhongtai-oa**：同步新 `SSO_SECRET_ZHONGTAI_OA` 与 `issuer=https://auth.xzrobot.com`。
3. **各客户端重新登录一次**：issuer 与密钥都变了，旧的会话/refresh token 全部失效。
4. **`ai.xzrobot.com` 根路径**目前 404（只有 `/agent/ /rag/ /market/ /router/` 四个入口）。
   需要的话可以在 45 的 nginx 加一个导航首页（约 20 行，无需重建容器）。

## 五、踩过的坑（下次别再犯）

- **容器内解析不到公网域名**：.34 上的容器走内网 DNS，历史上 `sso.xzrobot.com` 被解析到
  `192.168.31.252`（错）。凡容器内要发 HTTPS 到公网域名（token 交换、JWKS）的，都要
  `extra_hosts` / `--add-host auth.xzrobot.com:192.168.31.45`，否则回调在换 token 一步失败
  （本次 agent 就漏配过，靠实测 `POST /token` 才暴露）。
- **公网域名 ping 不通 ≠ 不能用**：akamai 只开放 443/22，ping/ICMP 本来就不通。
- **测试必须带 `--resolve`**：本机 DNS 是 split-horizon，解析不到公网入口。
- **`docker exec` 时的 `$()`、`$VAR` 会被 PowerShell 先展开**：远程命令一律写成脚本文件上传执行，
  否则会把 `$(pwd)` 之类展开成本机路径（本次差点把 agent 的 `build.sh` 写坏）。
- **rag 前端 nginx 会缓存 backend 容器 IP**：重建 backend 后必须一并重启/重建 frontend。
- **改 `clients.json` 不用重建 SSO 镜像**：该文件有 30 秒热更新，`docker cp` 进容器即可
  （但也要同步宿主机构建目录，供将来重建镜像）。
- **agent 测试污染**：`tests/unit/test_web_memory_proposals.py` 原先在**模块导入时**设
  `WEBUI_DISABLE_AUTH=1` 且不清理，导致同批次跑的 `test_sso_auth` 双轨鉴权用例假失败
  （表现为拿到假用户/非法 token 被放行）。已改为 autouse fixture 注入。

## 六、验证结果（2026-09-21，经公网入口实测；域名切换 auth.xzrobot.com 之后复测）

| 检查 | 结果 |
|---|---|
| 四个系统首页 `/agent/ /rag/ /market/ /router/` + SSO 首页 | 全部 200 |
| `auth.xzrobot.com` 的 discovery / jwks / healthz / `/authorize`(无参 400) | 均符合预期；issuer = `https://auth.xzrobot.com` |
| 四个容器内 `POST https://auth.xzrobot.com/token`（回调换 token 的前提，TLS 校验通过） | 均返回 401（连通；参数被拒属正常） |
| 四个系统 `sso/start` | 全部 302 到 `https://auth.xzrobot.com/authorize`，client_id/redirect_uri 正确 |
| rag / router 回调错误分支 | 302 回各自登录页并带 `error=` 文案 |
| agent / market 回调错误分支 | 401 JSON（**与前者不一致，属已知小差异，未改动以免扩大改动面**） |
| `/internal/`、`/router/internal/` | 404（不可达） |
| SSO discovery / jwks / healthz | 200，JWKS kid 仍为 `c3b644dca66338c8`（未换密钥环） |
| 证书校验（不带 `-k`，浏览器行为） | `auth.xzrobot.com` 200 无警告 |
| rag 全量测试 | 154 passed |
| router 单测 / tsc | 32 passed / 通过 |
| agent ruff + 相关测试 | All checks passed / 72 passed（全量套件在本工作区**既有**收集错误，与本次无关） |
| 服务令牌范围修复 | `/api/rbac/users` 带服务令牌 200（原 401），无凭证/错误令牌仍 401 |

## 七、收尾补充（2026-09-21 晚）

1. **SSO 回调失败一律跳登录页并回显原因**（原先 agent/market 返回 401 裸 JSON，与 rag/router 不一致）：
   - agent：`src/web/server.py` 新增 `_sso_login_redirect()`，回调各错误分支改 302 → `/agent/#/login?error=...`；
     前端 `LoginView.vue` 读 `route.query.error` 填入既有错误提示位；新产物已随镜像目录
     `src/web/static_vue/`（入库）一起部署。
   - market：`backend/app/routers/auth.py` 新增 `_sso_login_redirect()` → `/market/login?error=...`；
     前端 `LoginView.vue` 读 `route.query.error`（**保留了服务器版独有的「演示账号」块**，
     该文件在服务器上有本地没有的内容，故用外科插入而非整体替换）。
   - 现在四个系统的回调错误分支表现一致（302 + error 文案）。

2. **`ai.xzrobot.com` 根路径导航页**：45 上新增 `/home/xzrobot/docker/nginx/html/ai-index.html`
   （列出四个系统入口 + 统一认证入口），nginx 的 80 / 8888 / 443 三个 server 块各加一条
   `location = /`（精确匹配，不影响 `location /` 到 LLM 网关的 `/v1/...` 转发）。

3. **顺带修复**：443 块里 `/internal/` 的 404 规则此前被上一行注释**吞掉**（两行并成一行 →
   整行成了注释），`/internal/` 的 404 实际由上游网关给出。已拆回独立行，现在由 nginx 硬拦
   （实测 nginx 自己的 404 页）。

## 八、回滚

> 附加:`dashboard` 的本地配置与「rag 问答故障」的处置记录见第九节。

## 九、故障处置记录（2026-09-21 晚）

### 9.1 dashboard 报「未配置 OIDC_CLIENT_SECRET」

`%APPDATA%\dashboard\config.json`（Windows 上 `dashboard`/`Dashboard` 是同一目录）
缺 OIDC 三项，且 `agentUrl` 指向 `http://127.0.0.1:8080`（本机并无 agent）。已补：

```json
"agentUrl": "http://192.168.31.34:8090",
"agentServiceToken": "<agent 的 AGENT_SERVICE_TOKEN>",
"oidcIssuer": "https://auth.xzrobot.com",
"oidcClientId": "dashboard-gateway",
"oidcClientSecret": "<SSO_SECRET_DASHBOARD_GATEWAY>"
```

改配置后**必须重启 dashboard**（主进程启动时读一次）。同一台机器上实测其依赖链
（discovery/jwks/agent/服务令牌/token 端点）均通。

### 9.2 rag 问答"报错/答不出"的真实原因（两处独立缺陷）

**症状:** 提问后答「抱歉，我无法回答」，后端日志刷满
`InFailedSqlTransaction`，且 `sources` 为空。

**根因链:**
1. rag 的 `EmbeddingService` 发给网关的请求**没有 Authorization 头** →
   网关 `401` → 查询向量为空 `[]`；
2. 空向量被拿去执行 `CAST('[]' AS vector)` → `DataException: vector must have at least 1 dimension`，
   **这条失败把 SQLAlchemy 事务置为 aborted**；
3. 同一 session 里后续的 pgvector/BM25/实体扩展/统计查询**全部**报
   `InFailedSqlTransaction` → 检索彻底为空 → 模型只能答"无法回答"。
4. 另有一处配置缺口:网关的 `ApiKeyAllowedModel` 里**没有任何 key 被授权**
   `bge-large-zh-v1.5`，即便补上鉴权头也会 403。

**修复（rag 仓库 + 网关配置）:**
- `app/core/rag.py`:`EmbeddingService` 增加 `_headers`（带 `Bearer {LLM_API_KEY}`，
  空 key 时不加头以兼容本地 Ollama）并用于 encode/encode_batch 全部调用；
- `app/core/rag.py`:`_search_sync` 对**空向量直接短路**返回，且 pgvector 失败后
  **显式 `rollback()`**，避免污染事务拖垮 BM25 等其它检索路径（这层容错让
  embedding 挂掉时仍能用 BM25 兜底出结果）；
- 网关侧通过管理端 API（`PUT /api/keys/16`，key=`svc-rag`）授权
  `bge-large-zh-v1.5`，保留原有 `deepseek-flash`（走 API 有校验与审计）；
- 新增 4 个回归测试（Bearer 头、空 key 不加头、空向量短路）。

**验证:** 容器内直测 embedding 返回 1024 维向量；经公网提问回答变为
「根据参考资料，我找到了一些…」并**带回 sources**，后端错误计数 0。

### 9.3 rag 问答前端仍报「错误: Not Found」（子路径补丁有遗漏）

**症状:** 后端问答已正常（curl 打 `/rag/api/chat` 是 200），但**页面里**提问仍显示
`错误: Not Found`。

**根因:** 前端里三处调用写的是**绝对路径，缺 `/rag` 前缀**（子路径改造时漏改），
浏览器于是请求 `https://ai.xzrobot.com/api/chat`，被 45 的兜底 `location /`
转发到 LLM 网关 → 404；对 404 的 JSON 取 `err.detail` 就渲染成「错误: Not Found」。
漏掉的三处：

| 位置 | 原写法 | 影响 |
|---|---|---|
| `views/Chat.vue` | `fetch('/api/chat')` | **问答直接 404** |
| `views/Editor.vue` | `fetch('/api/organize')` | 笔记"自动整理"404 |
| `api/http.ts` | `window.location.href = '/login'` | 401 时跳到错误地址 |

（`stores/auth.ts`、`api/http.ts` 的 axios 实例都用了 `BASE_URL`，所以登录与大部分接口正常 ✓）

**修复:** 三处统一改成既有惯用写法
`(import.meta.env.BASE_URL || '/').replace(/\/$/, '') + '/api/...'`，重建前端后
在产物里核对：带 `/rag` 前缀的调用出现 6 条，裸 `fetch("/api/chat")` 与裸 `/login` 均为 0。

**顺带修:** 前端 nginx 的 `location /` 增加 `Cache-Control: no-cache`。
此前入口 HTML 没有任何缓存头，前端重建后浏览器可能仍用旧 index.html
（引用已删除的 hash 资源 → 白屏/报错），也会让人误以为"改的没生效"。

**排查提示:** 「后端 curl 正常但页面报错」时，先看前端产物里的**实际请求 URL**
（`grep -oE 'fetch\([^)]{0,90}' 产物.js`），子路径部署最常见的坑就是漏改前缀。

### 9.4 rag 报「无效的认证令牌」——同源应用 localStorage 键冲突

**症状:** 问答请求已打到正确后端 ✓，但返回 401「无效的认证令牌」；后端日志呈
`401 → 200（用工具自测）→ 401` 交替。

**根因:** 四个系统都部署在**同一 origin**（`https://ai.xzrobot.com`，靠路径区分），
而 localStorage 是**按 origin 隔离、不按路径隔离**的 —— rag 与 router 控制台都用了
裸键 `localStorage['token']`，于是互相覆盖：访问过 router 控制台后，rag 读到的是
router 的 JWT（用 router 的 JWT_SECRET 签的），rag 验签必然失败 → 401。

| 应用 | 原键 | 是否冲突 |
|---|---|---|
| rag | `token` | ✗ 与 router 冲突 |
| router 控制台 | `token` | ✗ 与 rag 冲突 |
| agent | `agent_jwt` | ✓ 已隔离 |
| market | `mk_token` / `mk_user` | ✓ 已隔离 |

**修复:** rag → `rag_token`（9 处/5 文件），router → `router_token`（7 处/3 文件），
与 agent/market 的命名风格对齐。**不做旧键迁移**：同源的旧 `token` 值归属不可判定
（可能是 rag 的也可能是 router 的），统一要求重新登录一次。

**验证:** 线上产物 rag 侧 `rag_token` 出现 9 次、router 侧 `router_token` 7 次，
裸 `localStorage` 存取 `token` 均为 0；两端页面 200，`vue-tsc`/构建通过。

**给后续开发的提醒:** 同一域名下多应用共用 localStorage 时，**任何持久化键都要加应用前缀**
（含 token、用户信息、草稿、折叠状态等），否则会出现这种"登录好好的、过一会儿就 401"的怪现象。

## 十、回滚

- **agent**：`/home/xzrobot/agent/src/web/server.py.bak-svcperm-<ts>`（服务令牌改动）；
  SSO 配置在 `.env` 与 `build.sh`（`--add-host` 行），删掉即回到「仅本地登录」。
- **rag**：`/home/xzrobot/rag/.bak-ssologin-<ts>/`（6 个源文件 + `.env` + compose 全套）；
  `docker compose --profile pg up -d --build backend frontend` 回滚。
- **router**：`/home/xzrobot/ai-gateway/.bak-ssologin-<ts>/`；`docker compose up -d --build admin web`。
- **SSO**：`clients.json` 容器内 `clients.json.bak_<ts>`；镜像保留 `sso:prev-<ts>`。
- **SSO 服务自身**：`/home/xzrobot/apps/_sso_backup_<ts>/`（旧镜像/旧 env/密钥环备份）。
