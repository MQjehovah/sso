# 安全基线（APP_ENV 分级）设计

日期：2026-09-20
状态：已确认，待实施
范围：跨 6 个仓库（rag / router / agent / market / sso / dashboard）

## 背景

平台评审列出一批"不安全默认值"与配置基线问题，本次核实后的清单：

| 仓库 | 问题 | 位置 |
|---|---|---|
| rag | CORS `allow_origins=["*"]` + `allow_credentials=True` | `backend/app/main.py:15-16` |
| rag | 硬编码 `minio_secret_key="xzyz2022!"`、`jwt_secret_key="change-me-in-production"`、`local_admin_password="123456"` | `backend/app/config.py:48,68,72` |
| rag | `.env.example` 无任何 SSO 变量（部署易漏配后回退弱默认） | `backend/.env.example` |
| router | `ENCRYPTION_KEY \|\| 'default-key'`（5 处）、`JWT_SECRET \|\| 'default-secret'` | `admin/src/routes/{internal,providers,sso}.ts`、`admin/src/index.ts:48` |
| router | admin 与 gateway 的 CORS `origin: true` | `admin/src/index.ts:24`、`gateway/src/app.ts:16` |
| agent | 首次启动写死 `admin/admin123`；`JWT_SECRET` 有回退 | `src/web/server.py:888`、`src/web/server.py:38` |
| agent | 两个 `mcp_servers.json` 仍 tracked 真实 `SMTP_PASSWORD` / `DEVICE_API_PASSWORD` | `config/mcp_servers.json`、`config/agents/设备运维/mcp_servers.json` |
| market | `jwt_secret` 弱默认、`seed_admin_password="admin123"` | `backend/app/config.py:29,39` |
| sso | 会话 cookie 无 `Secure`；登录/改密表单无 CSRF | `src/protocol.ts:144,466` |
| dashboard | OIDC issuer 默认写死 `http://192.168.31.45:8091` | `electron/main/identity.ts:93` |

（`market` 的 SSO 变量其实已在 `.env.example` 中，前期调研的那条发现已过时。）

## 目标

1. 用统一的 `APP_ENV` 分级策略消除上述不安全默认值：**生产必须显式配置，开发可用但告警**。
2. 消除"通配 CORS + credentials"组合。
3. 把仍 tracked 的凭证移出版本库，改环境变量注入。

## 非目标（YAGNI）

- 不引入密钥管理系统 / Vault。
- 不改变各仓库既有的鉴权模型（JWT/SSO/API key 组合不变）。
- 不重写配置加载框架，只加一层守卫。
- 不做各仓库间共享代码包（无包边界，只共享约定与弱值清单）。

## 共享策略：`APP_ENV` 分级

- 各服务读取环境变量 `APP_ENV`，**默认 `development`**；取值 `production` / `prod`（大小写不敏感）视为生产。
- 统一守卫（各语言各自实现一份，行为与错误文案对齐）：

```
require_secret(name, value, weak_values):
    bad = value 为空 OR value 命中 weak_values
    if not bad: return value
    if is_production:
        raise 启动错误：环境变量 <name> 未配置或仍为不安全的默认值，请参考 .env.example 设置
    else:
        warn：环境变量 <name> 使用默认/弱值，生产环境将拒绝启动
        return value
```

- **弱值清单**（跨仓库统一，显式列举，避免"只改默认值就绕过"）：
  `change-me-in-production`、`dev-secret-change-me-please-32-bytes-minimum`、`default-secret`、`default-key`、`xzyz2022!`、`admin123`、`123456`、`change-me`、`gateway-secret`、`agent-secret`、`your-secret-key`。
- 允许显式豁免：`APP_ENV=development` 下一切照旧可运行，便于本地开发与烟测。

### 实现落点（各仓库各一份，避免跨仓库依赖）

- Python（rag / agent / market）：`app/core/env_guard.py`（rag、market）与 `src/utils/env_guard.py` 或等价位置（agent），导出 `is_production()`、`require_secret()`、`load_env_secret()`。
- TypeScript（router / sso / dashboard）：`src/env.ts`（router 各包各自一份：`admin/src/env.ts`、`gateway/src/env.ts`；sso `src/env.ts`），导出同样的三个函数。
- 各仓库在**配置模块加载时**调用守卫（与 sso 上一阶段的 `posIntEnv` 同样是"导入即校验、启动快速失败"的语义）。

## 各仓库改动

### 1. rag
- 新增 `cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"`（前端 dev 端口是 3000）；`main.py` 改为按逗号切分白名单，`allow_credentials=True` 仅在白名单非 `*` 时启用；不再出现 `["*"] + credentials`。
- `minio_secret_key`、`jwt_secret_key`、`local_admin_password` 经 `require_secret` 校验。
- `.env.example` 补齐：`APP_ENV`、`CORS_ORIGINS`、`JWT_SECRET_KEY`、`LOCAL_ADMIN_PASSWORD`、`MINIO_*`、SSO（`SSO_ISSUER/AUDIENCE/JWKS_URI/CLIENT_ID/CLIENT_SECRET/REDIRECT_URI`）、图片签名（`IMAGE_SIGN_SECRET/TTL`）、多模态（`MULTIMODAL_ENABLED`）、LLM（`LLM_BASE_URL/LLM_MODEL/LLM_API_URL`）。

### 2. router
- `admin/src/env.ts`、`gateway/src/env.ts`：`requireSecret`。
- `internal.ts`/`providers.ts`/`sso.ts`/`index.ts` 的 `process.env.X || 'default-*'` 改为经守卫读取（生产缺失即启动失败）。
- CORS：`admin/src/index.ts` 与 `gateway/src/app.ts` 的 `origin: true` 改为 `CORS_ORIGINS`（默认 localhost）白名单；`credentials` 仅在白名单显式时开启。
- `.env.example` 补 `APP_ENV`、`CORS_ORIGINS`。

### 3. agent
- `src/web/server.py`：首次初始化的默认口令由 `admin123` 改为 `AGENT_ADMIN_PASSWORD`；生产缺失即失败；开发缺失时生成随机口令并**打印一次**（不再有固定弱口令）。
- `JWT_SECRET` 经守卫（现有回退逻辑保留但生产必须显式）。
- 两个 `mcp_servers.json` 里的 `SMTP_PASSWORD` / `DEVICE_API_PASSWORD` 改为 env 注入（沿用钉钉/飞书的 `apply_env_overrides` 方式），值移入本机 gitignored `.env`，并更新 `.env.example` 与 `AGENTS.md`。

### 4. market
- `jwt_secret` 经守卫；`seed_admin_password` 生产必填，开发缺失时随机生成并打印一次。
- `.env.example` 补 `APP_ENV`。

### 5. sso
- 会话 cookie：当 `SSO_ISSUER` 以 `https://` 开头时追加 `Secure`（`issueCodeRedirect` 与 `clearCookie` 两处都要一致）。
- CSRF：登录表单（`/login/password`）与改密表单（`/profile/password`）加签名的隐藏字段 `csrf`，服务端用现有 HMAC 能力（复用 `image_sign` 同款做法或独立小模块）校验；不引入新依赖；校验失败返回 400 并提示"页面已过期，请重新打开登录页"。
- `.env.example` 补 `APP_ENV`。

### 6. dashboard
- `identity.ts` 的 `issuer()` 去掉硬编码默认，改为 `process.env.OIDC_ISSUER ?? cfg.oidcIssuer`，两者皆空时抛出明确中文错误；设置页已有配置通道则沿用（与上一阶段 `oidcClientSecret` 的处理方式一致）。

## 验收标准

1. `APP_ENV=production` 下，各服务用弱值或缺失 secret 启动**必须失败**，错误信息指出变量名；`APP_ENV=development` 下可启动但打印 `WARNING`。
2. 全仓库不再存在"通配 CORS + credentials"组合（`origin: true`、`allow_origins=["*"]` 均不再与 credentials 同时出现）。
3. `git grep` 在 tracked 文件中不再命中弱值清单中的任何真实取值（`.env.example` 的 `change-me*` 占位符按白名单豁免）。
4. `agent` 的两个 `mcp_servers.json` 不再包含真实 `SMTP_PASSWORD` / `DEVICE_API_PASSWORD`。
5. sso 登录/改密表单缺 CSRF token 时返回 400；带合法 token 正常。
6. 各仓库既有测试全绿；每个守卫新增正/反例单元测试。

## 风险

- **升级阻断**：生产部署必须先配好 env 才能启动。这是刻意的（fail-fast），但需要在发布说明中写明。
- **弱值清单是硬编码的**：若某部署用了清单外的新弱值不会被拦截；清单应随发现持续补充。
- **sso CSRF**：会增加一次服务端校验；若客户端缓存了旧登录页会导致 400，需在提示中引导刷新。
- **agent 口令改为随机生成**：开发环境首次启动后需从日志读取一次性口令，文档需说明。

## 实施结果（2026-09-20）

各仓库提交：

| 仓库 | 提交 |
|---|---|
| sso | `76ff004`（Secure+CSRF）、`c71b5a6`（本文档与计划） |
| rag | `abdc446`、`992dec4`（守卫/CORS/env 模板/compose） |
| router | `e0b0eea`、`c4917f8`、`3ef4fd0` |
| agent | `89aa067`、`f62e4fb` |
| market | `d256672`、`e60472f` |
| dashboard | `ac07233` |

### 验收核对

| 标准 | 结果 | 证据 |
|---|---|---|
| 1. production 弱值/缺失 → 启动失败并指出变量名 | ✅ | rag：`APP_ENV=production py -3.12 -c "import app.config"` 抛 `RuntimeError: 环境变量 JWT_SECRET_KEY ...`；router：admin 入口抛 `环境变量 JWT_SECRET ...`；agent/market 同；dashboard `OIDC_ISSUER` 缺失抛中文错误 |
| 2. development 可启动但告警 | ✅ | 各仓库均输出 `WARNING: <VAR> 使用默认/弱值;生产环境将拒绝启动` |
| 3. 不再有「通配 CORS + credentials」 | ✅ | `git grep` 已无 `origin: true`（仅存于 router 的历史设计文档）与 `allow_origins=["*"]`；rag CORS 改白名单，credentials 仅在白名单下开启 |
| 4. agent 的 mcp 配置不再含真实凭证 | ✅ | `git grep` 对 `SMTP_PASSWORD`/`DEVICE_API_PASSWORD` 仅剩 `${...}` 占位；另清理出并移出多个此前未记录的硬编码凭证（`titan@810`、`E2CO2Xnv6ga9`、`xzyz2022!` 等） |
| 5. sso 登录/改密缺 CSRF → 400；带合法 token 正常 | ✅ | 烟测 61/61；反向验证（令 `verifyCsrf` 恒真）后该断言失败 |
| 6. 各仓库既有测试全绿 | ✅ | rag 106、dashboard 179、agent 33 failed/328 passed（与 HEAD 基线逐项一致，0 新增失败）、market 6 failed/122 passed（与基线一致）、router admin 25 + gateway 61、sso 单测 36 + 烟测 61/0 |
| 7. `git grep` 不再命中弱值真实取值 | ⚠️ 部分 | 见下「豁免」 |

### 第 7 条的豁免说明（重要）

弱值字符串仍会出现在两类**受控**位置，这是刻意保留的：

1. **守卫模块的弱值清单本身**（`env_guard.py` / `env.ts`）——它就是用来识别这些值的。
2. **受守卫的开发默认值**：如 rag `config.py` 的 `minio_secret_key="xzyz2022!"`、`jwt_secret_key="change-me-in-production"`，market `seed_admin_password="admin123"`。
   保留它们是为了让"生产忘记配置"能被守卫**明确捕获**（若默认改成空串，语义相同但错误信息更含糊；若改成清单外的值，守卫会漏掉）。这些默认在 `APP_ENV=production` 下必然导致启动失败，已在各仓库验证。

其余命中均为文档、测试夹具或 `docker-compose` 的 `:?required` 提示文本。

### 本阶段额外发现并已修复

- **router `.env.example` 占位符不在弱值清单里**（`your_jwt_secret_key_here` 等 10 个），照抄模板即可通过生产守卫 → 模板占位符统一改为 `change-me`，并加了解析模板的断言测试。
- **rag / market 的 docker-compose 绕过基线**：原本注入 `${JWT_SECRET_KEY:-change-me-in-production}` 且不设 `APP_ENV`，使生产部署实际运行在 development 只告警 → 改为 `APP_ENV=${APP_ENV:-production}` + 密钥 `:?required`。
- **market `deploy.py` 会生成弱密钥写进 `.env`** → 改为 `openssl rand -hex 32` 生成，且仅在缺失/弱值时生成，不覆盖已有强值。
- **market 登录页公开显示默认账号口令** → 移除。
- 上一阶段 docker-compose 的 `IMAGE_SIGN_SECRET=change-me` 会让弱值压过 JWT 回退 → 改为留空以走强回退。

### 遗留（未在本阶段处理，建议后续）

- market 的 `publisher123` / `user123456` 仍是硬编码种子口令，且文档公开；与 admin 同属「已知默认口令」类，但需要新增配置字段并会破坏本地引导与测试夹具，故单列后续。
- market compose 的 `SSO_CLIENT_SECRET=${SSO_CLIENT_SECRET:-xzrobot-market-2026}` 是硬编码兜底（值为上一阶段已轮换的公网泄露口令）；改为 `:?required` 会影响非 SSO 部署，需先确认部署形态。
- rag `image_sign.py` 中 `image_sign_secret` 若被设为纯空白字符串（`" "`）仍会绕过 JWT 回退；应在取值处 `.strip()`。
- agent 其余 tracked 配置（`mcp_server` 代码内 `xxx` 占位、`DINGTALK_APP_KEY` 等应用标识）按「非敏感」保留，如需一律外置可另开任务。
- CI 目前不会以 `APP_ENV=production` 跑一次导入检查，弱值可能在开发路径回流；建议加入 CI。
- `backend/.env.example` 里的 `MINIO_SECRET_KEY=minioadmin`（market）等模板占位符仍未纳入弱值清单。
