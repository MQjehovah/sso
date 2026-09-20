# 安全基线（APP_ENV 分级）实施计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 用统一的 `APP_ENV` 分级策略消除 6 个仓库中的不安全默认值（弱 secret、固定 admin 口令、通配 CORS + credentials），并把仍入库的凭证改为环境变量注入。

**Architecture:** 每个仓库内部实现一份行为一致的 env 守卫（跨仓库无包边界，只共享约定），在配置模块加载时校验；生产缺失/弱值 → 启动失败，开发 → 告警放行。

**Tech Stack:** Python 3.10+/FastAPI/pydantic-settings（rag、agent、market）；TypeScript（router 的 Fastify 两包、sso 的 node:http、dashboard 的 Electron 主进程）。

**设计依据：** `sso/docs/plans/2026-09-20-security-baseline-design.md`

---

## 共享约定（每个任务都适用）

- `APP_ENV` 默认 `development`；`production`/`prod`（大小写不敏感）为生产。
- 弱值清单（跨仓库统一）：
  `change-me-in-production`, `dev-secret-change-me-please-32-bytes-minimum`, `default-secret`, `default-key`, `xzyz2022!`, `admin123`, `123456`, `change-me`, `gateway-secret`, `agent-secret`, `your-secret-key`
- 守卫语义：

```
require_secret(name, value, weak_values):
    bad = (value 为空/None) or (value in weak_values)
    if not bad: return value
    if is_production: raise 错误("<name> 未配置或仍为不安全的默认值,请参考 .env.example 设置")
    else: 打印 WARNING("<name> 使用默认/弱值;生产环境将拒绝启动"); return value
```

- `.env.example` 中的 `change-me*` 占位符**属于弱值**，因此它们只能用于 `development`；生产必须替换。这是刻意设计。

---

## Task 1: rag — env 守卫 + CORS 白名单 + .env.example 补齐

**Files:** 新增 `backend/app/core/env_guard.py`；改 `backend/app/config.py`、`backend/app/main.py`、`backend/.env.example`；测试 `backend/tests/core/test_env_guard.py`

**Step 1: 写失败测试**

`backend/tests/core/test_env_guard.py`：

```python
import pytest

from app.core.env_guard import WEAK_VALUES, is_production, require_secret


def test_production_拒绝弱值(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(RuntimeError, match="JWT_SECRET_KEY"):
        require_secret("JWT_SECRET_KEY", "change-me-in-production")


def test_production_拒绝空值(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(RuntimeError):
        require_secret("MINIO_SECRET_KEY", "")


def test_development_放行但告警(monkeypatch, capsys):
    monkeypatch.setenv("APP_ENV", "development")
    assert require_secret("JWT_SECRET_KEY", "change-me-in-production") == "change-me-in-production"
    assert "WARNING" in capsys.readouterr().out.upper() or "警告" in capsys.readouterr().out


def test_正常值直接返回(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    assert require_secret("JWT_SECRET_KEY", "a-very-long-random-secret") == "a-very-long-random-secret"


def test_is_production_识别(monkeypatch):
    for v in ("production", "PROD", "Prod"):
        monkeypatch.setenv("APP_ENV", v)
        assert is_production() is True
    monkeypatch.setenv("APP_ENV", "development")
    assert is_production() is False


def test_弱值清单包含已知默认值():
    for weak in ("change-me-in-production", "xzyz2022!", "123456", "default-key"):
        assert weak in WEAK_VALUES
```

**Step 2: 运行确认失败** → `py -3.12 -m pytest tests/core/test_env_guard.py -q`，应因模块不存在而失败。

**Step 3: 实现 `backend/app/core/env_guard.py`**

```python
"""环境分级的安全配置守卫。

生产(APP_ENV=production/prod)下,弱值或缺失的秘密必须让进程启动失败;
开发下放行并打印告警。跨仓库保持同样的语义与弱值清单。
"""
import logging
import os

logger = logging.getLogger(__name__)

WEAK_VALUES = {
    "change-me-in-production",
    "dev-secret-change-me-please-32-bytes-minimum",
    "default-secret",
    "default-key",
    "xzyz2022!",
    "admin123",
    "123456",
    "change-me",
    "gateway-secret",
    "agent-secret",
    "your-secret-key",
}

_PRODUCTION_NAMES = {"production", "prod"}


def is_production() -> bool:
    return (os.environ.get("APP_ENV", "development").strip().lower() in _PRODUCTION_NAMES)


def require_secret(name: str, value: str | None, weak_values: set[str] = WEAK_VALUES) -> str | None:
    """校验秘密类配置:生产拒绝弱值/空值,开发放行并告警。"""
    bad = (value is None) or (str(value).strip() == "") or (value in weak_values)
    if not bad:
        return value
    if is_production():
        raise RuntimeError(
            f"环境变量 {name} 未配置或仍为不安全的默认值,请参考 .env.example 设置"
        )
    logger.warning("%s 使用默认/弱值;生产环境(APP_ENV=production)将拒绝启动", name)
    return value
```

**Step 4: 接入 `config.py`**

pydantic-settings 的字段是类属性默认值，需要在 `Settings` 实例化后校验。最简单且符合"启动失败"语义的做法：在 `config.py` 模块末尾（`settings = Settings()` 之后）加：

```python
from app.core.env_guard import require_secret

require_secret("JWT_SECRET_KEY", settings.jwt_secret_key)
require_secret("LOCAL_ADMIN_PASSWORD", settings.local_admin_password)
require_secret("MINIO_SECRET_KEY", settings.minio_secret_key)
```

**Step 5: CORS 白名单**

`config.py` 新增：

```python
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
```

`main.py` 改为：

```python
    origins = [o.strip() for o in settings.cors_origins.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials="*" not in origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
```

**Step 6: `.env.example` 补齐**

补：`APP_ENV=development`、`CORS_ORIGINS=...`、`JWT_SECRET_KEY=change-me`、`LOCAL_ADMIN_PASSWORD=change-me`、`MINIO_ENDPOINT/ACCESS_KEY/SECRET_KEY/BUCKET/SECURE`、SSO 六项、`IMAGE_SIGN_SECRET/TTL`、`MULTIMODAL_ENABLED`、`LLM_BASE_URL/LLM_MODEL/LLM_API_URL`。值一律用 `change-me*` 占位（生产必须替换）。

**Step 7: 验证并提交**

```
py -3.12 -m pytest tests/core/test_env_guard.py -q
py -3.12 -m pytest -q          # 必须仍为 0 收集错误
py -3.12 -m ruff check app tests
APP_ENV=production py -3.12 -c "import app.config"   # 期望:因弱值抛错
```
```bash
git add backend/app/core/env_guard.py backend/app/config.py backend/app/main.py backend/.env.example backend/tests/core/test_env_guard.py
git commit -m "feat(rag): 引入 APP_ENV 分级守卫,CORS 改白名单并补齐 env 模板"
```

> 注意：先跑一次 `APP_ENV=production` 的导入检查确认**确实失败**，再用 `APP_ENV=development` 确认**可以导入**（因为默认值就是弱值）。若 `settings` 在别处被 import 时就会触发，确认这符合"启动失败"预期。

---

## Task 2: router — env 守卫 + CORS 白名单

**Files:** 新增 `admin/src/env.ts`、`gateway/src/env.ts`；改 `admin/src/index.ts`、`admin/src/routes/internal.ts`、`admin/src/routes/providers.ts`、`admin/src/routes/sso.ts`、`gateway/src/app.ts`；`admin/.env.example` / `gateway/.env.example`（若存在）

**Step 1: 写 `admin/src/env.ts`**（`gateway/src/env.ts` 同构，注意路径/包名）

```ts
/** 环境分级的安全配置守卫(与平台其他服务保持同一约定)。 */
export const WEAK_VALUES = new Set([
  'change-me-in-production',
  'dev-secret-change-me-please-32-bytes-minimum',
  'default-secret',
  'default-key',
  'xzyz2022!',
  'admin123',
  '123456',
  'change-me',
  'gateway-secret',
  'agent-secret',
  'your-secret-key'
]);

export function isProduction(): boolean {
  const v = (process.env.APP_ENV ?? 'development').trim().toLowerCase();
  return v === 'production' || v === 'prod';
}

export function requireSecret(name: string, value: string | undefined): string {
  const bad = !value || value.trim() === '' || WEAK_VALUES.has(value);
  if (!bad) return value as string;
  if (isProduction()) {
    throw new Error(`环境变量 ${name} 未配置或仍为不安全的默认值,请参考 .env.example 设置`);
  }
  console.warn(`[env] ${name} 使用默认/弱值;生产环境(APP_ENV=production)将拒绝启动`);
  return value as string;
}

/** 按逗号解析 CORS 白名单;默认仅本机。 */
export function corsOrigins(): string[] {
  const raw = process.env.CORS_ORIGINS ?? 'http://localhost:5173,http://127.0.0.1:5173';
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}
```

**Step 2: 替换弱默认**

- `admin/src/routes/internal.ts:229`、`providers.ts:121,169,208`、`sso.ts:81`：
  `process.env.ENCRYPTION_KEY || 'default-key'` → `requireSecret('ENCRYPTION_KEY', process.env.ENCRYPTION_KEY)`
- `admin/src/index.ts:48`：`secret: process.env.JWT_SECRET || 'default-secret'` → `secret: requireSecret('JWT_SECRET', process.env.JWT_SECRET)`

**Step 3: CORS 白名单**

- `admin/src/index.ts:24` 的 `origin: true` → 由 `corsOrigins()` 驱动。
- `gateway/src/app.ts:16` 的 `origin: true` → 同。
- 两处都保留 `credentials: true` 但**仅**在显式白名单下（`corsOrigins()` 永不含 `*`）。

**Step 4: 验证与提交**

```
cd admin; npm run build; npm run test
cd gateway; npm run build; npm run test
```
另外用 `APP_ENV=production node -e "require('./admin/dist/env.js') ..."` 或一个小脚本确认生产下缺 `JWT_SECRET` 会抛错（或用一个针对 `requireSecret` 的单测）。
```bash
git add admin/src/env.ts gateway/src/env.ts admin/src gateway/src admin/.env.example gateway/.env.example
git commit -m "feat(router): 引入 APP_ENV 分级守卫,CORS 改白名单"
```

---

## Task 3: agent — 首次口令 + JWT_SECRET 守卫 + mcp 凭证移出

**Files:** 新增 `src/utils/env_guard.py`；改 `src/web/server.py`、`config/mcp_servers.json`、`config/agents/设备运维/mcp_servers.json`、`.env.example`、`AGENTS.md`；测试 `tests/unit/test_env_guard.py`

**Step 1:** 复用 Task 1 的 `env_guard.py` 内容放到 `src/utils/env_guard.py`（保留同样的 `WEAK_VALUES`/`is_production`/`require_secret`）。

**Step 2: 首次初始化口令**

`src/web/server.py` 约 `:866-889` 的首次初始化分支：

```python
import secrets
from utils.env_guard import require_secret

def _initial_admin_password() -> str:
    """首次初始化 admin 的口令:生产必须显式配置;开发缺省时随机生成并打印一次。"""
    configured = os.environ.get("AGENT_ADMIN_PASSWORD", "")
    if configured:
        return configured
    if is_production():
        raise RuntimeError("环境变量 AGENT_ADMIN_PASSWORD 未配置,生产环境拒绝创建默认管理员")
    generated = secrets.token_urlsafe(12)
    logger.warning("未配置 AGENT_ADMIN_PASSWORD,已生成一次性 admin 口令:%s(仅本次打印)", generated)
    return generated
```

把 `storage.set_user_password(user_id, "admin123")` 与其"admin/admin123"日志改为使用该函数；日志不得再回显固定口令。

**Step 3: JWT_SECRET**

`src/web/server.py:38` 附近读取 `JWT_SECRET` 处改为 `require_secret("JWT_SECRET", os.environ.get("JWT_SECRET", ""))`（保留其后的现有回退逻辑用于开发）。

**Step 4: mcp 凭证移出**

按钉钉/飞书已用的 `apply_env_overrides` 方式，把两个 `mcp_servers.json` 中的 `SMTP_PASSWORD` 与 `DEVICE_API_PASSWORD` 改为从环境变量取值（直接 `os.environ` 注入子进程，或沿用现有占位符机制）；配置文件中改为占位符；真实值写入本机 gitignored `.env`；更新 `.env.example` 与 `AGENTS.md`。用 `git grep` 确认仓库内不再出现真实值。

**Step 5: 验证与提交**

```
ruff check src/ tests/
pytest tests/unit/test_env_guard.py -q
pytest tests/ -q --tb=no --continue-on-collection-errors   # 基线 31 failed/320 passed/43 errors,不得新增失败
git grep -n "SMTP_PASSWORD\|DEVICE_API_PASSWORD" config    # 不得再出现真实值
```
```bash
git add src/utils/env_guard.py src/web/server.py config .env.example AGENTS.md tests/unit/test_env_guard.py
git commit -m "feat(agent): 引入 APP_ENV 守卫,去掉固定 admin 口令并移出 mcp 凭证"
```

---

## Task 4: market — env 守卫

**Files:** 新增 `backend/app/core/env_guard.py`；改 `backend/app/config.py`、`backend/.env.example`；测试 `backend/tests/test_env_guard.py`

**Step 1:** 复用 Task 1 的 `env_guard.py`。

**Step 2:** 在 `config.py` 的 `settings = Settings()` 之后校验：

```python
require_secret("JWT_SECRET", settings.jwt_secret)
require_secret("SEED_ADMIN_PASSWORD", settings.seed_admin_password)
```

**Step 3:** 种子管理员的创建处（搜索 `seed_admin_username`/`seed_admin_password` 的使用）在生产且未配置时不得落库固定口令；开发缺省时随机生成并打印一次（与 Task 3 同法）。

**Step 4:** `.env.example` 补 `APP_ENV=development`。

**Step 5: 验证与提交**

```
cd backend; py -3.12 -m pytest tests/test_env_guard.py -q
py -3.12 -m pytest -q        # 既有 5 failed/72 passed 基线;不得新增失败
```
```bash
git add backend/app/core/env_guard.py backend/app/config.py backend/.env.example backend/tests/test_env_guard.py
git commit -m "feat(market): 引入 APP_ENV 分级守卫"
```

---

## Task 5: sso — cookie Secure + 表单 CSRF

**Files:** 改 `src/protocol.ts`；新增 `src/csrf.ts`；测试 `test/csrf.test.ts`（node:test）

**Step 1: cookie Secure**

新增小工具（`src/cookies.ts` 或直接放 `protocol.ts`）：

```ts
/** https issuer 下会话 cookie 追加 Secure;本地 http 开发不加,否则浏览器不发送。 */
function sessionCookieAttrs(): string {
  const secure = config.issuer.startsWith('https://') ? '; Secure' : ''
  return `Path=/; HttpOnly; SameSite=Lax${secure}`
}
```

`issueCodeRedirect`（`:143-144`）与 `clearCookie()`（`:466`）都改用该属性串，保持两处一致。

**Step 2: CSRF**

新增 `src/csrf.ts`，用 `node:crypto` HMAC（复用与 `image_sign` 同款思路，密钥取 `SSO_CSRF_SECRET` 或回退一个进程级随机值）：

```ts
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

const secret = process.env.SSO_CSRF_SECRET || randomBytes(32).toString('hex')

export function issueCsrf(sid: string): string {
  const exp = Date.now() + 30 * 60_000
  const sig = createHmac('sha256', secret).update(`${sid}:${exp}`).digest('hex')
  return `${exp}.${sig}`
}

export function verifyCsrf(sid: string, token: string | undefined): boolean {
  if (!token) return false
  const [expStr, sig] = token.split('.')
  const exp = Number(expStr)
  if (!Number.isFinite(exp) || exp < Date.now()) return false
  const expected = createHmac('sha256', secret).update(`${sid}:${exp}`).digest('hex')
  const a = Buffer.from(sig ?? '', 'utf-8')
  const b = Buffer.from(expected, 'utf-8')
  return a.length === b.length && timingSafeEqual(a, b)
}
```

- `loginPage({...})` 与 `profilePage({...})` 的渲染参数加入 `csrf`（由 `issueCsrf(txId)` / `issueCsrf(session.sid)` 生成），模板里 `<input type="hidden" name="csrf" value="...">`。
- `handlePasswordLogin` 与 `handleProfilePassword` 在读取表单后校验 `verifyCsrf(...)`，失败返回 400 并提示"页面已过期,请重新打开登录页"。
- 注意：登录页的用例中，`txId` 在 `takeTx` 后仍可用；改密页用 `session.sid`。

**Step 3: 测试**

`test/csrf.test.ts`：有效 token 通过；过期失败；篡改 sig 失败；空 token 失败；不同 sid 失败。
扩展 `test/run-smoke.mjs`：登录页 HTML 含 `name="csrf"`；不带 csrf 的密码登录返回 400；带 csrf 的正常登录成功（用已有流程，按需解析登录页取 token）。

**Step 4: 验证与提交**

```
npm run typecheck; npm test; npm run test:smoke
```
```bash
git add src/cookies.ts src/csrf.ts src/render.ts src/protocol.ts test/csrf.test.ts test/run-smoke.mjs .env.example
git commit -m "feat(sso): 会话 cookie 按需 Secure,登录/改密表单加 CSRF 校验"
```

---

## Task 6: dashboard — issuer 去硬编码必填

**Files:** 改 `electron/main/identity.ts`、`electron/main/oidc-config.ts`、`src/views/SettingsView.vue`（如已有 issuer 配置项则复用它）

**Step 1:** 按上一阶段 `oidcClientSecret` 的同一模式，把 `issuer()` 改为：

```ts
function issuer(): string {
  const value = (process.env.OIDC_ISSUER ?? '').trim() || getConfig().oidcIssuer.trim()
  if (!value) {
    throw new Error('未配置 OIDC Issuer(请由安装包或企业配置注入),无法完成企业 SSO 登录')
  }
  return value.replace(/\/+$/, '')
}
```

配套：`store.ts` 的 `AppConfig` 增 `oidcIssuer`（默认空串）、设置页加输入项、`oidc-config.ts` 增 `resolveOidcIssuer(env, cfg)` 纯函数并加单测（env 优先、空白视为未配置、缺失抛中文错误）。

**Step 2: 验证与提交**

```
npm test; npm run typecheck; npm run build
```
```bash
git add electron/main/identity.ts electron/main/oidc-config.ts electron/main/store.ts src/stores/settings.ts src/views/SettingsView.vue test/kernel/oidc-config.test.ts
git commit -m "fix(dashboard): OIDC issuer 去掉硬编码默认,改为必填配置"
```

---

## Task 7: 跨仓库验收

**Step 1: 弱值扫描**

```bash
# 在每个仓库执行
git grep -nE "xzyz2022!|admin123(?![0-9])|default-secret|'default-key'|\"default-key\"|change-me-in-production" -- . ':(exclude)*.example*' ':(exclude).env.example'
```
期望：仅剩守卫模块自身的弱值清单（`env_guard.py` / `env.ts`）与测试文件；`.env.example` 的占位符按白名单豁免。逐条说明剩余命中。

**Step 2: 生产启动必须失败**

对每个服务，用 `APP_ENV=production` + 弱值环境启动，确认**进程启动失败**且错误信息含变量名；再用 `APP_ENV=development` 确认可启动。把每个服务的实际输出记录到设计文档的「实施结果」小节。

**Step 3: CORS 组合**

```bash
git grep -n "origin: true" -- router
git grep -n 'allow_origins=\["\*"\]' -- rag
```
期望：无命中。

**Step 4: 各仓库测试**

逐仓跑既有测试并记录前后对比（rag 99 passed、dashboard 174 passed、router 14+15 passed、sso 单测+烟测、agent/market 基线不新增失败）。前端 `npm run build` 通过。

**Step 5: 记录并提交**

把结果写入 `sso/docs/plans/2026-09-20-security-baseline-design.md` 的「实施结果」小节并提交。

---

## 已知限制

- 弱值清单是硬编码枚举，无法拦截清单外的新弱值；应随发现补充。
- 「开发放行」意味着本地开发仍可能用弱值跑起来——这是刻意的取舍，但 CI 应以 `APP_ENV=production` 跑一次导入/启动检查，防止弱值回流。
- 本阶段不引入密钥管理服务；秘密仍是明文环境变量。
