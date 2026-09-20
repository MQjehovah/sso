# SSO 密钥轮换 / 吊销收紧 / Secret 清理 实施计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 让 SSO 的签名密钥可零中断轮换、把登出/改密/离职的失效窗口从最长 7 天收敛到 12 小时、并把已泄露到公网的 client_secret 全部作废外置。

**Architecture:** SSO 由单密钥改为「密钥环」（多把密钥 + `active` 指针 + `meta.json` 状态），JWKS 一并发布 active/verifying 公钥；签发始终用 active。吊销不引入新协议，改为收紧 TTL：SSO access_token 降到 10 分钟，五个业务系统本地会话统一降到 12 小时（可配），refresh token 增加 `auth_time` 绝对上限防止旋转续期。client_secret 从仓库移出，改为 `${ENV:}` 占位由部署环境注入并全部轮换。

**Tech Stack:** Node.js 22 + TypeScript（原生类型擦除）、`jose`（JWKS/JWT）、`node:test`（新增单测）、Node HTTP、各客户端 Python 3.10 / Fastify。

**设计依据：** `sso/docs/plans/2026-09-20-keys-revocation-secrets-design.md`

---

## 前置说明（务必先读）

### 本机 Node 版本问题（阻塞项）

本机为 **Node v22.14.0**，`node src/index.ts` 会报 `ERR_UNKNOWN_FILE_EXTENSION`；必须加 `--experimental-strip-types`。已实测：加该参数后服务可正常启动，`npm run key:*` 也需同样处理。

- 本计划会把 `package.json` 的 scripts 统一加上 `--experimental-strip-types`。
- 若生产使用 Node ≥ 22.18，该参数为无操作，加着无害。

### 事实澄清（避免改错地方）

| 系统 | 角色 | 是否持有 client_secret | 本地会话 |
|---|---|---|---|
| agent | OIDC 客户端 + 资源服务 | ✅ `agent` | 自签 HS256 JWT，**7 天**（`src/web/server.py:58`）|
| dashboard | OIDC 客户端 | ✅ `dashboard-gateway`（另有硬编码兜底）| 持有 SSO refresh_token，自动续期 |
| market | 纯资源服务（只验 RS256）| ❌ 不调用 `/token` | 自签 JWT，**24h**（`backend/app/config.py:31`）|
| rag | 纯资源服务（只验 RS256）| ❌ | 自签 HS256，**24h**（`backend/app/config.py:63`）|
| router | 纯资源服务（`/internal/sso/exchange` 验 id_token）| ❌ | fastify.jwt 自签，**未显式设置** |

因此：**需要真正轮换的 client_secret 只有 `agent` 与 `dashboard-gateway` 两个**；`clients.json` 里 market/rag/router-admin/zhongtai-oa 的 secret 从未用于客户端认证，一并清理即可。

### 每个 Task 结束后都要提交

提交信息遵循 Conventional Commits，仓库内已有中文描述习惯。

---

## Task 1: 搭建 SSO 单元测试基础设施

**Files:**
- Modify: `sso/package.json`
- Create: `sso/test/keys.test.ts`

**Step 1: 修改 package.json scripts**

把 scripts 改为（保留原有 smoke 脚本）：

```json
"scripts": {
  "start": "node --experimental-strip-types --env-file-if-exists=.env src/index.ts",
  "dev": "node --experimental-strip-types --watch --env-file-if-exists=.env src/index.ts",
  "typecheck": "tsc --noEmit -p tsconfig.json",
  "test": "node --experimental-strip-types --test test/*.test.ts",
  "test:smoke": "node --experimental-strip-types test/run-smoke.mjs",
  "test:mock-dingtalk": "node test/mock-dingtalk.mjs"
}
```

**Step 2: 写一个必然失败的测试**

Create `sso/test/keys.test.ts`：

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'

test('smoke: 测试框架可用', () => {
  assert.equal(1 + 1, 2)
})
```

**Step 3: 运行确认通过**

Run: `npm test`（在 `sso/` 下）
Expected: `pass 1`，退出码 0。

**Step 4: 提交**

```bash
git add sso/package.json sso/test/keys.test.ts
git commit -m "test(sso): 引入 node:test 单元测试基础设施并修正 strip-types 启动"
```

---

## Task 2: 密钥环模块 `keyring.ts`

**Files:**
- Create: `sso/src/keyring.ts`
- Modify: `sso/test/keys.test.ts`

**Step 1: 写失败测试**

把 `sso/test/keys.test.ts` 改为（注意：keyring 的目录由构造参数注入，便于测试隔离）：

```ts
import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { KeyRing } from '../src/keyring.ts'

let dir: string
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'keyring-')) })
afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

test('首次创建:生成 active 密钥并落盘', async () => {
  const ring = new KeyRing(dir)
  const active = await ring.ensureActive()
  assert.ok(active.kid)
  assert.ok(existsSync(join(dir, 'active')))
  assert.ok(existsSync(join(dir, `${active.kid}.pem`)))
  assert.equal(ring.list().filter((k) => k.status === 'active').length, 1)
})

test('重复 ensureActive 不重复生成', async () => {
  const ring = new KeyRing(dir)
  const a = await ring.ensureActive()
  const b = await ring.ensureActive()
  assert.equal(a.kid, b.kid)
  assert.equal(ring.list().length, 1)
})

test('轮换:active 切换,旧密钥转 verifying 且仍可取公钥', async () => {
  const ring = new KeyRing(dir)
  const oldKid = (await ring.ensureActive()).kid
  const { previous, current } = await ring.rotate()
  assert.equal(previous, oldKid)
  assert.notEqual(current, oldKid)
  const byKid = Object.fromEntries(ring.list().map((k) => [k.kid, k.status]))
  assert.equal(byKid[oldKid], 'verifying')
  assert.equal(byKid[current], 'active')
  // JWKS 同时包含新旧两把
  assert.equal(ring.publicJwks().keys.length, 2)
})

test('prune:超出退休窗口的 verifying 转 retired 并移出 JWKS', async () => {
  const ring = new KeyRing(dir)
  const oldKid = (await ring.ensureActive()).kid
  await ring.rotate()
  await ring.prune(0) // 窗口 0 小时 => 立刻可退休
  const byKid = Object.fromEntries(ring.list().map((k) => [k.kid, k.status]))
  assert.equal(byKid[oldKid], 'retired')
  assert.equal(ring.publicJwks().keys.length, 1)
})

test('签名密钥始终是 active', async () => {
  const ring = new KeyRing(dir)
  const oldKid = (await ring.ensureActive()).kid
  await ring.rotate()
  const signing = await ring.signingKey()
  assert.notEqual(signing.kid, oldKid)
})

test('按 kid 取验签公钥,未知 kid 返回 null', async () => {
  const ring = new KeyRing(dir)
  const { kid } = await ring.ensureActive()
  assert.ok(ring.publicKeyFor(kid))
  assert.equal(ring.publicKeyFor('deadbeef'), null)
})
```

**Step 2: 运行确认失败**

Run: `npm test`
Expected: FAIL —— `Cannot find module '../src/keyring.ts'`

**Step 3: 实现 `sso/src/keyring.ts`**

```ts
import { createPublicKey, generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { importPKCS8, type CryptoKey } from 'jose'

/**
 * RS256 密钥环:目录内存放多把密钥,active 指针决定签发密钥,
 * verifying 密钥继续发布公钥以验签历史 token,retired 密钥移出 JWKS。
 *
 * 目录布局:
 *   <dir>/active            文本,内容为当前签名 kid
 *   <dir>/<kid>.pem         PKCS8 私钥 (0600)
 *   <dir>/<kid>.meta.json   { kid, createdAt, status }
 */
export type KeyStatus = 'active' | 'verifying' | 'retired'

export interface KeyMeta {
  kid: string
  createdAt: number
  status: KeyStatus
}

export interface SigningKey {
  kid: string
  pkcs8: string
  privateKey: CryptoKey
}

export class KeyRing {
  private readonly dir: string
  private signing: SigningKey | null = null
  private jwksCache: { keys: Record<string, unknown>[] } | null = null

  constructor(dir: string) {
    this.dir = dir
    mkdirSync(this.dir, { recursive: true })
  }

  private activeKidPath(): string {
    return join(this.dir, 'active')
  }

  private pemPath(kid: string): string {
    return join(this.dir, `${kid}.pem`)
  }

  private metaPath(kid: string): string {
    return join(this.dir, `${kid}.meta.json`)
  }

  private readMeta(kid: string): KeyMeta | null {
    try {
      return JSON.parse(readFileSync(this.metaPath(kid), 'utf-8')) as KeyMeta
    } catch {
      return null
    }
  }

  private writeMeta(meta: KeyMeta): void {
    writeFileSync(this.metaPath(meta.kid), JSON.stringify(meta), { mode: 0o600 })
  }

  private activeKid(): string | null {
    try {
      return readFileSync(this.activeKidPath(), 'utf-8').trim() || null
    } catch {
      return null
    }
  }

  private setActive(kid: string): void {
    const tmp = this.activeKidPath() + '.tmp'
    writeFileSync(tmp, kid, { mode: 0o600 })
    renameSync(tmp, this.activeKidPath())
    this.signing = null
    this.jwksCache = null
  }

  private generate(): KeyMeta {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
    const kid = randomBytes(8).toString('hex')
    writeFileSync(this.pemPath(kid), pem, { mode: 0o600 })
    const meta: KeyMeta = { kid, createdAt: Date.now(), status: 'active' }
    this.writeMeta(meta)
    return meta
  }

  /** 兼容旧布局:private.pem + kid => <kid>.pem + <kid>.meta.json + active */
  migrateLegacy(): boolean {
    const legacyPem = join(this.dir, 'private.pem')
    const legacyKid = join(this.dir, 'kid')
    if (this.activeKid() || !existsSync(legacyPem) || !existsSync(legacyKid)) return false
    const kid = readFileSync(legacyKid, 'utf-8').trim()
    if (!kid) return false
    renameSync(legacyPem, this.pemPath(kid))
    renameSync(legacyKid, this.metaPath(kid))
    this.writeMeta({ kid, createdAt: Date.now(), status: 'active' })
    this.setActive(kid)
    this.jwksCache = null
    return true
  }

  /** 确保存在 active 密钥(无则生成),返回其 kid */
  async ensureActive(): Promise<KeyMeta> {
    this.migrateLegacy()
    const kid = this.activeKid()
    if (kid) {
      const meta = this.readMeta(kid)
      if (meta) return meta
    }
    const meta = this.generate()
    this.setActive(meta.kid)
    return meta
  }

  /** 生成新密钥并切换 active,旧 active 转 verifying */
  async rotate(): Promise<{ previous: string | null; current: string }> {
    const previous = this.activeKid()
    if (previous) {
      const meta = this.readMeta(previous)
      if (meta) this.writeMeta({ ...meta, status: 'verifying' })
    }
    const created = this.generate()
    this.setActive(created.kid)
    this.jwksCache = null
    return { previous, current: created.kid }
  }

  list(): KeyMeta[] {
    const out: KeyMeta[] = []
    for (const f of readdirSync(this.dir)) {
      if (!f.endsWith('.meta.json')) continue
      const meta = this.readMeta(f.slice(0, -'.meta.json'.length))
      if (meta) out.push(meta)
    }
    return out.sort((a, b) => a.createdAt - b.createdAt)
  }

  /** 把 verifying 且超过 retireAfterMs 的密钥置 retired(移出 JWKS);返回新退休的 kid */
  async prune(retireAfterHours: number): Promise<string[]> {
    const cutoff = Date.now() - retireAfterHours * 3_600_000
    const retired: string[] = []
    for (const meta of this.list()) {
      if (meta.status === 'verifying' && meta.createdAt <= cutoff) {
        this.writeMeta({ ...meta, status: 'retired' })
        retired.push(meta.kid)
      }
    }
    if (retired.length) this.jwksCache = null
    return retired
  }

  retire(kid: string): boolean {
    const meta = this.readMeta(kid)
    if (!meta || meta.status === 'active') return false
    this.writeMeta({ ...meta, status: 'retired' })
    this.jwksCache = null
    return true
  }

  /** 当前签发密钥(kid + 私钥) */
  async signingKey(): Promise<SigningKey> {
    await this.ensureActive()
    const kid = this.activeKid()!
    if (!this.signing || this.signing.kid !== kid) {
      const pkcs8 = readFileSync(this.pemPath(kid), 'utf-8')
      this.signing = { kid, pkcs8, privateKey: await importPKCS8(pkcs8, 'RS256') }
    }
    return this.signing
  }

  /** 按 kid 取验签公钥;retired / 不存在返回 null */
  publicKeyFor(kid: string): KeyObject | null {
    const meta = this.readMeta(kid)
    if (!meta || meta.status === 'retired') return null
    try {
      return createPublicKey(readFileSync(this.pemPath(kid), 'utf-8'))
    } catch {
      return null
    }
  }

  /** JWKS:active + verifying 的公钥 */
  publicJwks(): { keys: Record<string, unknown>[] } {
    if (this.jwksCache) return this.jwksCache
    const keys: Record<string, unknown>[] = []
    for (const meta of this.list()) {
      if (meta.status === 'retired') continue
      const pub = this.publicKeyFor(meta.kid)
      if (!pub) continue
      const jwk = pub.export({ format: 'jwk' }) as Record<string, unknown>
      keys.push({ ...jwk, kid: meta.kid, use: 'sig', alg: 'RS256' })
    }
    this.jwksCache = { keys }
    return this.jwksCache
  }
}
```

**Step 4: 运行确认通过**

Run: `npm test`
Expected: 全部 `pass`。

**Step 5: 提交**

```bash
git add sso/src/keyring.ts sso/test/keys.test.ts
git commit -m "feat(sso): 新增 RS256 密钥环(多密钥/轮换/退休窗口)"
```

---

## Task 3: 用密钥环替换 `keys.ts` 单密钥实现

**Files:**
- Modify: `sso/src/keys.ts`
- Modify: `sso/src/config.ts`（新增 `keyRetireAfterHours`）

**Step 1: 改写 `sso/src/keys.ts`**

整体替换为（保持 `getSigningKey` / `getPublicJwk` / `getPublicKey` 之外的新接口 `getPublicKeyFor`）：

```ts
import { config } from './config.ts'
import { KeyRing, type SigningKey } from './keyring.ts'

/**
 * 全局密钥环单例。旧版单密钥(private.pem + kid)会在首次访问时自动迁移。
 */
let ring: KeyRing | null = null

export function keyRing(): KeyRing {
  if (!ring) {
    ring = new KeyRing(config.keysDir)
    if (ring.migrateLegacy()) {
      console.log('[keys] 已从单密钥布局迁移到密钥环')
    }
  }
  return ring
}

export async function getSigningKey(): Promise<SigningKey> {
  return keyRing().signingKey()
}

/** JWKS:active + verifying 公钥 */
export function getPublicJwks(): { keys: Record<string, unknown>[] } {
  return keyRing().publicJwks()
}

/** 按 kid 取验签公钥(Object);不存在/已退休返回 null */
export function getPublicKeyFor(kid: string | undefined) {
  if (!kid) {
    // 无 kid 时用 active 兜底(兼容极老的 token)
    const active = keyRing().list().find((k) => k.status === 'active')
    return active ? keyRing().publicKeyFor(active.kid) : null
  }
  return keyRing().publicKeyFor(kid)
}
```

**Step 2: 在 `sso/src/config.ts` 增加退休窗口配置**

在 `config` 对象内、`clientsPath` 之前加入：

```ts
  /** 密钥退休窗口:verifying 密钥超过该时长后移出 JWKS(小时) */
  keyRetireAfterHours: Number(process.env.SSO_KEY_RETIRE_AFTER_HOURS ?? 2),
```

**Step 3: 更新调用方**

`grep -rn "getPublicJwk\|getPublicKey" sso/src` 找到所有调用点：

- `sso/src/protocol.ts:7` 的 import 改为 `getSigningKey, getPublicJwks, getPublicKeyFor`
- `sso/src/protocol.ts:88` `handleJwks` 改为 `json(res, 200, getPublicJwks())`
- `sso/src/protocol.ts:366` `handleUserinfo` 的 `jwtVerify(auth.slice(7), getPublicKey(), …)` 改为：
  先取 header kid，再取公钥：

```ts
    const header = JSON.parse(Buffer.from(auth.slice(7).split('.')[0], 'base64url').toString('utf-8')) as { kid?: string }
    const pub = getPublicKeyFor(header.kid)
    if (!pub) return json(res, 401, { error: 'invalid_token' })
    const { payload } = await jwtVerify(auth.slice(7), pub, { issuer: config.issuer })
```

**Step 4: 类型检查与测试**

Run: `npm run typecheck; npm test`
Expected: 无类型错误；测试通过。

**Step 5: 提交**

```bash
git add sso/src/keys.ts sso/src/config.ts sso/src/protocol.ts
git commit -m "refactor(sso): keys.ts 改用密钥环,JWKS 发布多密钥"
```

---

## Task 4: 密钥管理 CLI

**Files:**
- Create: `sso/src/cli/keys.ts`
- Modify: `sso/package.json`

**Step 1: 实现 `sso/src/cli/keys.ts`**

```ts
import { keyRing } from '../keys.ts'
import { config } from '../config.ts'

/**
 * 密钥运维 CLI:
 *   node --experimental-strip-types src/cli/keys.ts rotate
 *   node --experimental-strip-types src/cli/keys.ts list
 *   node --experimental-strip-types src/cli/keys.ts prune
 *   node --experimental-strip-types src/cli/keys.ts retire <kid>
 */
async function main(): Promise<void> {
  const [cmd, arg] = process.argv.slice(2)
  const ring = keyRing()

  switch (cmd) {
    case 'rotate': {
      await ring.ensureActive()
      const { previous, current } = await ring.rotate()
      console.log(`[keys] 轮换完成: ${previous ?? '(无)'} -> ${current}`)
      console.log(`[keys] 旧密钥保留验签 ${config.keyRetireAfterHours} 小时后可执行 prune 退休`)
      return
    }
    case 'list': {
      await ring.ensureActive()
      for (const k of ring.list()) {
        console.log(`${k.status.padEnd(9)} ${k.kid}  ${new Date(k.createdAt).toISOString()}`)
      }
      return
    }
    case 'prune': {
      const retired = await ring.prune(config.keyRetireAfterHours)
      console.log(retired.length ? `[keys] 已退休: ${retired.join(', ')}` : '[keys] 无需退休')
      return
    }
    case 'retire': {
      if (!arg) throw new Error('用法: keys.ts retire <kid>')
      console.log(ring.retire(arg) ? `[keys] ${arg} 已退休` : `[keys] 无法退休 ${arg}(不存在或仍是 active)`)
      return
    }
    default:
      console.log('用法: keys.ts <rotate|list|prune|retire <kid>>')
      process.exitCode = 1
  }
}

main().catch((err: unknown) => {
  console.error('[keys] 失败:', (err as Error).message)
  process.exitCode = 1
})
```

**Step 2: 添加 npm scripts**

在 `package.json` 的 scripts 中加入：

```json
"key:rotate": "node --experimental-strip-types src/cli/keys.ts rotate",
"key:list": "node --experimental-strip-types src/cli/keys.ts list",
"key:prune": "node --experimental-strip-types src/cli/keys.ts prune",
"key:retire": "node --experimental-strip-types src/cli/keys.ts retire"
```

**Step 3: 手动验证**

Run（在 `sso/` 下，用临时目录避免污染）：

```bash
$env:SSO_ISSUER="http://127.0.0.1:18091"; $env:SSO_KEYS_DIR="./test/keys-cli"
npm run key:rotate
npm run key:list
npm run key:prune
```

Expected: `list` 输出两行（一行 active、一行 verifying）。

**Step 4: 提交**

```bash
git add sso/src/cli/keys.ts sso/package.json
git commit -m "feat(sso): 新增密钥运维 CLI(rotate/list/prune/retire)"
```

---

## Task 5: access_token / id_token TTL 参数化

**Files:**
- Modify: `sso/src/config.ts`
- Modify: `sso/src/protocol.ts`

**Step 1: 在 `config.ts` 增加**

```ts
  /** access_token 寿命(秒),默认 10 分钟;缩短以限制登出后的残留有效期 */
  accessTokenTtlSeconds: Number(process.env.SSO_ACCESS_TOKEN_TTL_SECONDS ?? 600),
  /** id_token 寿命(秒),默认 10 分钟 */
  idTokenTtlSeconds: Number(process.env.SSO_ID_TOKEN_TTL_SECONDS ?? 600),
```

**Step 2: 替换 `protocol.ts` 中两处硬编码**

`handleToken` 内共三处 `.setExpirationTime(now + 3600)`（access）与两处 `now + 600`（id）：

- 所有 access_token 的 `now + 3600` → `now + config.accessTokenTtlSeconds`
- 所有 id_token 的 `now + 600` → `now + config.idTokenTtlSeconds`
- 响应体里两处 `expires_in: 3600` → `expires_in: config.accessTokenTtlSeconds`

Run: `grep -n "3600\|now + 600" sso/src/protocol.ts`
Expected: 替换后不再有硬编码（`handleDiscovery` 里的 `jwks_uri` 等无关项除外）。

**Step 3: 更新 discovery 文档端点**

`handleDiscovery` 中加入：

```ts
    revocation_endpoint: `${iss}/logout`,
```

（可选，仅用于让客户端知道登出入口；实现前确认 dashboard 未强依赖此字段。）

**Step 4: typecheck + 提交**

Run: `npm run typecheck`
```bash
git add sso/src/config.ts sso/src/protocol.ts
git commit -m "feat(sso): access/id token TTL 参数化并默认降到 10 分钟"
```

---

## Task 6: 断言 access_token TTL 的单元测试

**Files:**
- Create: `sso/test/token-ttl.test.ts`

**Step 1: 写测试**

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { SignJWT, jwtVerify, generateKeyPair, exportJWK, importPKCS8 } from 'jose'
import { config } from '../src/config.ts'

const POLLUTED_ISSUER = 'http://127.0.0.1:18091'

test('accessTokenTtlSeconds 默认 600 且可由 env 覆盖', () => {
  // 该测试仅验证配置读取逻辑;真实 TTL 在 smoke 测试中断言
  assert.equal(typeof config.accessTokenTtlSeconds, 'number')
  assert.ok(config.accessTokenTtlSeconds > 0)
})

test('签发的 token exp-iat 等于配置的 TTL', async () => {
  const { privateKey } = await generateKeyPair('RS256', { extractable: true })
  const now = Math.floor(Date.now() / 1000)
  const ttl = config.accessTokenTtlSeconds
  const token = await new SignJWT({ scope: 'openid profile' })
    .setProtectedHeader({ alg: 'RS256', kid: 'test' })
    .setIssuer(POLLUTED_ISSUER)
    .setIssuedAt(now)
    .setExpirationTime(now + ttl)
    .sign(privateKey)
  const { payload } = await jwtVerify(token, privateKey)
  assert.equal((payload.exp as number) - (payload.iat as number), ttl)
})
```

**Step 2: 运行**

Run: `npm test`
Expected: PASS。

**Step 3: 提交**

```bash
git add sso/test/token-ttl.test.ts
git commit -m "test(sso): 断言 access_token TTL 与配置一致"
```

---

## Task 7: 修复改密未吊销 refresh token

**Files:**
- Modify: `sso/src/protocol.ts:429` 附近

**Step 1: 修改 `handleProfilePassword`**

在 `await verifier.setPassword(...)` 成功后、`audit(...)` 之前加入：

```ts
    // 改密后立即吊销该用户全部 refresh token,使其它端最迟在本端 access TTL 内失效
    revokeRefreshTokens(session.sub)
```

`revokeRefreshTokens` 已在 `protocol.ts:11` 导入，无需新增 import。

**Step 2: 扩展 smoke 测试验证**

在 `sso/test/run-smoke.mjs` 末尾（登出用例之后）新增一段：改密后旧的 refresh_token 必须无法再刷新。追加：

```js
// ---- 改密后 refresh token 必须失效 ----
{
  const jar3 = new Jar()
  const { id_token: _idt, access_token: _at, refresh_token: rtBefore } =
    await passwordLogin(jar3, '10001', 'pass123')
  assert('改密前 refresh 可用', Boolean(rtBefore))
  await changePassword(jar3, 'pass123', 'newpass123')
  const r = await fetch(`${SSO}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: rtBefore,
      client_id: 'test-web',
      client_secret: 'test-secret'
    })
  })
  assert('改密后旧 refresh 被拒', r.status === 400)
}
```

若 smoke 脚本中没有 `passwordLogin` / `changePassword` 辅助函数，需按现有代码风格抽出（参考脚本中已有的密码登录流程与 `/profile/password` 调用）。

**Step 3: 运行 smoke**

Run: `npm run test:smoke`
Expected: 新增两条断言 PASS，其余不回归。

**Step 4: 提交**

```bash
git add sso/src/protocol.ts sso/test/run-smoke.mjs
git commit -m "fix(sso): 改密后吊销全部 refresh token"
```

---

## Task 8: refresh token 每客户端 TTL + 绝对会话上限

**Files:**
- Modify: `sso/src/clients.ts`
- Modify: `sso/src/store.ts`

**Step 1: `clients.ts` 增加 `refresh_ttl_hours`**

在 `OidcClient` 接口加入：

```ts
  /** 本客户端 refresh token 有效期(小时),默认 12;决定桌面端可续登时长 */
  refresh_ttl_hours?: number
```

**Step 2: `store.ts` 改造 refresh 记录**

`RefreshTokenRecord` 增加 `auth_time: number`（首次授权时间戳 ms）。修改 `issueRefreshToken` 签名，接收 `authTime`：

```ts
export function issueRefreshToken(
  sub: string, name: string, dept: string, clientId: string,
  dingtalkUserId: string | undefined, ttlMs: number, authTime: number
): string {
  rtLoad()
  const now = Date.now()
  for (const [t, r] of refreshTokens) if (r.expires_at <= now) refreshTokens.delete(t)
  const token = randomBytes(32).toString('hex')
  // 绝对上限:expires_at 从首次授权时间算起,轮换不延长
  refreshTokens.set(token, {
    token, sub, name, dept, dingtalkUserId: dingtalkUserId || undefined,
    client_id: clientId, expires_at: authTime + ttlMs, auth_time: authTime
  })
  rtPersist()
  return token
}
```

`consumeRefreshToken` 返回值增加 `authTime`：

```ts
export function consumeRefreshToken(token: string, clientId: string):
  { sub: string; name: string; dept: string; dingtalkUserId?: string; authTime: number } | null {
  rtLoad()
  const r = refreshTokens.get(token)
  if (!r) return null
  refreshTokens.delete(token)
  rtPersist()
  if (r.client_id !== clientId || r.expires_at <= Date.now()) return null
  return { sub: r.sub, name: r.name, dept: r.dept, dingtalkUserId: r.dingtalkUserId, authTime: r.auth_time ?? Date.now() }
}
```

同时把旧的 `const RT_TTL = 7 * 24 * 3_600_000` 删除（TTL 改为调用方传入）。

**Step 3: `protocol.ts` 两处调用点适配**

- authorization_code 分支（`protocol.ts:347`）：

```ts
  const refreshTtlMs = (client.refresh_ttl_hours ?? 12) * 3_600_000
  const authTime = Date.now()
  const refreshToken = issueRefreshToken(codeRecord.sub, codeRecord.name, codeRecord.dept, clientId, codeRecord.dingtalkUserId, refreshTtlMs, authTime)
```

- refresh_token 分支（`protocol.ts:274`）：

```ts
    const refreshTtlMs = (client.refresh_ttl_hours ?? 12) * 3_600_000
    const newRefresh = issueRefreshToken(old.sub, old.name, old.dept, clientId, old.dingtalkUserId, refreshTtlMs, old.authTime)
```

**Step 4: 单元测试绝对上限**

在 `sso/test/token-ttl.test.ts` 追加（需 `SSO_DATA_DIR` 指向临时目录并在导入前设置）：

```ts
test('refresh 轮换不延长绝对会话上限', async () => {
  process.env.SSO_DATA_DIR = mkdtempSync(join(tmpdir(), 'rt-'))
  const store = await import('../src/store.ts')
  const authTime = Date.now() - 1000
  const t1 = store.issueRefreshToken('u1', 'U', 'D', 'c1', undefined, 60_000, authTime)
  const c1 = store.consumeRefreshToken(t1, 'c1')!
  const t2 = store.issueRefreshToken('u1', 'U', 'D', 'c1', undefined, 60_000, c1.authTime)
  // 第二次的过期时间仍是 authTime + 60s,只减少了已流逝的 1s
  const c2 = store.consumeRefreshToken(t2, 'c1')!
  assert.equal(c2.authTime, authTime)
})
```

> 注意：`store.ts` 有模块级 `rtLoaded` 缓存，跨测试复用同一模块实例；如需隔离用不同 `client_id`。

**Step 5: 运行并提交**

Run: `npm test`
```bash
git add sso/src/clients.ts sso/src/store.ts sso/src/protocol.ts sso/test/token-ttl.test.ts
git commit -m "feat(sso): refresh token 支持每客户端 TTL 与绝对会话上限"
```

---

## Task 9: client_secret 支持 `${ENV:}` 占位

**Files:**
- Modify: `sso/src/clients.ts`
- Create: `sso/test/clients.test.ts`

**Step 1: 写失败测试**

```ts
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { expandSecret } from '../src/clients.ts'

test('${ENV:NAME} 占位被环境变量替换', () => {
  process.env.TEST_SECRET_X = 's3cret'
  assert.equal(expandSecret('${ENV:TEST_SECRET_X}'), 's3cret')
})

test('缺失的环境变量抛错', () => {
  delete process.env.TEST_SECRET_MISSING
  assert.throws(() => expandSecret('${ENV:TEST_SECRET_MISSING}'), /未设置环境变量/)
})

test('非占位值原样返回', () => {
  assert.equal(expandSecret('plain'), 'plain')
})
```

**Step 2: 运行确认失败**

Run: `npm test`
Expected: FAIL —— `expandSecret` 未导出。

**Step 3: 在 `clients.ts` 实现**

在 `loadClients` 之前加入：

```ts
/**
 * 展开 client_secret 的 ${ENV:NAME} 占位;非占位值原样返回。
 * 缺失的环境变量直接抛错(快速失败,避免静默变成空 secret)。
 */
export function expandSecret(raw: string): string {
  const m = /^\$\{ENV:([A-Za-z_][A-Za-z0-9_]*)\}$/.exec(raw)
  if (!m) return raw
  const value = process.env[m[1]]
  if (!value) throw new Error(`client_secret 引用了未设置环境变量: ${m[1]}`)
  return value
}
```

并在 `loadClients()` 的循环里应用：

```ts
  for (const c of file.clients ?? []) {
    if (c.client_secret) c.client_secret = expandSecret(c.client_secret)
    map.set(c.client_id, c)
  }
```

**Step 4: 运行确认通过**

Run: `npm test`
Expected: PASS。

**Step 5: 提交**

```bash
git add sso/src/clients.ts sso/test/clients.test.ts
git commit -m "feat(sso): client_secret 支持 \${ENV:} 占位注入"
```

---

## Task 10: clients.json 移出仓库 + 模板与 .gitignore

**Files:**
- Modify: `sso/.gitignore`
- Modify: `sso/clients.example.json`
- Add: `sso/clients.json`（仅本地，不提交）
- Modify: `sso/.env.example`

**Step 1: 更新 `.gitignore`**

追加：

```
clients.json
```

**Step 2: 从 git 移除但保留本地文件**

```bash
git rm --cached sso/clients.json
```

**Step 3: 改造 `clients.example.json`**

把每个 client 的 `client_secret` 改为占位，并新增 `refresh_ttl_hours`。示例（其余 client 同构）：

```json
{
  "clients": [
    {
      "client_id": "agent",
      "client_secret": "${ENV:SSO_SECRET_AGENT}",
      "name": "零号员工",
      "redirect_uris": ["http://127.0.0.1:8080/api/auth/oidc/callback"],
      "default_role": "user",
      "refresh_ttl_hours": 12,
      "dept_role_map": { "平台组": "admin" }
    },
    {
      "client_id": "dashboard-gateway",
      "client_secret": "${ENV:SSO_SECRET_DASHBOARD}",
      "name": "员工 AI 工作台",
      "redirect_uris": ["http://127.0.0.1:8090/api/auth/oidc/callback"],
      "post_logout_redirect_uris": [],
      "default_role": "user",
      "refresh_ttl_hours": 12,
      "dept_role_map": { "平台组": "admin", "AI-Admin": "admin" }
    }
  ]
}
```

> 说明：market/rag/router-admin/zhongtai-oa 只是资源服务、从不做客户端认证，模板中可保留条目但 secret 用占位即可。

**Step 4: 生成本地 `clients.json` 与新 secret**

用 node 生成五个随机 secret（32 字节 base64url）并打印，由运维写入各部署环境：

```bash
node -e "for (const n of ['AGENT','DASHBOARD','MARKET','RAG','ROUTER']) console.log('SSO_SECRET_'+n+'='+require('crypto').randomBytes(32).toString('base64url'))"
```

把其中的 `SSO_SECRET_AGENT`、`SSO_SECRET_DASHBOARD` 写入 SSO 部署的 `.env`，并同步到 agent / dashboard 的运行环境（见 Task 11）。

> 注意：`test/fixtures/clients.json` 是测试夹具，用的是 `test-secret` 等假值，无需改动，但**不要**把它误加进 .gitignore。

**Step 5: 更新 `.env.example`**

追加：

```
# ---- 客户端密钥(配合 clients.json 的 ${ENV:...} 占位) ----
SSO_SECRET_AGENT=change-me
SSO_SECRET_DASHBOARD=change-me
# ---- token 寿命 ----
SSO_ACCESS_TOKEN_TTL_SECONDS=600
SSO_ID_TOKEN_TTL_SECONDS=600
SSO_KEY_RETIRE_AFTER_HOURS=2
```

**Step 6: 验证**

Run:
```bash
git ls-files | Select-String clients
git grep -nE 'xzrobot[-]' -- . || echo "仓库内已无泄露值"
```
Expected: 只列出 `clients.example.json` 与 `test/fixtures/clients.json`；无旧密钥前缀残留。

**Step 7: 提交**

```bash
git add sso/.gitignore sso/clients.example.json sso/.env.example
git rm --cached sso/clients.json
git commit -m "chore(sso): clients.json 移出版本库,secret 改由环境变量注入"
```

---

## Task 11: 客户端 secret 读取路径与硬编码清理

**Files:**
- Modify: `dashboard/electron/main/identity.ts:95-100`
- 核实: `agent/src/web/sso_auth.py`（已支持 `SSO_CLIENT_SECRET`，无需改）

**Step 1: 去掉 dashboard 硬编码兜底**

把 `oidcClient()` 改为：

```ts
function oidcClient(): { clientId: string; clientSecret: string } {
  const clientId = process.env.OIDC_CLIENT_ID
  const clientSecret = process.env.OIDC_CLIENT_SECRET
  if (!clientId || !clientSecret) {
    throw new Error('未配置 OIDC_CLIENT_ID / OIDC_CLIENT_SECRET(请由桌面端安装包或企业配置注入)')
  }
  return { clientId, clientSecret }
}
```

> 该函数在两处被调用（`ensureFreshOidc` 与 `startSsoLogin`），抛错会被各自的 try/catch 转成用户可见错误，行为安全。

**Step 2: 类型检查**

Run（在 `dashboard/` 下）: `npm run typecheck`（若无该脚本则 `npx vue-tsc --noEmit` / `npx tsc --noEmit`）

**Step 3: 提交**

```bash
git add dashboard/electron/main/identity.ts
git commit -m "fix(dashboard): 移除硬编码 OIDC client secret,改为强制环境注入"
```

---

## Task 12: agent 本地会话 12h 可配

**Files:**
- Modify: `agent/src/web/server.py:58`

**Step 1: 修改 `create_jwt` 默认值**

```python
def _session_ttl_seconds() -> int:
    """本地会话有效期(秒),默认 12 小时;SSO access token 另由 SSO 侧控制。"""
    try:
        return int(os.environ.get("AGENT_SESSION_TTL_SECONDS", "43200"))
    except ValueError:
        return 43200


def create_jwt(user: dict, expires_seconds: int | None = None) -> str:
    if expires_seconds is None:
        expires_seconds = _session_ttl_seconds()
```

> 确认文件顶部已 `import os`；`server.py` 其它位置已使用 `os`，如未导入则补上。

**Step 2: 测试**

Run（在 `agent/` 下）: `pytest tests/ -q`（若存在既有失败，至少确认 `tests/unit/test_sso_auth.py` 不回归）

**Step 3: 提交**

```bash
git add agent/src/web/server.py
git commit -m "feat(agent): 本地会话 TTL 降至 12h 并可用 AGENT_SESSION_TTL_SECONDS 覆盖"
```

---

## Task 13: rag 本地会话 12h 可配

**Files:**
- Modify: `rag/backend/app/config.py:63`

**Step 1: 修改默认值**

```python
    jwt_expire_minutes: int = 720
```

（可由 `.env` 的 `JWT_EXPIRE_MINUTES` 覆盖，pydantic-settings 已支持。）

**Step 2: 提交**

```bash
git add rag/backend/app/config.py
git commit -m "feat(rag): 本地会话 TTL 由 24h 降至 12h"
```

---

## Task 14: market 本地会话 12h 可配

**Files:**
- Modify: `market/backend/app/config.py:31`

**Step 1: 修改默认值**

```python
    jwt_expire_minutes: int = 720
```

**Step 2: 提交**

```bash
git add market/backend/app/config.py
git commit -m "feat(market): 本地会话 TTL 由 24h 降至 12h"
```

---

## Task 15: router 本地会话 12h 显式化

**Files:**
- Modify: `router/admin/src/routes/auth.ts`（`fastify.jwt.sign` 调用处，约 31 行）
- Modify: `router/admin/src/index.ts` 或注册 jwt 插件处（如有 `expiresIn` 全局配置）

**Step 1: 显式设置过期时间**

把：

```ts
const token = fastify.jwt.sign({
      id: user.id,
      email: user.email ?? '',
      role: user.role
    });
```

改为：

```ts
const token = fastify.jwt.sign(
      { id: user.id, email: user.email ?? '', role: user.role },
      { expiresIn: process.env.ADMIN_SESSION_TTL ?? '12h' }
    );
```

**Step 2: 确认 OIDC 颁发的 SSO 会话不经过此路径**

Run: `grep -n "routes/sso" router/admin/src/index.ts`
确认 `/internal/sso/exchange` 仅验 id_token 并签发 router key，不签发 admin 会话 token。

**Step 3: 构建 + 测试**

Run（在 `router/` 下）: `npm run build; npm run test`
Expected: 无类型错误；测试通过。

**Step 4: 提交**

```bash
git add router/admin/src/routes/auth.ts
git commit -m "feat(router): admin 会话 TTL 显式设为 12h 可配"
```

---

## Task 16: sso 补 `.gitlab-ci.yml`

**Files:**
- Create: `sso/.gitlab-ci.yml`

**Step 1: 写 CI**

```yaml
stages: [verify]

default:
  image: node:22
  cache:
    key:
      files: [package-lock.json]
    paths: [node_modules/]

verify:
  stage: verify
  script:
    - npm ci
    - npm run typecheck
    - npm test
```

> 若 GitLab Runner 未安装或未注册，本任务先提交配置，pipeline 会显示 pending；不影响其它任务。

**Step 2: 提交**

```bash
git add sso/.gitlab-ci.yml
git commit -m "ci(sso): typecheck + 单元测试"
```

---

## Task 17: sso README(含密钥轮换运维手册)

**Files:**
- Create: `sso/README.md`

**Step 1: 写文档**

必须包含以下小节：

1. **定位**：内部 OIDC Provider，为 agent/market/rag/router/dashboard 提供单点登录。
2. **快速开始**：`npm ci`、`.env` 配置、`npm start`、Node 版本要求（≥22.18 或加 `--experimental-strip-types`）。
3. **环境变量一览**：`SSO_ISSUER`、`SSO_PORT`、`SSO_DATA_DIR`、`SSO_KEYS_DIR`、`SSO_CLIENTS_PATH`、`SSO_SESSION_TTL_HOURS`、`SSO_ACCESS_TOKEN_TTL_SECONDS`、`SSO_ID_TOKEN_TTL_SECONDS`、`SSO_KEY_RETIRE_AFTER_HOURS`、LDAP/钉钉相关、`SSO_SECRET_*`。
4. **密钥轮换运维手册**：
   - 常规轮换：`npm run key:rotate` → 观察一天 → `npm run key:prune`
   - 紧急轮换（私钥疑似泄露）：`key:rotate` 后**立即** `key:retire <old-kid>`（会立刻断掉旧 token）
   - 回滚：备份 `SSO_KEYS_DIR` 后还原目录
   - 客户端 JWKS 缓存 300s，轮换后最长 5 分钟收敛
5. **secret 管理**：`clients.json` 不入库；`${ENV:...}` 占位；如何生成与分发；泄露处置流程。
6. **吊销语义**（重要）：明确写出「登出/改密后，SSO token 10 分钟内失效，客户端本地会话最长 12 小时」，以及为什么做不到秒级（离线验签）。
7. **接口清单**：discovery / jwks / authorize / token / userinfo / logout / profile。

**Step 2: 提交**

```bash
git add sso/README.md
git commit -m "docs(sso): 新增 README 与密钥轮换运维手册"
```

---

## Task 18: 端到端验收

**Step 1: 启动 SSO 与验证密钥轮换**

```bash
cd sso
$env:SSO_ISSUER="http://127.0.0.1:18091"; $env:SSO_KEYS_DIR="./test/keys-e2e"; $env:SSO_DATA_DIR="./test/data-e2e"; $env:SSO_CLIENTS_PATH="./test/fixtures/clients.json"; $env:FILE_USERS_PATH="./test/data/users.json"
npm run key:rotate
npm start
# 另开终端:
Invoke-WebRequest http://127.0.0.1:18091/.well-known/jwks.json -UseBasicParsing | Select-Object -ExpandProperty Content
```
Expected: JWKS 含 2 个 key(active + verifying)，`kid` 与 `keys/active` 一致。

**Step 2: 跑完整 smoke**

Run: `npm run test:smoke`
Expected: 全部 PASS，包含「改密后旧 refresh 被拒」。

**Step 3: 逐仓验证**

| 仓库 | 命令 | 期望 |
|---|---|---|
| sso | `npm run typecheck; npm test` | 通过 |
| agent | `ruff check src/ tests/; pytest tests/ -q` | 不新增失败 |
| rag | `pytest` | 不新增失败 |
| market | `pytest` | 通过 |
| router | `npm run build; npm run test` | 通过 |
| dashboard | `npm run build` | 通过 |

**Step 4: 验收清单复核**

对照设计文档《验收标准》6 条逐条确认，把结果记录到 `sso/docs/plans/2026-09-20-keys-revocation-secrets-design.md` 末尾的「实施结果」小节。

---

## 部署顺序（重要）

secret 轮换必须与 5 个客户端同步，顺序如下，否则会 401：

1. 先部署新版 SSO（密钥环 + `${ENV:}` 占位），**暂时把 `clients.json` 的 secret 保留旧值**，并同时把新值写入 `SSO_SECRET_*`（新旧并存期）——过渡期可让 `expandSecret` 支持 `${ENV:X:fallback}` 形式，实现前确认是否需要。
2. 更新 agent 与 dashboard 的 `SSO_CLIENT_SECRET` / `OIDC_CLIENT_SECRET` 为新值并重启。
3. 验证两者 SSO 登录成功。
4. 从 `clients.json` 删除旧值，只保留 `${ENV:...}`。
5. 观察一个 access token TTL(10 分钟)窗口，确认无鉴权失败。
