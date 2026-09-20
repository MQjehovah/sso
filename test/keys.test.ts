import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from 'node:fs'
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

test('prune 从降级时刻计算窗口:长期 active 的密钥轮换后不会被立即退休', async () => {
  const ring = new KeyRing(dir)
  const oldKid = (await ring.ensureActive()).kid
  // 模拟该密钥已 active 了很久(把 createdAt 回拨 90 天)
  const metaPath = join(dir, `${oldKid}.meta.json`)
  const meta = JSON.parse(readFileSync(metaPath, 'utf-8'))
  writeFileSync(metaPath, JSON.stringify({ ...meta, createdAt: Date.now() - 90 * 24 * 3_600_000 }))
  await ring.rotate()
  await ring.prune(2) // 退休窗口 2 小时
  const status = Object.fromEntries(ring.list().map((k) => [k.kid, k.status]))
  assert.equal(status[oldKid], 'verifying', '刚降级的密钥不应被立即退休')
  assert.equal(ring.publicJwks().keys.length, 2)
})
