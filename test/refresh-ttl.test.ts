import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/**
 * refresh token 每客户端 TTL + 绝对会话上限。
 * store.ts 在导入时捕获 config.dataDir,且模块级 rtLoaded 只加载一次,
 * 因此必须在首次 import 前设置 SSO_DATA_DIR,并用动态 import。
 */
let store: typeof import('../src/store.ts')

const H = 3_600_000
const LEGACY_TOKEN = 'legacy-token-without-auth-time'

before(async () => {
  process.env.SSO_DATA_DIR = mkdtempSync(join(tmpdir(), 'rt-'))
  process.env.SSO_ISSUER = 'http://127.0.0.1:18091'
  // 老记录:本改动前写入,无 auth_time;expires_at 仍在未来,用于验证兜底逻辑
  writeFileSync(join(process.env.SSO_DATA_DIR, 'refresh_tokens.json'), JSON.stringify([
    {
      token: LEGACY_TOKEN, sub: 'u-legacy', name: '老用户', dept: 'D',
      client_id: 'c-legacy', expires_at: Date.now() + H
    }
  ]))
  store = await import('../src/store.ts')
})

test('轮换不延长绝对会话上限', () => {
  const authTime = Date.now() - 11 * H
  const t1 = store.issueRefreshToken('u1', 'U', 'D', 'c1', undefined, 12 * H, authTime)
  const c1 = store.consumeRefreshToken(t1, 'c1')
  assert.ok(c1)
  assert.equal(c1.authTime, authTime)

  // 轮换沿用原 authTime:11 小时时仍在 12 小时上限内,可继续刷新
  const t2 = store.issueRefreshToken('u1', 'U', 'D', 'c1', undefined, 12 * H, c1.authTime)
  const c2 = store.consumeRefreshToken(t2, 'c1')
  assert.ok(c2, '未超过绝对上限时应可刷新')
  assert.equal(c2.authTime, authTime)

  // 13 小时已超过 12 小时绝对上限:即便刚签发也应立即失效
  const expiredAuth = Date.now() - 13 * H
  const t3 = store.issueRefreshToken('u1', 'U', 'D', 'c2', undefined, 12 * H, expiredAuth)
  assert.equal(store.consumeRefreshToken(t3, 'c2'), null)
})

test('每客户端 TTL 被遵守', () => {
  const ok = store.issueRefreshToken('u2', 'U', 'D', 'c-1h', undefined, 1 * H, Date.now())
  assert.ok(store.consumeRefreshToken(ok, 'c-1h'), 'TTL 内应可刷新')

  const stale = store.issueRefreshToken('u2', 'U', 'D', 'c-1h', undefined, 1 * H, Date.now() - 2 * H)
  assert.equal(store.consumeRefreshToken(stale, 'c-1h'), null)
})

test('客户端不匹配仍被拒绝', () => {
  const t = store.issueRefreshToken('u3', 'U', 'D', 'c1', undefined, H, Date.now())
  assert.equal(store.consumeRefreshToken(t, 'c2'), null)
})

test('老记录无 auth_time 仍可用并返回数字 authTime', () => {
  const c = store.consumeRefreshToken(LEGACY_TOKEN, 'c-legacy')
  assert.ok(c)
  assert.equal(typeof c.authTime, 'number')
})
