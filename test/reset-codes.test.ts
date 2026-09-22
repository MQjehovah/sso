import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createResetCodeStore } from '../src/reset.ts'

const dir = mkdtempSync(join(tmpdir(), 'sso-reset-codes-'))

after(() => {
  rmSync(dir, { recursive: true, force: true })
})

test('issue 后正确码校验通过且记录被删除(单次有效)', () => {
  const store = createResetCodeStore(dir, { ttlSeconds: 600 })
  store.issue('1001', 'a@corp.com', '123456', '10.0.0.1')
  assert.equal(store.verifyAndConsume('1001', '123456'), 'ok')
  assert.equal(store.peek('1001'), undefined)
})

test('错码返回 mismatch,attempts 递增且记录仍在', () => {
  const store = createResetCodeStore(dir, { ttlSeconds: 600 })
  store.issue('1002', 'b@corp.com', '654321', '10.0.0.2')
  assert.equal(store.verifyAndConsume('1002', '000000'), 'mismatch')
  const rec = store.peek('1002')
  assert.equal(rec?.attempts, 1)
  assert.equal(rec?.email, 'b@corp.com')
  assert.equal(rec?.ip, '10.0.0.2')
})

test('错满 5 次返回 too_many 并作废记录,正确码也不再生效', () => {
  const store = createResetCodeStore(dir, { ttlSeconds: 600 })
  store.issue('1003', 'c@corp.com', '112233', '10.0.0.3')
  for (let i = 0; i < 4; i++) {
    assert.equal(store.verifyAndConsume('1003', '999999'), 'mismatch')
    assert.equal(store.peek('1003')?.attempts, i + 1)
  }
  assert.equal(store.verifyAndConsume('1003', '999999'), 'too_many')
  assert.equal(store.peek('1003'), undefined)
  assert.equal(store.verifyAndConsume('1003', '112233'), 'missing')
})

test('过期返回 expired 并删除记录', () => {
  let now = 1_000_000
  const store = createResetCodeStore(dir, { now: () => now, ttlSeconds: 600 })
  store.issue('1004', 'd@corp.com', '445566', '10.0.0.4')
  now += 600_000
  assert.equal(store.verifyAndConsume('1004', '445566'), 'expired')
  assert.equal(store.peek('1004'), undefined)
})

test('记录不存在返回 missing', () => {
  const store = createResetCodeStore(dir, { ttlSeconds: 600 })
  assert.equal(store.verifyAndConsume('nobody', '123456'), 'missing')
})

test('新实例(模拟重启)仍能校验且保留尝试次数', () => {
  const store = createResetCodeStore(dir, { ttlSeconds: 600 })
  store.issue('1005', 'e@corp.com', '778899', '10.0.0.5')
  assert.equal(store.verifyAndConsume('1005', '000000'), 'mismatch')

  const restarted = createResetCodeStore(dir, { ttlSeconds: 600 })
  assert.equal(restarted.peek('1005')?.attempts, 1)
  assert.equal(restarted.verifyAndConsume('1005', '778899'), 'ok')
})

test('新实例加载时清理过期条目,不影响有效条目', () => {
  let now = 2_000_000
  const first = createResetCodeStore(dir, { now: () => now, ttlSeconds: 600 })
  first.issue('2001', 'old@corp.com', '101010', '10.0.0.6')
  now += 600_000
  first.issue('2002', 'new@corp.com', '202020', '10.0.0.7')

  const restarted = createResetCodeStore(dir, { now: () => now, ttlSeconds: 600 })
  assert.equal(restarted.peek('2001'), undefined)
  assert.equal(restarted.peek('2002')?.email, 'new@corp.com')
  assert.equal(restarted.verifyAndConsume('2002', '202020'), 'ok')
})
