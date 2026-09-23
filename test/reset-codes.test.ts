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

// ---- verify / consume(密码失败不消费验证码的基础) ----

test('verify 正确码返回 ok 但不删除也不计数, consume 后才删除', () => {
  const store = createResetCodeStore(dir, { ttlSeconds: 600 })
  store.issue('3001', 'f@corp.com', '123456', '10.0.0.8')
  assert.equal(store.verify('3001', '123456'), 'ok')
  assert.equal(store.verify('3001', '123456'), 'ok', '可重复校验(TTL 内换密码重试)')
  const rec = store.peek('3001')
  assert.ok(rec, 'verify 不得删除记录')
  assert.equal(rec.attempts, 0, '正确码不计数')

  store.consume('3001')
  assert.equal(store.peek('3001'), undefined)
  assert.equal(store.verify('3001', '123456'), 'missing')
})

test('consume 不存在的记录为无害空操作', () => {
  const store = createResetCodeStore(dir, { ttlSeconds: 600 })
  store.consume('nobody')
  assert.equal(store.peek('nobody'), undefined)
})

test('verify 错码累计 attempts 且记录仍在, 达到上限才作废', () => {
  const store = createResetCodeStore(dir, { ttlSeconds: 600, maxAttempts: 3 })
  store.issue('3002', 'g@corp.com', '111111', '10.0.0.9')
  assert.equal(store.verify('3002', '222222'), 'mismatch')
  assert.equal(store.peek('3002')?.attempts, 1)
  assert.equal(store.verify('3002', '222222'), 'mismatch')
  assert.equal(store.peek('3002')?.attempts, 2, '错码期间记录保留(密码失败不消费语义成立)')
  assert.equal(store.verify('3002', '222222'), 'too_many')
  assert.equal(store.peek('3002'), undefined)
  assert.equal(store.verify('3002', '111111'), 'missing')
})

test('verify 过期返回 expired 并删除, 与 verifyAndConsume 行为一致', () => {
  let now = 3_000_000
  const store = createResetCodeStore(dir, { now: () => now, ttlSeconds: 600 })
  store.issue('3003', 'h@corp.com', '333333', '10.0.0.10')
  now += 600_000
  assert.equal(store.verify('3003', '333333'), 'expired')
  assert.equal(store.peek('3003'), undefined)
})

test('verifyAndConsume 语义不变: 正确码删除, 错码累计', () => {
  const store = createResetCodeStore(dir, { ttlSeconds: 600 })
  store.issue('3004', 'i@corp.com', '444444', '10.0.0.11')
  assert.equal(store.verifyAndConsume('3004', '000000'), 'mismatch')
  assert.equal(store.peek('3004')?.attempts, 1)
  assert.equal(store.verifyAndConsume('3004', '444444'), 'ok')
  assert.equal(store.peek('3004'), undefined)
})
