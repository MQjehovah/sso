import { test } from 'node:test'
import assert from 'node:assert/strict'
import { rateLimit } from '../src/ratelimit.ts'

test('ratelimit: 短窗口调用不裁剪长窗口键的历史(跨键清理回归)', (t) => {
  t.mock.timers.enable({ apis: ['Date'] })
  const hourKey = 'reset:ip:10.9.9.9'
  for (let i = 0; i < 9; i++) {
    assert.equal(rateLimit(hourKey, 10, 3_600_000), true, `1h 键第 ${i + 1} 次应放行`)
  }
  // 空闲 61 秒(触发周期清理)后,另一次 60s 窗口的不同键调用不得动到 1h 键
  t.mock.timers.tick(61_000)
  assert.equal(rateLimit('authorize:10.8.8.8', 60, 60_000), true)
  // 1h 键历史仍在:第 10 次放行,第 11 次必须被拒
  assert.equal(rateLimit(hourKey, 10, 3_600_000), true, '第 10 次(达到上限前)应放行')
  assert.equal(rateLimit(hourKey, 10, 3_600_000), false, '第 11 次应被 1h 窗口拒绝(历史未被裁剪)')
})

test('ratelimit: 同一键按自身窗口清理过期时间戳', (t) => {
  t.mock.timers.enable({ apis: ['Date'] })
  const key = 'pwd:10.7.7.7'
  assert.equal(rateLimit(key, 2, 60_000), true)
  assert.equal(rateLimit(key, 2, 60_000), true)
  assert.equal(rateLimit(key, 2, 60_000), false)
  t.mock.timers.tick(60_001)
  assert.equal(rateLimit(key, 2, 60_000), true, '窗口过期后应重新放行')
})
