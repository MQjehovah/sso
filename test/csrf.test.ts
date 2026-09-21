import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'

/**
 * csrf.ts 在导入时读取 SSO_CSRF_SECRET(缺省则进程内随机)。
 * 为能构造"过期/篡改"用例,先固定密钥再动态导入。
 */
process.env.SSO_CSRF_SECRET = 'test-csrf-secret'

let csrf: typeof import('../src/csrf.ts')

before(async () => {
  csrf = await import('../src/csrf.ts')
})

/** 用已知密钥手工签发 token,便于构造过期/篡改用例 */
function forge(sid: string, exp: number, secret = 'test-csrf-secret'): string {
  const sig = createHmac('sha256', secret).update(`${sid}:${exp}`).digest('hex')
  return `${exp}.${sig}`
}

test('有效 token 通过与 sid 绑定的校验', () => {
  assert.equal(csrf.verifyCsrf('sid-1', csrf.issueCsrf('sid-1')), true)
})

test('过期 token 被拒', () => {
  assert.equal(csrf.verifyCsrf('sid-1', forge('sid-1', Date.now() - 1000)), false)
})

test('篡改签名被拒', () => {
  const [exp] = csrf.issueCsrf('sid-1').split('.')
  assert.equal(csrf.verifyCsrf('sid-1', `${exp}.${'a'.repeat(64)}`), false)
})

test('缺失/空 token 被拒', () => {
  assert.equal(csrf.verifyCsrf('sid-1', undefined), false)
  assert.equal(csrf.verifyCsrf('sid-1', ''), false)
})

test('不同 sid 的 token 被拒', () => {
  assert.equal(csrf.verifyCsrf('sid-other', csrf.issueCsrf('sid-1')), false)
})

test('格式非法(无点/多段/空签名)被拒', () => {
  assert.equal(csrf.verifyCsrf('sid-1', 'no-dot'), false)
  assert.equal(csrf.verifyCsrf('sid-1', 'a.b.c'), false)
  assert.equal(csrf.verifyCsrf('sid-1', `${Date.now() + 60_000}.`), false)
})
