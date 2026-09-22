import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  createResetCodeStore, requestReset, confirmReset,
  RESET_REQUEST_MESSAGE, RESET_FAIL_MESSAGE,
  type ResetDeps
} from '../src/reset.ts'
import type { DirectoryUser } from '../src/directory.ts'
import { rateLimit } from '../src/ratelimit.ts'

const USER: DirectoryUser = {
  sub: '1001', name: '张三', dept: '平台组', email: 'zs@corp.com', dingtalkUserId: '', status: 'active'
}

const dirs: string[] = []
after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true })
})

interface AuditEvt { event: string; ok: boolean; sub?: string; ip?: string; detail?: string }

function makeDeps(over: Partial<ResetDeps> = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'sso-reset-flow-'))
  dirs.push(dir)
  const mails: Array<{ to: string; code: string; ttlMinutes: number }> = []
  const notices: Array<{ to: string }> = []
  const audits: AuditEvt[] = []
  const setPasswordCalls: Array<{ user: DirectoryUser; current: string | null; next: string }> = []
  let sessionsRevoked = 0
  let tokensRevoked = 0
  const codes = createResetCodeStore(dir, { ttlSeconds: 600 })
  const deps: ResetDeps = {
    directory: { findByIdentifier: async (id) => (id === USER.sub ? USER : null) },
    mailer: {
      isConfigured: () => true,
      sendVerificationCode: async (m) => { mails.push(m) },
      sendPasswordChangedNotice: async (m) => { notices.push(m) }
    },
    codes,
    password: { setPassword: async (user, current, next) => { setPasswordCalls.push({ user, current, next }) } },
    rateLimit: () => true,
    revokeSessions: () => { sessionsRevoked++ },
    revokeTokens: () => { tokensRevoked++ },
    audit: (evt) => { audits.push(evt) },
    ...over
  }
  return {
    deps, codes, mails, notices, audits, setPasswordCalls,
    revoked: () => ({ sessionsRevoked, tokensRevoked })
  }
}

// ---- requestReset ----

test('requestReset: 工号不存在 → 统一文案, 不发信不存码', async () => {
  const { deps, codes, mails, audits } = makeDeps({ directory: { findByIdentifier: async () => null } })
  const res = await requestReset({ sub: '9999', ip: '10.0.0.9' }, deps)
  assert.equal(res.message, RESET_REQUEST_MESSAGE)
  assert.equal(mails.length, 0)
  assert.equal(codes.peek('9999'), undefined)
  const evt = audits.find((e) => e.event === 'reset_request')
  assert.ok(evt)
  assert.equal(evt.ok, true)
  assert.match(evt.detail ?? '', /"sent":false/)
})

test('requestReset: 用户无邮箱 → 统一文案, 不发信不存码', async () => {
  const { deps, codes, mails } = makeDeps({
    directory: { findByIdentifier: async () => ({ ...USER, email: undefined }) }
  })
  const res = await requestReset({ sub: '1001', ip: '10.0.0.10' }, deps)
  assert.equal(res.message, RESET_REQUEST_MESSAGE)
  assert.equal(mails.length, 0)
  assert.equal(codes.peek('1001'), undefined)
})

test('requestReset: mailer 未配置 → 统一文案, 不发信不存码', async () => {
  const { deps, codes, mails } = makeDeps()
  deps.mailer.isConfigured = () => false
  const res = await requestReset({ sub: '1001', ip: '10.0.0.11' }, deps)
  assert.equal(res.message, RESET_REQUEST_MESSAGE)
  assert.equal(mails.length, 0)
  assert.equal(codes.peek('1001'), undefined)
})

test('requestReset: 工号为空 → 统一文案且不查目录', async () => {
  let lookups = 0
  const { deps, mails } = makeDeps({
    directory: { findByIdentifier: async () => { lookups++; return USER } }
  })
  const res = await requestReset({ sub: '   ', ip: '10.0.0.12' }, deps)
  assert.equal(res.message, RESET_REQUEST_MESSAGE)
  assert.equal(lookups, 0)
  assert.equal(mails.length, 0)
})

test('requestReset: 60 秒冷却内第二次请求不发信(真实限流)', async () => {
  const fresh = { ...USER, sub: '3001' }
  const { deps, mails } = makeDeps({
    rateLimit,
    directory: { findByIdentifier: async () => fresh }
  })
  const first = await requestReset({ sub: '3001', ip: '10.0.0.30' }, deps)
  const second = await requestReset({ sub: '3001', ip: '10.0.0.30' }, deps)
  assert.equal(first.message, RESET_REQUEST_MESSAGE)
  assert.equal(second.message, RESET_REQUEST_MESSAGE)
  assert.equal(mails.length, 1)
})

test('requestReset: 小时限流命中 → 统一文案 + 审计 ok=false, 不发信', async () => {
  const { deps, mails, audits } = makeDeps({
    rateLimit: (key, _limit, windowMs) => !(windowMs === 3_600_000 && key.startsWith('reset:send'))
  })
  const res = await requestReset({ sub: '1001', ip: '10.0.0.31' }, deps)
  assert.equal(res.message, RESET_REQUEST_MESSAGE)
  assert.equal(mails.length, 0)
  assert.ok(audits.some((e) => e.event === 'reset_request' && e.ok === false))
})

test('requestReset: IP 限流命中 → 统一文案, 不发信', async () => {
  const { deps, mails } = makeDeps({
    rateLimit: (key, _limit, windowMs) => !(windowMs === 3_600_000 && key.startsWith('reset:ip:'))
  })
  const res = await requestReset({ sub: '1001', ip: '10.0.0.32' }, deps)
  assert.equal(res.message, RESET_REQUEST_MESSAGE)
  assert.equal(mails.length, 0)
})

test('requestReset: 正常请求存码并发出含 6 位码的邮件', async () => {
  const { deps, codes, mails, audits } = makeDeps()
  const res = await requestReset({ sub: ' 1001 ', ip: '10.0.0.33' }, deps)
  assert.equal(res.message, RESET_REQUEST_MESSAGE)
  assert.equal(mails.length, 1)
  assert.equal(mails[0].to, 'zs@corp.com')
  assert.match(mails[0].code, /^\d{6}$/)
  const rec = codes.peek('1001')
  assert.ok(rec)
  assert.equal(rec.email, 'zs@corp.com')
  const evt = audits.find((e) => e.event === 'reset_request' && e.ok)
  assert.ok(evt)
  assert.match(evt.detail ?? '', /"sent":true/)
  assert.ok(!(evt.detail ?? '').includes(mails[0].code), '审计不得包含验证码')
})

test('requestReset: 发信抛错不冒泡, 仅审计 sent=false', async () => {
  const { deps, codes, mails, audits } = makeDeps()
  deps.mailer.sendVerificationCode = async () => { throw new Error('SMTP 拒绝') }
  const res = await requestReset({ sub: '1001', ip: '10.0.0.34' }, deps)
  assert.equal(res.message, RESET_REQUEST_MESSAGE)
  assert.equal(mails.length, 0)
  assert.ok(codes.peek('1001'), '码已生成(发信失败不回滚, 与计划一致)')
  const evt = audits.find((e) => e.event === 'reset_request' && e.ok)
  assert.ok(evt)
  assert.match(evt.detail ?? '', /SMTP 拒绝/)
})

// ---- confirmReset ----

test('confirmReset: 错码 → 统一失败文案且不写密码', async () => {
  const { deps, codes, setPasswordCalls, audits, revoked } = makeDeps()
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
  const res = await confirmReset({ sub: '1001', code: '000000', newPassword: 'newpass123', ip: '10.0.0.35' }, deps)
  assert.deepEqual(res, { ok: false, message: RESET_FAIL_MESSAGE })
  assert.equal(setPasswordCalls.length, 0)
  assert.equal(revoked().sessionsRevoked, 0)
  assert.equal(revoked().tokensRevoked, 0)
  const evt = audits.find((e) => e.event === 'reset_confirm')
  assert.ok(evt)
  assert.equal(evt.ok, false)
  assert.match(evt.detail ?? '', /mismatch/)
})

test('confirmReset: 密码过短/过长 → 统一失败文案且不消费验证码', async () => {
  for (const bad of ['short', 'x'.repeat(65)]) {
    const { deps, codes, setPasswordCalls } = makeDeps()
    codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
    const res = await confirmReset({ sub: '1001', code: '123456', newPassword: bad, ip: '10.0.0.36' }, deps)
    assert.deepEqual(res, { ok: false, message: RESET_FAIL_MESSAGE })
    assert.ok(codes.peek('1001'), '长度不符时验证码必须保留')
    assert.equal(setPasswordCalls.length, 0)
  }
})

test('confirmReset: 正确码 → 写密码/踢会话与 token/通知/审计 ok=true', async () => {
  const { deps, codes, setPasswordCalls, notices, audits, revoked } = makeDeps()
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
  const res = await confirmReset({ sub: '1001', code: '123456', newPassword: 'newpass123', ip: '10.0.0.37' }, deps)
  assert.deepEqual(res, { ok: true })
  assert.equal(setPasswordCalls.length, 1)
  assert.equal(setPasswordCalls[0].user.sub, '1001')
  assert.equal(setPasswordCalls[0].current, null)
  assert.equal(setPasswordCalls[0].next, 'newpass123')
  assert.deepEqual(revoked(), { sessionsRevoked: 1, tokensRevoked: 1 })
  assert.equal(notices.length, 1)
  assert.equal(notices[0].to, 'zs@corp.com')
  assert.ok(audits.some((e) => e.event === 'reset_confirm' && e.ok === true))
  assert.equal(codes.peek('1001'), undefined, '验证码单次有效, 重置后清除')
})

test('confirmReset: 目录查无用户 → 统一失败文案且不写密码', async () => {
  const { deps, codes, setPasswordCalls } = makeDeps({
    directory: { findByIdentifier: async () => null }
  })
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
  const res = await confirmReset({ sub: '1001', code: '123456', newPassword: 'newpass123', ip: '10.0.0.38' }, deps)
  assert.deepEqual(res, { ok: false, message: RESET_FAIL_MESSAGE })
  assert.equal(setPasswordCalls.length, 0)
})

test('confirmReset: setPassword 抛错 → 统一失败文案且不踢会话', async () => {
  const { deps, codes, audits, revoked } = makeDeps()
  deps.password.setPassword = async () => { throw new Error('LDAP 不可用') }
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
  const res = await confirmReset({ sub: '1001', code: '123456', newPassword: 'newpass123', ip: '10.0.0.39' }, deps)
  assert.deepEqual(res, { ok: false, message: RESET_FAIL_MESSAGE })
  assert.equal(revoked().sessionsRevoked, 0)
  assert.ok(audits.some((e) => e.event === 'reset_confirm' && !e.ok && (e.detail ?? '').includes('LDAP 不可用')))
})

test('confirmReset: 变更通知抛错不影响成功返回, 审计 ok=true', async () => {
  const { deps, codes, setPasswordCalls, audits, revoked } = makeDeps()
  deps.mailer.sendPasswordChangedNotice = async () => { throw new Error('SMTP 挂了') }
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
  const res = await confirmReset({ sub: '1001', code: '123456', newPassword: 'newpass123', ip: '10.0.0.40' }, deps)
  assert.deepEqual(res, { ok: true })
  assert.equal(setPasswordCalls.length, 1)
  assert.deepEqual(revoked(), { sessionsRevoked: 1, tokensRevoked: 1 })
  const evt = audits.find((e) => e.event === 'reset_confirm' && e.ok === true)
  assert.ok(evt)
  assert.match(evt.detail ?? '', /SMTP 挂了/)
})

test('confirmReset: 验证码过期 → 统一失败文案', async () => {
  let now = 5_000_000
  const dir = mkdtempSync(join(tmpdir(), 'sso-reset-flow-'))
  dirs.push(dir)
  const codes = createResetCodeStore(dir, { now: () => now, ttlSeconds: 600 })
  const { deps, setPasswordCalls } = makeDeps()
  deps.codes = codes
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
  now += 600_000
  const res = await confirmReset({ sub: '1001', code: '123456', newPassword: 'newpass123', ip: '10.0.0.41' }, deps)
  assert.deepEqual(res, { ok: false, message: RESET_FAIL_MESSAGE })
  assert.equal(setPasswordCalls.length, 0)
})
