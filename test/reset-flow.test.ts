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

/** 等待后台发信/审计落地(轮询短超时) */
async function waitFor(cond: () => boolean, timeoutMs = 1000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 5))
  }
}

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

const sentAudit = (audits: AuditEvt[], sent: boolean) =>
  audits.some((e) => e.event === 'reset_request' && e.ok && (e.detail ?? '').includes(`"sent":${sent}`))

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

test('requestReset: 禁用账号(有邮箱) → 统一文案, 不发信不存码, 审计账号已禁用', async () => {
  const disabled = { ...USER, status: 'disabled' as const }
  const { deps, codes, mails, audits } = makeDeps({ directory: { findByIdentifier: async () => disabled } })
  const res = await requestReset({ sub: '1001', ip: '10.0.0.50' }, deps)
  assert.equal(res.message, RESET_REQUEST_MESSAGE)
  assert.equal(mails.length, 0)
  assert.equal(codes.peek('1001'), undefined)
  const evt = audits.find((e) => e.event === 'reset_request' && e.ok)
  assert.match(evt?.detail ?? '', /账号已禁用/)
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

test('requestReset: IP 限流命中 → 统一文案, 不发信且不查目录', async () => {
  let lookups = 0
  const { deps, mails } = makeDeps({
    rateLimit: (key, _limit, windowMs) => !(windowMs === 3_600_000 && key.startsWith('reset:ip:')),
    directory: { findByIdentifier: async () => { lookups++; return USER } }
  })
  const res = await requestReset({ sub: '1001', ip: '10.0.0.32' }, deps)
  assert.equal(res.message, RESET_REQUEST_MESSAGE)
  assert.equal(mails.length, 0)
  assert.equal(lookups, 0)
})

test('requestReset: per-sub 限流与验证码按目录规范 sub 键控(手机号输入)', async () => {
  const keys: string[] = []
  const { deps, codes, mails, audits } = makeDeps({
    directory: { findByIdentifier: async (id) => (id === '13800000001' ? USER : null) },
    rateLimit: (key) => { keys.push(key); return true }
  })
  const res = await requestReset({ sub: '13800000001', ip: '10.0.0.48' }, deps)
  assert.equal(res.message, RESET_REQUEST_MESSAGE)
  assert.ok(keys.includes('reset:ip:10.0.0.48'), `应查 IP 键, 实际: ${keys.join(',')}`)
  assert.ok(keys.includes('reset:send:1001'), `per-sub 冷却应用规范 sub, 实际: ${keys.join(',')}`)
  assert.ok(keys.includes('reset:send:h:1001'), `per-sub 小时应用规范 sub, 实际: ${keys.join(',')}`)
  assert.equal(codes.peek('1001')?.email, 'zs@corp.com', '码按规范 sub 存储')
  assert.equal(codes.peek('13800000001'), undefined)
  await waitFor(() => sentAudit(audits, true))
  assert.equal(mails[0]?.to, 'zs@corp.com')
})

test('requestReset: 正常请求存码并发出含 6 位码的邮件', async () => {
  const { deps, codes, mails, audits } = makeDeps()
  const res = await requestReset({ sub: ' 1001 ', ip: '10.0.0.33' }, deps)
  assert.equal(res.message, RESET_REQUEST_MESSAGE)
  const rec = codes.peek('1001')
  assert.ok(rec, '返回前码已同步落库')
  assert.equal(rec.email, 'zs@corp.com')
  await waitFor(() => sentAudit(audits, true) && mails.length === 1)
  assert.equal(mails.length, 1)
  assert.equal(mails[0].to, 'zs@corp.com')
  assert.match(mails[0].code, /^\d{6}$/)
  assert.equal(mails[0].ttlMinutes, 10, '邮件 TTL 文案与码存储 TTL 一致')
  const evt = audits.find((e) => e.event === 'reset_request' && e.ok)
  assert.ok(evt)
  assert.ok(!(evt.detail ?? '').includes(mails[0].code), '审计不得包含验证码')
})

test('requestReset: 发信在后台进行, 不阻塞统一文案返回(时间旁路防护)', async () => {
  let release: () => void = () => {}
  const { deps, codes, mails, audits } = makeDeps()
  deps.mailer.sendVerificationCode = (m) => new Promise<void>((resolve) => {
    release = () => { mails.push(m); resolve() }
  })
  const res = await requestReset({ sub: '1001', ip: '10.0.0.47' }, deps)
  assert.equal(res.message, RESET_REQUEST_MESSAGE)
  assert.ok(codes.peek('1001'), '发信未完成时码已存')
  assert.equal(mails.length, 0, '请求返回不应等待发信')
  assert.equal(sentAudit(audits, true), false, '发信完成前不写发送审计')
  release()
  await waitFor(() => mails.length === 1 && sentAudit(audits, true))
})

test('requestReset: 发信抛错不冒泡, 仅审计 sent=false', async () => {
  const { deps, codes, mails, audits } = makeDeps()
  deps.mailer.sendVerificationCode = async () => { throw new Error('SMTP 拒绝') }
  const res = await requestReset({ sub: '1001', ip: '10.0.0.34' }, deps)
  assert.equal(res.message, RESET_REQUEST_MESSAGE)
  assert.equal(mails.length, 0)
  assert.ok(codes.peek('1001'), '码已生成(发信失败不回滚, 与计划一致)')
  await waitFor(() => (audits.find((e) => e.event === 'reset_request' && e.ok)?.detail ?? '').includes('SMTP 拒绝'))
  const evt = audits.find((e) => e.event === 'reset_request' && e.ok)
  assert.ok(evt)
  assert.match(evt.detail ?? '', /"sent":false/)
})

test('requestReset: 审计记录目录规范 sub(手机号输入 → 工号)', async () => {
  const { deps, mails, audits } = makeDeps({
    directory: { findByIdentifier: async (id) => (id === '13800000001' ? USER : null) }
  })
  await requestReset({ sub: '13800000001', ip: '10.0.0.44' }, deps)
  await waitFor(() => sentAudit(audits, true))
  assert.equal(audits.find((e) => e.event === 'reset_request' && e.ok)?.sub, '1001')
  assert.equal(mails.length, 1)
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

test('confirmReset: 限流键与阈值(reset:confirm:<ip>, 10 次/分钟), 正常路径放行', async () => {
  const calls: Array<[string, number, number]> = []
  const { deps, codes, setPasswordCalls } = makeDeps({
    rateLimit: (key, limit, windowMs) => { calls.push([key, limit, windowMs]); return true }
  })
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
  const res = await confirmReset({ sub: '1001', code: '123456', newPassword: 'newpass123', ip: '10.0.0.52' }, deps)
  assert.deepEqual(res, { ok: true })
  assert.deepEqual(calls, [['reset:confirm:10.0.0.52', 10, 60_000]])
  assert.equal(setPasswordCalls.length, 1)
  assert.equal(codes.peek('1001'), undefined)
})

test('confirmReset: 限流命中 → 统一失败文案, 不消费验证码且审计限流原因', async () => {
  const { deps, codes, setPasswordCalls, audits, revoked } = makeDeps({
    rateLimit: (key, _limit, windowMs) => !(windowMs === 60_000 && key.startsWith('reset:confirm:'))
  })
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.53')
  const res = await confirmReset({ sub: '1001', code: '123456', newPassword: 'newpass123', ip: '10.0.0.53' }, deps)
  assert.deepEqual(res, { ok: false, message: RESET_FAIL_MESSAGE })
  assert.ok(codes.peek('1001'), '限流命中时验证码必须保留')
  assert.equal(setPasswordCalls.length, 0)
  assert.deepEqual(revoked(), { sessionsRevoked: 0, tokensRevoked: 0 })
  const evt = audits.find((e) => e.event === 'reset_confirm' && !e.ok)
  assert.ok(evt)
  assert.match(evt.detail ?? '', /限流:reset:confirm:10\.0\.0\.53/)
})

test('confirmReset: 禁用账号(有邮箱) → 统一失败, 不写密码不踢会话', async () => {
  const disabled = { ...USER, status: 'disabled' as const }
  const { deps, codes, setPasswordCalls, audits, revoked } = makeDeps({
    directory: { findByIdentifier: async () => disabled }
  })
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
  const res = await confirmReset({ sub: '1001', code: '123456', newPassword: 'newpass123', ip: '10.0.0.51' }, deps)
  assert.deepEqual(res, { ok: false, message: RESET_FAIL_MESSAGE })
  assert.equal(setPasswordCalls.length, 0)
  assert.deepEqual(revoked(), { sessionsRevoked: 0, tokensRevoked: 0 })
  assert.ok(audits.some((e) => e.event === 'reset_confirm' && !e.ok && (e.detail ?? '').includes('账号已禁用')))
})

test('confirmReset: 密码不足 8 位 → 明确文案且不消费验证码', async () => {
  const { deps, codes, setPasswordCalls, audits } = makeDeps()
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
  const res = await confirmReset({ sub: '1001', code: '123456', newPassword: 'short', ip: '10.0.0.36' }, deps)
  assert.deepEqual(res, { ok: false, message: '新密码至少 8 位' })
  assert.ok(codes.peek('1001'), '长度不符时验证码必须保留')
  assert.equal(setPasswordCalls.length, 0)
  assert.ok(audits.some((e) => e.event === 'reset_confirm' && !e.ok))
})

test('confirmReset: 长度规则与 profile 一致(仅要求 ≥8, 无上限)', async () => {
  const { deps, codes, setPasswordCalls } = makeDeps()
  const long = 'x'.repeat(65)
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
  const res = await confirmReset({ sub: '1001', code: '123456', newPassword: long, ip: '10.0.0.42' }, deps)
  assert.deepEqual(res, { ok: true })
  assert.equal(setPasswordCalls[0]?.next, long)
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

test('confirmReset: 审计与码校验按目录规范 sub(手机号输入 → 工号)', async () => {
  const { deps, codes, audits, setPasswordCalls } = makeDeps({
    directory: { findByIdentifier: async (id) => (id === '13800000001' ? USER : null) }
  })
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
  const res = await confirmReset({ sub: '13800000001', code: '123456', newPassword: 'newpass123', ip: '10.0.0.43' }, deps)
  assert.deepEqual(res, { ok: true })
  assert.equal(setPasswordCalls[0]?.user.sub, '1001')
  assert.equal(audits.find((e) => e.event === 'reset_confirm' && e.ok)?.sub, '1001')
})

test('confirmReset: revokeTokens 抛错不阻断成功(审计含 revokeError, 通知仍发)', async () => {
  const { deps, codes, notices, audits, setPasswordCalls, revoked } = makeDeps()
  deps.revokeTokens = () => { throw new Error('磁盘只读') }
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
  const res = await confirmReset({ sub: '1001', code: '123456', newPassword: 'newpass123', ip: '10.0.0.45' }, deps)
  assert.deepEqual(res, { ok: true })
  assert.equal(setPasswordCalls.length, 1)
  assert.equal(notices.length, 1)
  assert.equal(revoked().sessionsRevoked, 1)
  assert.match(audits.find((e) => e.event === 'reset_confirm' && e.ok)?.detail ?? '', /revokeError: revokeTokens: 磁盘只读/)
})

test('confirmReset: revokeSessions 抛错时 revokeTokens 仍被调用(独立兜底)', async () => {
  const { deps, codes, audits, revoked } = makeDeps()
  deps.revokeSessions = () => { throw new Error('会话文件写失败') }
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
  const res = await confirmReset({ sub: '1001', code: '123456', newPassword: 'newpass123', ip: '10.0.0.46' }, deps)
  assert.deepEqual(res, { ok: true })
  assert.equal(revoked().tokensRevoked, 1, 'revokeSessions 抛错不得跳过 revokeTokens')
  assert.match(audits.find((e) => e.event === 'reset_confirm' && e.ok)?.detail ?? '', /revokeError: revokeSessions: 会话文件写失败/)
})

test('confirmReset: revokeSessions 与 revokeTokens 同时抛错 → detail 合并两条', async () => {
  const { deps, codes, audits } = makeDeps()
  deps.revokeSessions = () => { throw new Error('A') }
  deps.revokeTokens = () => { throw new Error('B') }
  codes.issue('1001', 'zs@corp.com', '123456', '10.0.0.1')
  const res = await confirmReset({ sub: '1001', code: '123456', newPassword: 'newpass123', ip: '10.0.0.49' }, deps)
  assert.deepEqual(res, { ok: true })
  assert.match(audits.find((e) => e.event === 'reset_confirm' && e.ok)?.detail ?? '', /revokeSessions: A; revokeTokens: B/)
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
