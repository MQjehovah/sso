import { randomBytes, randomInt, scryptSync, timingSafeEqual } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { config } from './config.ts'
import type { DirectoryUser } from './directory.ts'
import type { Mailer } from './mailer.ts'

/**
 * 自助重置验证码存储(JSON 落盘,风格同 store.ts):
 * - 只存 scrypt 哈希,不存明文码;单次有效,校验通过即删除。
 * - 错码累计尝试;达到上限(默认 5 次)作废该记录。
 * - 读写时清理过期条目;文件权限 0600(数据目录约定)。
 */
export type VerifyResult = 'ok' | 'missing' | 'expired' | 'mismatch' | 'too_many'

export interface ResetCodeRecord {
  sub: string
  email: string
  codeHash: string
  salt: string
  expiresAt: number
  attempts: number
  sentAt: number
  ip: string
}

export function createResetCodeStore(dir: string, opts?: { now?: () => number; ttlSeconds?: number; maxAttempts?: number }): {
  issue(sub: string, email: string, code: string, ip: string): void
  verifyAndConsume(sub: string, code: string): VerifyResult
  peek(sub: string): ResetCodeRecord | undefined
} {
  const file = join(dir, 'reset_codes.json')
  const now = opts?.now ?? Date.now
  const ttlSeconds = opts?.ttlSeconds ?? config.resetCodeTtlSeconds
  const maxAttempts = opts?.maxAttempts ?? 5
  const codes = new Map<string, ResetCodeRecord>()
  let loaded = false

  function ensureLoaded(): void {
    if (loaded) return
    loaded = true
    try {
      if (existsSync(file)) {
        const arr = JSON.parse(readFileSync(file, 'utf-8')) as ResetCodeRecord[]
        const t = now()
        for (const r of arr) {
          if (r.expiresAt > t) codes.set(r.sub, r)
        }
      }
    } catch {
      // 损坏则从空开始
    }
  }

  function persist(): void {
    mkdirSync(dir, { recursive: true })
    const tmp = file + '.tmp'
    writeFileSync(tmp, JSON.stringify([...codes.values()], null, 0), { encoding: 'utf-8', mode: 0o600 })
    renameSync(tmp, file)
  }

  function prune(): void {
    const t = now()
    for (const [sub, r] of codes) {
      if (r.expiresAt <= t) codes.delete(sub)
    }
  }

  return {
    issue(sub: string, email: string, code: string, ip: string): void {
      ensureLoaded()
      prune()
      const salt = randomBytes(16)
      const t = now()
      codes.set(sub, {
        sub,
        email,
        codeHash: scryptSync(code, salt, 32).toString('hex'),
        salt: salt.toString('hex'),
        expiresAt: t + ttlSeconds * 1000,
        attempts: 0,
        sentAt: t,
        ip
      })
      persist()
    },

    verifyAndConsume(sub: string, code: string): VerifyResult {
      ensureLoaded()
      const rec = codes.get(sub)
      if (!rec) return 'missing'
      if (rec.expiresAt <= now()) {
        codes.delete(sub)
        persist()
        return 'expired'
      }
      const expected = Buffer.from(rec.codeHash, 'hex')
      const actual = scryptSync(code, Buffer.from(rec.salt, 'hex'), expected.length)
      if (expected.length === actual.length && timingSafeEqual(expected, actual)) {
        codes.delete(sub)
        persist()
        return 'ok'
      }
      rec.attempts++
      if (rec.attempts >= maxAttempts) {
        codes.delete(sub)
        persist()
        return 'too_many'
      }
      persist()
      return 'mismatch'
    },

    peek(sub: string): ResetCodeRecord | undefined {
      ensureLoaded()
      const rec = codes.get(sub)
      if (!rec) return undefined
      if (rec.expiresAt <= now()) {
        codes.delete(sub)
        persist()
        return undefined
      }
      return rec
    }
  }
}

/**
 * 请求/确认编排(依赖注入,路由装配真实实现,单测注入假实现)。
 * 对外一律返回统一文案,不泄露工号是否存在、邮箱是否配置、是否限流。
 */
export interface ResetDeps {
  directory: { findByIdentifier(id: string): Promise<DirectoryUser | null> }
  mailer: Mailer
  codes: ReturnType<typeof createResetCodeStore>
  password: { setPassword(user: DirectoryUser, currentPassword: string | null, newPassword: string): Promise<void> }
  rateLimit: (key: string, limit: number, windowMs: number) => boolean
  /** 重置成功后作废该用户全部会话与 refresh token(默认接 store 实现,测试注入假实现) */
  revokeSessions(sub: string): void
  revokeTokens(sub: string): void
  audit(evt: { event: string; ok: boolean; sub?: string; ip?: string; detail?: string }): void
  now?: () => number
}

/** 统一文案(不泄露账号存在性) */
export const RESET_REQUEST_MESSAGE = '若该工号存在, 验证码已发送至其企业邮箱'
export const RESET_FAIL_MESSAGE = '验证码无效或已过期, 请重新获取'

/** 请求重置:限流 → 查目录 → 有邮箱且邮件已配置才生成码并发送;任何分支都返回统一文案 */
export async function requestReset(input: { sub: string; ip: string }, deps: ResetDeps): Promise<{ message: string }> {
  const sub = input.sub.trim()
  const ip = input.ip
  const deny = (detail: string): { message: string } => {
    deps.audit({ event: 'reset_request', ok: false, sub: sub || undefined, ip, detail })
    return { message: RESET_REQUEST_MESSAGE }
  }
  if (!sub) return deny('工号为空')
  // 冷却与小时配额必须用不同 key:滑动窗口实现按当前窗口裁剪同一 key 的时间戳,
  // 同 key 的 60s 调用会把 1h 历史裁掉,导致小时上限永不触发
  const limits = [
    { key: `reset:send:${sub}`, limit: 1, windowMs: 60_000 },
    { key: `reset:send:h:${sub}`, limit: 5, windowMs: 3_600_000 },
    { key: `reset:ip:${ip}`, limit: 10, windowMs: 3_600_000 }
  ]
  for (const l of limits) {
    if (!deps.rateLimit(l.key, l.limit, l.windowMs)) return deny(`限流:${l.key}`)
  }

  const user = await deps.directory.findByIdentifier(sub)
  let sent = false
  let reason = '目录中无此工号'
  if (user && !user.email) {
    reason = '用户未登记企业邮箱'
  } else if (user && !deps.mailer.isConfigured()) {
    reason = '邮件服务未配置'
  } else if (user?.email) {
    const code = String(randomInt(0, 1_000_000)).padStart(6, '0')
    deps.codes.issue(sub, user.email, code, ip)
    try {
      await deps.mailer.sendVerificationCode({
        to: user.email,
        code,
        ttlMinutes: Math.max(1, Math.round(config.resetCodeTtlSeconds / 60))
      })
      sent = true
      reason = '已发送'
    } catch (err) {
      reason = `发送失败: ${(err as Error).message}`
    }
  }
  deps.audit({ event: 'reset_request', ok: true, sub: user?.sub ?? sub, ip, detail: JSON.stringify({ sent, reason }) })
  return { message: RESET_REQUEST_MESSAGE }
}

/** 确认重置:校验密码长度 → 消费验证码 → 查目录 → 写密码 → 踢会话/token → 变更通知(best-effort) */
export async function confirmReset(
  input: { sub: string; code: string; newPassword: string; ip: string },
  deps: ResetDeps
): Promise<{ ok: true } | { ok: false; message: string }> {
  const sub = input.sub.trim()
  // 审计优先用目录规范 sub(手机号输入→工号);查不到目录用户时保留原始输入
  let auditSub = sub
  const fail = (detail: string): { ok: false; message: string } => {
    deps.audit({ event: 'reset_confirm', ok: false, sub: auditSub || undefined, ip: input.ip, detail })
    return { ok: false, message: RESET_FAIL_MESSAGE }
  }
  // 长度规则与 /profile/password 对齐(仅要求 ≥8);不符时不消费验证码,且属用户自有输入,给明确提示
  if (input.newPassword.length < 8) {
    deps.audit({ event: 'reset_confirm', ok: false, sub: sub || undefined, ip: input.ip, detail: '新密码少于 8 位' })
    return { ok: false, message: '新密码至少 8 位' }
  }

  const result = deps.codes.verifyAndConsume(sub, input.code)
  if (result !== 'ok') return fail(`验证码校验失败(${result})`)

  const user = await deps.directory.findByIdentifier(sub)
  if (!user) return fail('目录中无此工号')
  auditSub = user.sub
  try {
    await deps.password.setPassword(user, null, input.newPassword)
  } catch (err) {
    return fail(`设置密码失败: ${(err as Error).message}`)
  }

  // 密码已改是既成事实:revoke 落盘异常只记审计,不阻断成功返回与变更通知
  let revokeError: string | undefined
  try {
    deps.revokeSessions(user.sub)
    deps.revokeTokens(user.sub)
  } catch (err) {
    revokeError = (err as Error).message
  }
  let noticeError: string | undefined
  if (user.email) {
    try {
      await deps.mailer.sendPasswordChangedNotice({ to: user.email })
    } catch (err) {
      noticeError = (err as Error).message
    }
  }
  const details = [
    revokeError ? `revokeError: ${revokeError}` : '',
    noticeError ? `变更通知发送失败: ${noticeError}` : ''
  ].filter(Boolean)
  deps.audit({
    event: 'reset_confirm',
    ok: true,
    sub: user.sub,
    ip: input.ip,
    detail: details.length ? details.join('; ') : undefined
  })
  return { ok: true }
}
