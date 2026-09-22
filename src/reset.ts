import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { config } from './config.ts'

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
