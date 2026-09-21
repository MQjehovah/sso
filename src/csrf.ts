import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

const secret = process.env.SSO_CSRF_SECRET || randomBytes(32).toString('hex')
const TTL_MS = 30 * 60_000

/** 生成与 sid 绑定的 CSRF token:`<exp>.<hmac>`。 */
export function issueCsrf(sid: string): string {
  const exp = Date.now() + TTL_MS
  const sig = createHmac('sha256', secret).update(`${sid}:${exp}`).digest('hex')
  return `${exp}.${sig}`
}

/** 校验 CSRF token:格式、过期、签名、sid 绑定。 */
export function verifyCsrf(sid: string, token: string | undefined): boolean {
  if (!token) return false
  const parts = token.split('.')
  if (parts.length !== 2) return false
  const exp = Number(parts[0])
  if (!Number.isFinite(exp) || exp < Date.now()) return false
  const expected = createHmac('sha256', secret).update(`${sid}:${exp}`).digest('hex')
  const a = Buffer.from(parts[1], 'utf-8')
  const b = Buffer.from(expected, 'utf-8')
  return a.length === b.length && timingSafeEqual(a, b)
}
