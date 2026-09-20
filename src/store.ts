import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync } from 'node:fs'
import { join } from 'node:path'
import { config } from './config.ts'

/**
 * SSO 会话与授权码存储。
 * - 会话:内存 + JSON 落盘(重启不丢;数百人量级 JSON 足够,免数据库运维)
 * - 授权码/登录事务:仅内存(短 TTL 一次性,丢失=重新登录,可接受)
 */
export interface SsoSession {
  sid: string
  sub: string
  name: string
  dept: string
  /** 钉钉号(目录有值才记录,用于下发 dingtalk claim;空则省略) */
  dingtalkUserId?: string
  /** 认证方式:qr(钉钉扫码)| pwd(账号密码) */
  authMode: 'qr' | 'pwd'
  /** 会话建立时间(用于扫码后 10 分钟内免验证设置初始密码) */
  createdAt: number
  expiresAt: number
}

const sessionsFile = join(config.dataDir, 'sessions.json')

const sessions = new Map<string, SsoSession>()
let loaded = false

function ensureLoaded(): void {
  if (loaded) return
  loaded = true
  try {
    if (existsSync(sessionsFile)) {
      const arr = JSON.parse(readFileSync(sessionsFile, 'utf-8')) as SsoSession[]
      const now = Date.now()
      for (const s of arr) {
        if (s.expiresAt > now) sessions.set(s.sid, s)
      }
    }
  } catch {
    // 损坏则从空开始
  }
}

function persist(): void {
  mkdirSync(config.dataDir, { recursive: true })
  const tmp = sessionsFile + '.tmp'
  writeFileSync(tmp, JSON.stringify([...sessions.values()], null, 0), 'utf-8')
  renameSync(tmp, sessionsFile)
}

function prune(): void {
  const now = Date.now()
  for (const [sid, s] of sessions) {
    if (s.expiresAt <= now) sessions.delete(sid)
  }
}

export function createSession(sub: string, name: string, dept: string, authMode: 'qr' | 'pwd', dingtalkUserId?: string): SsoSession {
  ensureLoaded()
  prune()
  const session: SsoSession = {
    sid: randomBytes(24).toString('hex'),
    sub,
    name,
    dept,
    dingtalkUserId: dingtalkUserId || undefined,
    authMode,
    createdAt: Date.now(),
    expiresAt: Date.now() + config.sessionTtlMs
  }
  sessions.set(session.sid, session)
  persist()
  return session
}

export function getSession(sid: string | undefined): SsoSession | null {
  ensureLoaded()
  if (!sid) return null
  const s = sessions.get(sid)
  if (!s) return null
  if (s.expiresAt <= Date.now()) {
    sessions.delete(sid)
    persist()
    return null
  }
  // 滑动续期
  s.expiresAt = Date.now() + config.sessionTtlMs
  return s
}

export function destroySession(sid: string | undefined): void {
  ensureLoaded()
  if (sid && sessions.delete(sid)) persist()
}

/** 吊销指定用户的全部会话(可保留当前会话),返回吊销数量;用于改密后踢下线其它端 */
export function destroySessionsForSub(sub: string, exceptSid?: string): number {
  ensureLoaded()
  let n = 0
  for (const [sid, s] of sessions) {
    if (s.sub === sub && sid !== exceptSid) {
      sessions.delete(sid)
      n++
    }
  }
  if (n) persist()
  return n
}

// ---- 授权码(一次性,仅内存) ----

export interface PendingTx {
  id: string
  client_id: string
  redirect_uri: string
  scope: string
  state?: string
  nonce?: string
  code_challenge?: string
  created_at: number
}

export interface AuthCode {
  code: string
  client_id: string
  redirect_uri: string
  sub: string
  name: string
  dept: string
  /** 钉钉号(随 code 透传,供换 token 时签发 dingtalk claim;空则省略) */
  dingtalkUserId?: string
  nonce?: string
  code_challenge?: string
  expires_at: number
  used: boolean
}

const txs = new Map<string, PendingTx>()
const codes = new Map<string, AuthCode>()

// ---- refresh token(持久化,使用即轮换) ----

export interface RefreshTokenRecord {
  token: string
  sub: string
  name: string
  dept: string
  /** 钉钉号(随 refresh token 透传,刷新时用于签发 dingtalk claim;空则省略) */
  dingtalkUserId?: string
  client_id: string
  expires_at: number
  /** 首次授权时间(绝对会话上限的起算点,轮换不更新);老记录可能缺失 */
  auth_time?: number
}

const RT_FILE = join(config.dataDir, 'refresh_tokens.json')
const refreshTokens = new Map<string, RefreshTokenRecord>()
let rtLoaded = false

function rtLoad(): void {
  if (rtLoaded) return
  rtLoaded = true
  try {
    if (existsSync(RT_FILE)) {
      const arr = JSON.parse(readFileSync(RT_FILE, 'utf-8')) as RefreshTokenRecord[]
      const now = Date.now()
      for (const r of arr) if (r.expires_at > now) refreshTokens.set(r.token, r)
    }
  } catch {
    // 损坏则从空开始
  }
}

function rtPersist(): void {
  mkdirSync(config.dataDir, { recursive: true })
  const tmp = RT_FILE + '.tmp'
  writeFileSync(tmp, JSON.stringify([...refreshTokens.values()], null, 0), 'utf-8')
  renameSync(tmp, RT_FILE)
}

/** 签发 refresh token(绑定用户与客户端;绝对上限由首次授权时间 authTime + ttlMs 决定,轮换不延长) */
export function issueRefreshToken(sub: string, name: string, dept: string, clientId: string, dingtalkUserId: string | undefined, ttlMs: number, authTime: number): string {
  rtLoad()
  const now = Date.now()
  for (const [t, r] of refreshTokens) if (r.expires_at <= now) refreshTokens.delete(t)
  const token = randomBytes(32).toString('hex')
  // 绝对上限:expires_at 始终从首次授权时间起算,轮换不延长
  refreshTokens.set(token, {
    token, sub, name, dept, dingtalkUserId: dingtalkUserId || undefined,
    client_id: clientId, expires_at: authTime + ttlMs, auth_time: authTime
  })
  rtPersist()
  return token
}

/** 校验并轮换:成功返回用户信息与首次授权时间并废弃旧 token(调用方应签发新 refresh token) */
export function consumeRefreshToken(token: string, clientId: string): { sub: string; name: string; dept: string; dingtalkUserId?: string; authTime: number } | null {
  rtLoad()
  const r = refreshTokens.get(token)
  if (!r) return null
  refreshTokens.delete(token)
  rtPersist()
  if (r.client_id !== clientId || r.expires_at <= Date.now()) return null
  // 老记录(本改动前写入)无 auth_time,按当前时间兜底,避免立即失效
  return {
    sub: r.sub, name: r.name, dept: r.dept, dingtalkUserId: r.dingtalkUserId,
    authTime: r.auth_time ?? Date.now()
  }
}

/** 登出时吊销该用户在某客户端下的全部 refresh token */
export function revokeRefreshTokens(sub: string, clientId?: string): void {
  rtLoad()
  let changed = false
  for (const [t, r] of refreshTokens) {
    if (r.sub === sub && (!clientId || r.client_id === clientId)) {
      refreshTokens.delete(t)
      changed = true
    }
  }
  if (changed) rtPersist()
}

export function putTx(tx: PendingTx): void {
  const now = Date.now()
  for (const [id, t] of txs) {
    if (now - t.created_at > config.txTtlMs) txs.delete(id)
  }
  txs.set(tx.id, tx)
}

export function takeTx(id: string): PendingTx | null {
  const tx = txs.get(id)
  if (!tx) return null
  if (Date.now() - tx.created_at > config.txTtlMs) {
    txs.delete(id)
    return null
  }
  // 登录事务在签发 code 前允许反复尝试(扫码跳转/密码输错重试),完成时显式删除
  return tx
}

export function finishTx(id: string): PendingTx | null {
  const tx = takeTx(id)
  if (tx) txs.delete(id)
  return tx
}

export function issueCode(tx: PendingTx, session: SsoSession): string {
  const code = randomBytes(24).toString('hex')
  codes.set(code, {
    code,
    client_id: tx.client_id,
    redirect_uri: tx.redirect_uri,
    sub: session.sub,
    name: session.name,
    dept: session.dept,
    dingtalkUserId: session.dingtalkUserId,
    nonce: tx.nonce,
    code_challenge: tx.code_challenge,
    expires_at: Date.now() + config.codeTtlMs,
    used: false
  })
  return code
}

export function consumeCode(code: string): AuthCode | null {
  const c = codes.get(code)
  if (!c) return null
  codes.delete(code)
  if (c.used || Date.now() > c.expires_at) return null
  c.used = true
  return c
}
