import { createPublicKey, generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { importPKCS8, type CryptoKey } from 'jose'

/**
 * RS256 密钥环:目录内存放多把密钥,active 指针决定签发密钥,
 * verifying 密钥继续发布公钥以验签历史 token,retired 密钥移出 JWKS。
 *
 * 目录布局:
 *   <dir>/active            文本,内容为当前签名 kid
 *   <dir>/<kid>.pem         PKCS8 私钥 (0600)
 *   <dir>/<kid>.meta.json   { kid, createdAt, status, verifyingSince? }
 */
export type KeyStatus = 'active' | 'verifying' | 'retired'

export interface KeyMeta {
  kid: string
  createdAt: number
  status: KeyStatus
  /** 从 active 降级为 verifying 的时间戳(ms);仅 verifying/retired 状态有值 */
  verifyingSince?: number
}

export interface SigningKey {
  kid: string
  pkcs8: string
  privateKey: CryptoKey
}

export class KeyRing {
  private readonly dir: string
  private signing: SigningKey | null = null

  constructor(dir: string) {
    this.dir = dir
    mkdirSync(this.dir, { recursive: true })
  }

  private activeKidPath(): string {
    return join(this.dir, 'active')
  }

  private pemPath(kid: string): string {
    return join(this.dir, `${kid}.pem`)
  }

  private metaPath(kid: string): string {
    return join(this.dir, `${kid}.meta.json`)
  }

  private readMeta(kid: string): KeyMeta | null {
    try {
      return JSON.parse(readFileSync(this.metaPath(kid), 'utf-8')) as KeyMeta
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        console.warn('[keyring] 读取密钥失败:', this.metaPath(kid), (err as Error).message)
      }
      return null
    }
  }

  private writeMeta(meta: KeyMeta): void {
    writeFileSync(this.metaPath(meta.kid), JSON.stringify(meta), { mode: 0o600 })
  }

  activeKid(): string | null {
    try {
      return readFileSync(this.activeKidPath(), 'utf-8').trim() || null
    } catch {
      return null
    }
  }

  private setActive(kid: string): void {
    const tmp = this.activeKidPath() + '.tmp'
    writeFileSync(tmp, kid, { mode: 0o600 })
    renameSync(tmp, this.activeKidPath())
    this.signing = null
  }

  private generate(): KeyMeta {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
    const kid = randomBytes(8).toString('hex')
    writeFileSync(this.pemPath(kid), pem, { mode: 0o600 })
    const meta: KeyMeta = { kid, createdAt: Date.now(), status: 'active' }
    this.writeMeta(meta)
    return meta
  }

  /** 兼容旧布局:private.pem + kid => <kid>.pem + <kid>.meta.json + active */
  migrateLegacy(): boolean {
    const legacyPem = join(this.dir, 'private.pem')
    const legacyKid = join(this.dir, 'kid')
    if (this.activeKid() || !existsSync(legacyPem) || !existsSync(legacyKid)) return false
    const kid = readFileSync(legacyKid, 'utf-8').trim()
    if (!kid) return false
    renameSync(legacyPem, this.pemPath(kid))
    chmodSync(this.pemPath(kid), 0o600)
    this.writeMeta({ kid, createdAt: Date.now(), status: 'active' })
    this.setActive(kid)
    return true
  }

  /** 确保存在 active 密钥(无则生成),返回其 kid */
  async ensureActive(): Promise<KeyMeta> {
    this.migrateLegacy()
    const kid = this.activeKid()
    if (kid) {
      const meta = this.readMeta(kid)
      if (meta && meta.status === 'active') return meta
    }
    const meta = this.generate()
    this.setActive(meta.kid)
    return meta
  }

  /** 生成新密钥并切换 active,旧 active 转 verifying */
  async rotate(): Promise<{ previous: string | null; current: string }> {
    const previous = this.activeKid()
    if (previous) {
      const meta = this.readMeta(previous)
      if (meta) this.writeMeta({ ...meta, status: 'verifying', verifyingSince: Date.now() })
    }
    const created = this.generate()
    this.setActive(created.kid)
    return { previous, current: created.kid }
  }

  list(): KeyMeta[] {
    const out: KeyMeta[] = []
    for (const f of readdirSync(this.dir)) {
      if (!f.endsWith('.meta.json')) continue
      const meta = this.readMeta(f.slice(0, -'.meta.json'.length))
      if (meta) out.push(meta)
    }
    return out.sort((a, b) => a.createdAt - b.createdAt)
  }

  /** 把 verifying 且超过 retireAfterHours 的密钥置 retired(移出 JWKS);返回新退休的 kid */
  async prune(retireAfterHours: number): Promise<string[]> {
    const cutoff = Date.now() - retireAfterHours * 3_600_000
    const retired: string[] = []
    for (const meta of this.list()) {
      const since = meta.verifyingSince ?? meta.createdAt
      if (meta.status === 'verifying' && since <= cutoff) {
        this.writeMeta({ ...meta, status: 'retired' })
        retired.push(meta.kid)
      }
    }
    return retired
  }

  retire(kid: string): boolean {
    const meta = this.readMeta(kid)
    if (!meta || meta.status === 'active' || this.activeKid() === kid) return false
    this.writeMeta({ ...meta, status: 'retired' })
    return true
  }

  /** 当前签发密钥(kid + 私钥) */
  async signingKey(): Promise<SigningKey> {
    await this.ensureActive()
    const kid = this.activeKid()!
    if (!this.signing || this.signing.kid !== kid) {
      const pkcs8 = readFileSync(this.pemPath(kid), 'utf-8')
      this.signing = { kid, pkcs8, privateKey: await importPKCS8(pkcs8, 'RS256') }
    }
    return this.signing
  }

  /** 按 kid 取验签公钥;retired / 不存在返回 null */
  publicKeyFor(kid: string): KeyObject | null {
    const meta = this.readMeta(kid)
    if (!meta || meta.status === 'retired') return null
    try {
      return createPublicKey(readFileSync(this.pemPath(kid), 'utf-8'))
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        console.warn('[keyring] 读取密钥失败:', this.pemPath(kid), (err as Error).message)
      }
      return null
    }
  }

  /** JWKS:active + verifying 的公钥(每次调用实时构建,保证跨进程轮换可见) */
  publicJwks(): { keys: Record<string, unknown>[] } {
    const keys: Record<string, unknown>[] = []
    for (const meta of this.list()) {
      if (meta.status === 'retired') continue
      const pub = this.publicKeyFor(meta.kid)
      if (!pub) continue
      const jwk = pub.export({ format: 'jwk' }) as Record<string, unknown>
      keys.push({ ...jwk, kid: meta.kid, use: 'sig', alg: 'RS256' })
    }
    return { keys }
  }
}
