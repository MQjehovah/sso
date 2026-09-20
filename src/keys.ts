import type { KeyObject } from 'node:crypto'
import { config } from './config.ts'
import { KeyRing, type SigningKey } from './keyring.ts'

/**
 * 全局密钥环单例。旧版单密钥(private.pem + kid)会在首次访问时自动迁移。
 */
let ring: KeyRing | null = null

export function keyRing(): KeyRing {
  if (!ring) {
    ring = new KeyRing(config.keysDir)
    if (ring.migrateLegacy()) {
      console.log('[keys] 已从单密钥布局迁移到密钥环')
    }
  }
  return ring
}

export async function getSigningKey(): Promise<SigningKey> {
  return keyRing().signingKey()
}

/** JWKS:active + verifying 公钥 */
export function getPublicJwks(): { keys: Record<string, unknown>[] } {
  return keyRing().publicJwks()
}

/** 按 kid 取验签公钥(Object);不存在/已退休返回 null */
export function getPublicKeyFor(kid: string | undefined): KeyObject | null {
  if (!kid) {
    // 无 kid 时用 active 兜底(兼容极老的 token)
    const active = keyRing().activeKid()
    return active ? keyRing().publicKeyFor(active) : null
  }
  return keyRing().publicKeyFor(kid)
}
