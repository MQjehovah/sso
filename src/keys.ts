import { createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { importPKCS8, type CryptoKey } from 'jose'
import { config } from './config.ts'

/**
 * RS256 签发密钥:首次启动自动生成 RSA-2048,私钥文件 600 权限。
 * kid 随机生成并持久化;轮换 = 保留旧私钥双签发/验签期(运维手册另行覆盖 v1 简化为单密钥)。
 */
interface KeyMaterial {
  privateKeyPem: string
  kid: string
}

let cached: { pkcs8: string; kid: string; privateKey: CryptoKey } | null = null

function loadOrCreate(): KeyMaterial {
  const dir = config.keysDir
  const keyPath = join(dir, 'private.pem')
  const kidPath = join(dir, 'kid')
  mkdirSync(dir, { recursive: true })
  if (existsSync(keyPath) && existsSync(kidPath)) {
    return { privateKeyPem: readFileSync(keyPath, 'utf-8'), kid: readFileSync(kidPath, 'utf-8').trim() }
  }
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  const kid = randomBytes(8).toString('hex')
  writeFileSync(keyPath, pem, { mode: 0o600 })
  writeFileSync(kidPath, kid, { mode: 0o600 })
  console.log('[keys] 已生成 RS256 签发密钥(仅首次)')
  return { privateKeyPem: pem, kid }
}

export async function getSigningKey(): Promise<{ pkcs8: string; kid: string; privateKey: CryptoKey }> {
  if (!cached) {
    const m = loadOrCreate()
    cached = { pkcs8: m.privateKeyPem, kid: m.kid, privateKey: await importPKCS8(m.privateKeyPem, 'RS256') }
  }
  return cached
}

/** JWKS 公钥:由私钥文件直接导出公钥成分(不经 WebCrypto,避免不可导出限制) */
export function getPublicJwk(): Record<string, unknown> {
  const { privateKeyPem, kid } = loadOrCreate()
  const jwk = createPublicKey(privateKeyPem).export({ format: 'jwk' }) as Record<string, unknown>
  return { ...jwk, kid, use: 'sig', alg: 'RS256' }
}

/** 验签用公钥(KeyObject;jwtVerify 需要公钥而非私钥) */
let publicKeyCache: ReturnType<typeof createPublicKey> | null = null

export function getPublicKey(): ReturnType<typeof createPublicKey> {
  if (!publicKeyCache) publicKeyCache = createPublicKey(loadOrCreate().privateKeyPem)
  return publicKeyCache
}
