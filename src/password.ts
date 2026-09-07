import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { Attribute, Change, Client } from 'ldapts'
import { config } from './config.ts'
import type { DirectoryUser } from './directory.ts'

/**
 * 密码校验与设置:
 * - LdapVerifier:生产——用 OpenLDAP bind 验证(密码哈希/ppolicy 全部由 LDAP 负责);
 *   设密 = 用管理账号改该用户的 userPassword。SSO 自身不存储任何密码。
 * - FileVerifier:开发/烟测——文件目录内 scrypt 哈希。
 * 口径:verify(identifier, password) 返回用户(成功)或 null(失败/禁用)。
 */
export interface PasswordVerifier {
  verify(identifier: string, password: string): Promise<DirectoryUser | null>
  hasPassword(user: DirectoryUser): Promise<boolean>
  /** 设密/改密。currentPassword 在"改密"时必填校验;"激活"场景由调用方判定豁免 */
  setPassword(user: DirectoryUser, currentPassword: string | null, newPassword: string): Promise<void>
}

class LdapVerifier implements PasswordVerifier {
  private ldap = config.ldap!

  async verify(identifier: string, password: string): Promise<DirectoryUser | null> {
    const { createDirectory } = await import('./directory.ts')
    const user = await createDirectory().findByIdentifier(identifier)
    if (!user) return null
    // 用目录返回的条目 DN 做 bind —— 对任意 LDAP 布局通用
    if (!user.dn) return null
    const client = new Client({ url: this.ldap.url })
    try {
      await client.bind(user.dn, password)
      return user
    } catch {
      return null
    } finally {
      await client.unbind().catch(() => {})
    }
  }

  async hasPassword(user: DirectoryUser): Promise<boolean> {
    // LDAP 下无法便宜地判断是否已设密;按"已有密码"处理 → 改密必须提供当前密码。
    // 初始激活走扫码会话豁免通道(见 /profile/password 路由)。
    return true
  }

  async setPassword(user: DirectoryUser, currentPassword: string | null, newPassword: string): Promise<void> {
    if (currentPassword !== null) {
      const ok = await this.verify(user.sub, currentPassword)
      if (!ok) throw new Error('当前密码不正确')
    }
    const target = user.dn ?? `uid=${escapeDn(user.sub)},ou=people,${this.ldap.baseDn}`
    const client = new Client({ url: this.ldap.url })
    try {
      await client.bind(this.ldap.bindDn, this.ldap.bindPassword)
      await client.modify(target, new Change({
        operation: 'replace',
        modification: new Attribute({ type: 'userPassword', values: [newPassword] })
      }))
    } finally {
      await client.unbind().catch(() => {})
    }
  }
}

class FileVerifier implements PasswordVerifier {
  private readUsers(): Array<DirectoryUser & { passwordHash?: string }> {
    return JSON.parse(readFileSync(config.fileUsersPath, 'utf-8'))
  }

  private writeUsers(users: Array<DirectoryUser & { passwordHash?: string }>): void {
    writeFileSync(config.fileUsersPath, JSON.stringify(users, null, 2), 'utf-8')
  }

  async verify(identifier: string, password: string): Promise<DirectoryUser | null> {
    const user = this.readUsers().find((u) => (u.sub === identifier || u.mobile === identifier))
    if (!user?.passwordHash) return null
    const [, saltHex, hashHex] = user.passwordHash.split(':')
    const expected = Buffer.from(hashHex, 'hex')
    const actual = scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length)
    if (!timingSafeEqual(expected, actual)) return null
    const { passwordHash: _ph, ...pub } = user
    return pub
  }

  async hasPassword(user: DirectoryUser): Promise<boolean> {
    return this.readUsers().some((u) => u.sub === user.sub && !!u.passwordHash)
  }

  async setPassword(user: DirectoryUser, currentPassword: string | null, newPassword: string): Promise<void> {
    const users = this.readUsers()
    const target = users.find((u) => u.sub === user.sub)
    if (!target) throw new Error('用户不存在')
    if (currentPassword !== null) {
      const ok = await this.verify(user.sub, currentPassword)
      if (!ok) throw new Error('当前密码不正确')
    }
    const salt = randomBytes(16)
    const hash = scryptSync(newPassword, salt, 32)
    target.passwordHash = `scrypt:${salt.toString('hex')}:${hash.toString('hex')}`
    this.writeUsers(users)
  }
}

export function createPasswordVerifier(): PasswordVerifier {
  if (config.ldap) return new LdapVerifier()
  return new FileVerifier()
}

function escapeDn(v: string): string {
  return v.replace(/[,+"\\<>;]/g, '\\' + '$&')
}
