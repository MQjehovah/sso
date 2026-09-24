import { readFileSync } from 'node:fs'
import { Client } from 'ldapts'
import { config, type ProfileOverride } from './config.ts'

/**
 * 用户目录抽象:
 * - LdapDirectory:生产,读 LDAP(属性名/用户容器/禁用标记均可用环境变量适配)
 * - FileDirectory:开发/烟测,JSON fixture(无 Docker 环境验证协议用)
 * 目录条目不含密码;认证见 password.ts。
 */
export interface DirectoryUser {
  /** 唯一标识(OIDC sub;自建目录=工号,Synology=uid 账号名) */
  sub: string
  name: string
    dept: string
    /** 邮箱(LDAP mail 属性);登录后作为 id_token 的 email claim 下发给业务系统 */
    email?: string
    mobile?: string
  dingtalkUserId: string
  status: 'active' | 'disabled'
  /** 条目真实 DN(密码 bind 用;任意布局通用) */
  dn?: string
}

export interface DirectoryProvider {
  findByDingtalkUserId(id: string): Promise<DirectoryUser | null>
  /** 唯一标识或手机号(密码登录用) */
  findByIdentifier(id: string): Promise<DirectoryUser | null>
}

/**
 * 在目录结果上应用 SSO_PROFILE_OVERRIDES 补充映射(LDAP 缺属性场景,如 AD 无 dingtalkUserId):
 * 仅非空字符串覆盖(空串保留目录原值);覆盖后 dingtalkUserId 保持 string。
 */
export function applyProfileOverrides(
  user: DirectoryUser | null,
  overrides: Record<string, ProfileOverride> = config.profileOverrides
): DirectoryUser | null {
  if (!user) return null
  const o = overrides[user.sub]
  if (!o) return user
  const nonEmpty = (v: string | undefined): string | undefined => (typeof v === 'string' && v !== '' ? v : undefined)
  return {
    ...user,
    name: nonEmpty(o.name) ?? user.name,
    dept: nonEmpty(o.dept) ?? user.dept,
    email: nonEmpty(o.email) ?? user.email,
    mobile: nonEmpty(o.mobile) ?? user.mobile,
    dingtalkUserId: nonEmpty(o.dingtalkUserId) ?? user.dingtalkUserId
  }
}

export interface LdapAttrs {
  sub: string
  name: string
  dept: string
  mobile: string
  mail: string
  dingtalk: string
  status: string
}

/**
 * 把 LDAP 条目映射为 DirectoryUser:属性名一律取自配置(LDAP_ATTR_*),不写死默认属性名。
 * 抽成纯函数便于用自定义属性布局单测(如 LDAP_ATTR_MOBILE=mobileNumber)。
 */
export function mapLdapEntry(e: Record<string, unknown>, attrs: LdapAttrs, statusDisabledFlag: string): DirectoryUser {
  const statusRaw = e[attrs.status] ? String(e[attrs.status]) : ''
  const disabled = statusRaw.toLowerCase().includes(statusDisabledFlag.toLowerCase())
  const mob = e[attrs.mobile]
  return {
    sub: String(e[attrs.sub] ?? ''),
    name: String(e[attrs.name] || e.cn || ''),
    dept: String(e[attrs.dept] ?? ''),
    email: e[attrs.mail] ? String(e[attrs.mail]).trim().toLowerCase() : undefined,
    mobile: mob ? String(mob) : undefined,
    dingtalkUserId: String(e[attrs.dingtalk] ?? ''),
    status: disabled ? 'disabled' : 'active',
    dn: typeof e.dn === 'string' ? e.dn : undefined
  }
}

class LdapDirectory implements DirectoryProvider {
  private ldap = config.ldap!

  async findByDingtalkUserId(id: string): Promise<DirectoryUser | null> {
    return applyProfileOverrides(await this.search(`(${this.ldap.attrs.dingtalk}=${escapeFilter(id)})`))
  }

  async findByIdentifier(id: string): Promise<DirectoryUser | null> {
    const f = escapeFilter(id)
    // 标识 = 主标识属性(sub 对应属性)或手机号
    return applyProfileOverrides(await this.search(`(|(${this.ldap.attrs.sub}=${f})(${this.ldap.attrs.mobile}=${f}))`))
  }

  private async search(filter: string): Promise<DirectoryUser | null> {
    const client = new Client({ url: this.ldap.url })
    const a = this.ldap.attrs
    try {
      await client.bind(this.ldap.bindDn, this.ldap.bindPassword)
      const { searchEntries } = await client.search(this.ldap.peopleBase, {
        scope: 'sub',
        filter,
          attributes: [a.sub, a.name, 'cn', a.dept, a.mobile, a.mail, a.dingtalk, a.status]
      })
      if (searchEntries.length === 0) return null
      return mapLdapEntry(searchEntries[0] as unknown as Record<string, unknown>, a, this.ldap.statusDisabledFlag)
    } finally {
      await client.unbind().catch(() => {})
    }
  }
}

interface FileUser extends DirectoryUser {
  /** FileVerifier 用的本地哈希(scrypt),仅存在于文件目录实现 */
  passwordHash?: string
}

class FileDirectory implements DirectoryProvider {
  private users(): FileUser[] {
    // 每次读盘:烟测中途可修改用户状态(如离职禁用)
    return JSON.parse(readFileSync(config.fileUsersPath, 'utf-8'))
  }

  async findByDingtalkUserId(id: string): Promise<DirectoryUser | null> {
    return applyProfileOverrides(this.users().find((u) => u.dingtalkUserId === id) ?? null)
  }

  async findByIdentifier(id: string): Promise<DirectoryUser | null> {
    return applyProfileOverrides(this.users().find((u) => u.sub === id || u.mobile === id) ?? null)
  }
}

export function createDirectory(): DirectoryProvider {
  if (config.ldap) return new LdapDirectory()
  console.warn('[directory] 未配置 LDAP_URL,使用文件目录(仅限开发/烟测)')
  return new FileDirectory()
}

export function escapeFilter(v: string): string {
  return v.replace(/[*()\\\0]/g, (c) => '\\' + c.charCodeAt(0).toString(16).padStart(2, '0'))
}

export type { FileUser }
