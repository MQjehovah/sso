/** SSO 服务配置:全部来自环境变量(见 .env.example) */
function req(name: string): string {
  const v = process.env[name]
  if (!v) throw new Error(`缺少必需环境变量 ${name}(参考 .env.example)`)
  return v
}

function trimSlash(u: string): string {
  return u.replace(/\/+$/, '')
}

export const config = {
  port: Number(process.env.SSO_PORT ?? 8091),
  /** 签发者标识与对外地址(生产如 https://sso.company.internal) */
  get issuer(): string {
    return trimSlash(req('SSO_ISSUER'))
  },
  dataDir: process.env.SSO_DATA_DIR ?? './data',
  keysDir: process.env.SSO_KEYS_DIR ?? './keys',

  /** 会话与票据生命周期 */
  sessionTtlMs: Number(process.env.SSO_SESSION_TTL_HOURS ?? 8) * 3_600_000,
  codeTtlMs: 5 * 60_000,
  txTtlMs: 10 * 60_000,

  /**
   * 用户目录:配置 LDAP_URL 则走真实 LDAP,否则使用文件目录(开发/烟测)。
   * 属性名与用户容器均可配,以适配不同 LDAP 布局(自建 OpenLDAP / Synology / AD 均可接入)。
   */
  get ldap():
    | {
        url: string
        bindDn: string
        bindPassword: string
        baseDn: string
        /** 用户条目容器(搜索 base) */
        peopleBase: string
        /** 密码 bind 的用户 DN 模板;默认用搜索返回的条目 DN(适配任意布局) */
        attrs: { sub: string; name: string; dept: string; mobile: string; dingtalk: string; status: string }
        /** status 属性中出现该子串即视为禁用(如 sambaAcctFlags 的 'D') */
        statusDisabledFlag: string
      }
    | null {
    if (!process.env.LDAP_URL) return null
    return {
      url: process.env.LDAP_URL,
      bindDn: req('LDAP_BIND_DN'),
      bindPassword: req('LDAP_BIND_PASSWORD'),
      baseDn: req('LDAP_BASE_DN'),
      peopleBase: process.env.LDAP_PEOPLE_BASE ?? `ou=people,${req('LDAP_BASE_DN')}`,
      attrs: {
        sub: process.env.LDAP_ATTR_SUB ?? 'employeeNumber',
        name: process.env.LDAP_ATTR_NAME ?? 'cn',
        dept: process.env.LDAP_ATTR_DEPT ?? 'departmentNumber',
        mobile: process.env.LDAP_ATTR_MOBILE ?? 'mobile',
        dingtalk: process.env.LDAP_ATTR_DINGTALK ?? 'dingtalkUserId',
        status: process.env.LDAP_ATTR_STATUS ?? 'aiStatus'
      },
      statusDisabledFlag: process.env.LDAP_STATUS_DISABLED_FLAG ?? 'disabled'
    }
  },
  fileUsersPath: process.env.FILE_USERS_PATH ?? './data/users.json',

  /** 钉钉扫码是否已配置(未配置时登录页隐藏扫码入口,/dingtalk/start 返回友好提示) */
  get dingtalkConfigured(): boolean {
    return !!process.env.DINGTALK_APP_KEY && !!process.env.DINGTALK_APP_SECRET
  },

  /** 钉钉扫码 */
  get dingtalk(): { appKey: string; appSecret: string; apiBase: string; oapiBase: string; loginBase: string; redirectUri: string } {
    return {
      appKey: req('DINGTALK_APP_KEY'),
      appSecret: req('DINGTALK_APP_SECRET'),
      apiBase: trimSlash(process.env.DINGTALK_API_BASE ?? 'https://api.dingtalk.com'),
      oapiBase: trimSlash(process.env.DINGTALK_OAPI_BASE ?? 'https://oapi.dingtalk.com'),
      loginBase: trimSlash(process.env.DINGTALK_LOGIN_BASE ?? 'https://login.dingtalk.com'),
      redirectUri: req('SSO_DINGTALK_REDIRECT_URI')
    }
  },

  /** 密钥退休窗口:verifying 密钥超过该时长后移出 JWKS(小时) */
  keyRetireAfterHours: Number(process.env.SSO_KEY_RETIRE_AFTER_HOURS ?? 2),

  /** 客户端注册文件 */
  clientsPath: process.env.SSO_CLIENTS_PATH ?? './clients.json'
}

export type Config = typeof config
