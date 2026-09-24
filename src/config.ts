/** SSO 服务配置:全部来自环境变量(见 .env.example) */
function req(name: string): string {
  const v = process.env[name]
  if (!v) throw new Error(`缺少必需环境变量 ${name}(参考 .env.example)`)
  return v
}

function trimSlash(u: string): string {
  return u.replace(/\/+$/, '')
}

/** 读取正整数环境变量:未设置/空串返回默认值,非法值快速失败(避免 0 或 NaN 静默产生不可用 token) */
function posIntEnv(name: string, def: number, min = 1): number {
  const raw = process.env[name]
  if (raw === undefined || raw.trim() === '') return def
  const n = Number(raw)
  if (!Number.isFinite(n) || n < min) {
    throw new Error(`环境变量 ${name} 必须是 >= ${min} 的数字,当前为 ${JSON.stringify(raw)}`)
  }
  return n
}

/** 目录补充映射:key=sub,value=字段名→字符串(LDAP 缺属性/写不进去时在目录结果上覆盖,如 AD 无 dingtalkUserId) */
export type ProfileOverride = Record<string, string>

/** 解析 SSO_PROFILE_OVERRIDES(JSON);结构非法则整体按空处理并告警,不影响启动 */
function parseProfileOverrides(raw: string | undefined): Record<string, ProfileOverride> {
  const text = (raw ?? '').trim()
  if (text === '') return {}
  let data: unknown
  try {
    data = JSON.parse(text)
  } catch (err) {
    console.warn(`[config] SSO_PROFILE_OVERRIDES 不是合法 JSON,已按空处理: ${(err as Error).message}`)
    return {}
  }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    console.warn('[config] SSO_PROFILE_OVERRIDES 必须是 {sub: {字段: 字符串}} 形式的对象,已按空处理')
    return {}
  }
  for (const [sub, fields] of Object.entries(data)) {
    if (typeof fields !== 'object' || fields === null || Array.isArray(fields)) {
      console.warn(`[config] SSO_PROFILE_OVERRIDES 条目 ${sub} 必须是 {字段: 字符串} 对象,已按空处理`)
      return {}
    }
    for (const [key, value] of Object.entries(fields)) {
      if (typeof value !== 'string') {
        console.warn(`[config] SSO_PROFILE_OVERRIDES 条目 ${sub}.${key} 的值必须是字符串,已按空处理`)
        return {}
      }
    }
  }
  return data as Record<string, ProfileOverride>
}

let profileOverridesCache: Record<string, ProfileOverride> | undefined

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
          attrs: { sub: string; name: string; dept: string; mobile: string; mail: string; dingtalk: string; status: string }
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
          mail: process.env.LDAP_ATTR_MAIL ?? 'mail',
        dingtalk: process.env.LDAP_ATTR_DINGTALK ?? 'dingtalkUserId',
        status: process.env.LDAP_ATTR_STATUS ?? 'aiStatus'
      },
      statusDisabledFlag: process.env.LDAP_STATUS_DISABLED_FLAG ?? 'disabled'
    }
  },
  fileUsersPath: process.env.FILE_USERS_PATH ?? './data/users.json',

  /**
   * 目录结果补充映射(SSO_PROFILE_OVERRIDES JSON,形如 {"工号":{"dingtalkUserId":"...","mobile":"..."}})。
   * 懒解析并缓存;仅非空字符串在目录结果上覆盖,空串/非法结构不生效(非法时整体按空并告警)。
   */
  get profileOverrides(): Record<string, ProfileOverride> {
    if (!profileOverridesCache) profileOverridesCache = parseProfileOverrides(process.env.SSO_PROFILE_OVERRIDES)
    return profileOverridesCache
  },

  /** 是否信任反向代理传来的客户端 IP 头(x-real-ip/x-forwarded-for);默认关闭,仅当服务不直接对外暴露时开启 */
  get trustProxy(): boolean {
    return (process.env.SSO_TRUST_PROXY ?? '').trim().toLowerCase() === 'true'
  },

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
  keyRetireAfterHours: posIntEnv('SSO_KEY_RETIRE_AFTER_HOURS', 2, 0),
  /** access_token 寿命(秒),默认 10 分钟;缩短以限制登出后的残留有效期 */
  accessTokenTtlSeconds: posIntEnv('SSO_ACCESS_TOKEN_TTL_SECONDS', 600),
  /** id_token 寿命(秒),默认 10 分钟 */
  idTokenTtlSeconds: posIntEnv('SSO_ID_TOKEN_TTL_SECONDS', 600),
  /** token-exchange 换取的 access_token 寿命(秒),默认 1 小时 */
  exchangeTtlSeconds: posIntEnv('SSO_EXCHANGE_TTL', 3600),

  /** 邮件发送(SMTP,可选;未配置时自助重置降级提示,不影响启动) */
  smtp: {
    host: (process.env.SSO_SMTP_HOST ?? '').trim(),
    port: posIntEnv('SSO_SMTP_PORT', 465, 1),
    secure: (process.env.SSO_SMTP_SECURE ?? 'true').trim().toLowerCase() !== 'false',
    username: (process.env.SSO_SMTP_USERNAME ?? '').trim(),
    password: process.env.SSO_SMTP_PASSWORD ?? '',
    fromName: (process.env.SSO_SMTP_FROM_NAME ?? '零号员工').trim(),
    /** 发件地址, 默认与登录账号相同 */
    from: (process.env.SSO_SMTP_FROM ?? '').trim()
  },
  /** 自助重置验证码有效期(秒), 默认 10 分钟 */
  resetCodeTtlSeconds: posIntEnv('SSO_RESET_CODE_TTL_SECONDS', 600, 60),

  /** 客户端注册文件 */
  clientsPath: process.env.SSO_CLIENTS_PATH ?? './clients.json'
}

export type Config = typeof config
