import { existsSync, readFileSync } from 'node:fs'
import { config } from './config.ts'

/**
 * 静态客户端注册(自研内网系统用配置文件管理,不做动态注册/管理界面)。
 * dept_role_map:部门名 → 本客户端下授予的角色;default_role 为兜底角色。
 */
export interface OidcClient {
  client_id: string
  client_secret: string
  redirect_uris: string[]
  post_logout_redirect_uris?: string[]
  /** 客户端名称(审计与登录页展示) */
  name?: string
  dept_role_map?: Record<string, string>
  default_role?: string
  /** 本客户端 refresh token 有效期(小时),默认 12;由首次授权时间起算(轮换不延长) */
  refresh_ttl_hours?: number
  /** 允许本客户端通过 token-exchange 换取的目标受众(如 ["router"]);未配置=禁止交换 */
  allowed_audiences?: string[]
}

interface ClientsFile {
  clients: OidcClient[]
}

let cached: Map<string, OidcClient> | null = null
let loadedAt = 0

/**
 * 展开 client_secret 的 ${ENV:NAME} 占位;非占位值原样返回。
 * 缺失的环境变量直接抛错(快速失败,避免静默变成空 secret 导致鉴权绕过)。
 */
export function expandSecret(raw: string): string {
  const m = /^\$\{ENV:([A-Za-z_][A-Za-z0-9_]*)\}$/.exec(raw)
  if (!m) {
    // 含 ${ENV: 但格式不合法的(大小写不敏感),视为配置错误(否则会被当成字面量 secret 静默生效)
    if (/\$\{env:/i.test(raw)) {
      throw new Error(`client_secret 占位格式非法(需形如 \${ENV:NAME}): ${raw}`)
    }
    return raw
  }
  const value = process.env[m[1]]
  if (!value || value.trim() === '') throw new Error(`client_secret 引用了未设置环境变量: ${m[1]}`)
  return value.trim()
}

export function loadClients(): Map<string, OidcClient> {
  // 每 30 秒允许热更新(改配置无需重启)
  const now = Date.now()
  if (cached && now - loadedAt < 30_000) return cached
  const path = config.clientsPath
  if (!existsSync(path)) {
    if (!cached) throw new Error(`客户端注册文件不存在:${path}(参考 clients.example.json)`)
    return cached
  }
  const file = JSON.parse(readFileSync(path, 'utf-8')) as ClientsFile
  const map = new Map<string, OidcClient>()
  for (const c of file.clients ?? []) {
    // 空/非字符串 secret 是配置错误:会退化成 safeEqual('','') 放行,必须启动即失败
    if (typeof c.client_secret !== 'string' || c.client_secret === '') {
      throw new Error(`客户端 ${c.client_id} 的 client_secret 缺失或为空(参考 clients.example.json)`)
    }
    c.client_secret = expandSecret(c.client_secret)
    map.set(c.client_id, c)
  }
  cached = map
  loadedAt = now
  return map
}

export function getClient(clientId: string | null | undefined): OidcClient | null {
  if (!clientId) return null
  return loadClients().get(clientId) ?? null
}

export function expandRoles(client: OidcClient, dept: string): string[] {
  const role = client.dept_role_map?.[dept] ?? client.default_role ?? 'user'
  return [role]
}

/** 取客户端 refresh token 有效期(小时):非法值回退默认 12,避免 NaN 导致永不过期 */
export function refreshTtlHours(client: OidcClient): number {
  const raw = client.refresh_ttl_hours
  if (typeof raw !== 'number' || !Number.isFinite(raw) || raw <= 0) return 12
  return raw
}
