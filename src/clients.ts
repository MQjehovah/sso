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
}

interface ClientsFile {
  clients: OidcClient[]
}

let cached: Map<string, OidcClient> | null = null
let loadedAt = 0

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
  for (const c of file.clients ?? []) map.set(c.client_id, c)
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
