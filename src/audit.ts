import { appendFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { config } from './config.ts'

export interface AuditEvent {
  ts: string
  event: string
  ok: boolean
  sub?: string
  client_id?: string
  ip?: string
  detail?: string
}

const auditPath = join(config.dataDir, 'audit.jsonl')

/** 全部登录/拒绝/敏感操作追加审计(JSONL);控制台同步输出 */
export function audit(event: Omit<AuditEvent, 'ts'>): void {
  const line: AuditEvent = { ts: new Date().toISOString(), ...event }
  try {
    mkdirSync(config.dataDir, { recursive: true })
    appendFileSync(auditPath, JSON.stringify(line) + '\n', 'utf-8')
  } catch {
    // 审计写失败不阻断主流程(磁盘告警由运维监控覆盖)
  }
  console.log(`[audit] ${line.event} ok=${line.ok}${line.sub ? ' sub=' + line.sub : ''}${line.detail ? ' ' + line.detail : ''}`)
}
