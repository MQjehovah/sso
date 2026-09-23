/**
 * 密码策略提示(纯函数, 便于单测):
 * - checkPasswordStrength 是本地预检, 只覆盖常见强度项; 最终以目录(域)策略为准。
 * - friendlyPasswordError 把目录返回的错误文本翻译成用户可读文案;
 *   无法识别时原样返回, 不吞掉原始信息。
 * 注意: 映射结果会直接展示给用户, 不得包含内部错误堆栈/凭据。
 */

export const PASSWORD_POLICY_HINT = '至少 8 位，且需包含大写字母、小写字母、数字和特殊字符'

/**
 * 宽松特殊字符定义: 除字母/数字/空白外的可见字符都算特殊字符。
 * 比目录策略宽, 只用于预检提示; 预检通过但目录仍拒绝时由 friendlyPasswordError 兜底。
 */
const SPECIAL_CHAR_RE = /[^A-Za-z0-9\s]/

/** 返回缺失项的中文提示列表; 全部满足返回空数组 */
export function checkPasswordStrength(pw: string): string[] {
  const issues: string[] = []
  if (pw.length < 8) issues.push('不足 8 位')
  if (!/[A-Z]/.test(pw)) issues.push('缺大写字母')
  if (!/[a-z]/.test(pw)) issues.push('缺小写字母')
  if (!/[0-9]/.test(pw)) issues.push('缺数字')
  if (!SPECIAL_CHAR_RE.test(pw)) issues.push('缺特殊字符')
  return issues
}

/** 把 checkPasswordStrength 的缺失项拼成用户提示(issues 非空时调用) */
export function describePasswordIssues(issues: string[]): string {
  return `新密码不符合要求: ${issues.join('、')}`
}

/**
 * 目录(如 Synology Directory Server)拒绝新密码时, 把原始错误翻译为可操作提示。
 * 匹配顺序: 已知 Syno 规则 → 未知 Syno 规则 → LDAP 约束违规(0x13) → 原样返回。
 * (同时带未知 Syno 与 0x13 时保留 Syno token, 便于管理员定位目录侧规则。)
 */
export function friendlyPasswordError(err: unknown): string {
  const raw = err instanceof Error ? err.message : typeof err === 'string' ? err : String(err ?? '')
  const message = raw.trim()
  if (!message) return '设置密码失败, 请稍后重试或联系管理员'

  if (message.includes('SynoSpecialChar')) return '新密码需包含特殊字符（如 !@#$%^&*）'
  if (message.includes('SynoMixedCase')) return '新密码需同时包含大写和小写字母'
  if (message.includes('SynoDigit') || message.includes('SynoNumeric')) return '新密码需包含数字'
  if (message.includes('SynoTooShort') || message.includes('SynoPasswordLength')) return '新密码长度不足'
  const token = message.match(/Syno[A-Za-z0-9]+/)?.[0]
  if (token) return `不符合域密码策略（目录错误: ${token}）`
  if (/0x13/i.test(message)) return `不符合域密码策略：${PASSWORD_POLICY_HINT}`
  return message
}
