import { randomBytes } from 'node:crypto'
import { config } from './config.ts'

/**
 * 钉钉扫码认证适配(仅此一处接触钉钉,便于 mock/替换):
 *   扫码页 → authCode → userAccessToken(unionId)→ 企业 token → unionId 换 userid
 * userid 即同步 worker 写入 LDAP 的 dingtalkUserId。
 */
export interface DingtalkIdentity {
  userid: string
  name?: string
  mobile?: string
  email?: string
  /** 钉钉员工详情里的工号(job_number)，用于按 LDAP uid 匹配 */
  jobNumber?: string
}

export function buildScanUrl(state: string): string {
  const cfg = config.dingtalk
  const params = new URLSearchParams({
    client_id: cfg.appKey,
    redirect_uri: cfg.redirectUri,
    response_type: 'code',
    scope: 'openid',
    state,
    prompt: 'consent'
  })
  return `${cfg.loginBase}/oauth2/auth?${params.toString()}`
}

/** 防回调伪造:state 由 SSO 生成并绑定登录事务 */
export function newDingtalkState(): string {
  return randomBytes(16).toString('hex')
}

export async function exchangeIdentity(authCode: string): Promise<DingtalkIdentity> {
  const cfg = config.dingtalk

  // 1) authCode → 用户级 token(含 unionId)
  // 注意: 钉钉新版 v1.0 接口请求体为 camelCase(clientId/clientSecret/grantType)
  const utRes = await fetch(`${cfg.apiBase}/v1.0/oauth2/userAccessToken`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      clientId: cfg.appKey,
      clientSecret: cfg.appSecret,
      code: authCode,
      grantType: 'authorization_code'
    })
  })
  if (!utRes.ok) {
    const body = await utRes.text().catch(() => '')
    console.error(`[dingtalk] userAccessToken HTTP ${utRes.status}: ${body.slice(0, 300)}`)
    throw new Error(`钉钉 userAccessToken 获取失败(HTTP ${utRes.status}${body ? ': ' + body.slice(0, 200) : ''})`)
  }
  // 真实响应只有 accessToken/refreshToken/expireIn/corpId, unionId 需再调 /contact/users/me
  const ut = (await utRes.json()) as { accessToken?: string }
  if (!ut.accessToken) throw new Error('钉钉 userAccessToken 响应异常')

  // 1.5) 用户级 token → 本人信息(unionId/昵称/手机号)
  const meRes = await fetch(`${cfg.apiBase}/v1.0/contact/users/me`, {
    headers: { 'x-acs-dingtalk-access-token': ut.accessToken }
  })
  if (!meRes.ok) {
    const body = await meRes.text().catch(() => '')
    console.error(`[dingtalk] contact/me HTTP ${meRes.status}: ${body.slice(0, 300)}`)
    throw new Error(`钉钉用户信息获取失败(HTTP ${meRes.status}${body ? ': ' + body.slice(0, 200) : ''})`)
  }
  const me = (await meRes.json()) as { unionId?: string; nick?: string; mobile?: string }
  if (!me.unionId) throw new Error('钉钉用户信息缺少 unionId')

  // 2) unionId → 企业内 userid
  const appRes = await fetch(`${cfg.apiBase}/v1.0/oauth2/accessToken`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ appKey: cfg.appKey, appSecret: cfg.appSecret })
  })
  if (!appRes.ok) throw new Error(`钉钉企业 token 获取失败(HTTP ${appRes.status})`)
  const app = (await appRes.json()) as { accessToken?: string }
  if (!app.accessToken) throw new Error('钉钉企业 token 响应异常')

  const mapRes = await fetch(`${cfg.oapiBase}/topapi/user/getbyunionid?access_token=${encodeURIComponent(app.accessToken)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ unionid: me.unionId })
  })
  if (!mapRes.ok) throw new Error(`钉钉 unionId 映射失败(HTTP ${mapRes.status})`)
  const mapped = (await mapRes.json()) as { result?: { userid?: string }; errcode?: number; errmsg?: string }
  const userid = mapped.result?.userid
  if (!userid) throw new Error(`钉钉账号未关联企业员工(unionId=${me.unionId})`)

  // 2.5) 员工详情: 取工号(job_number, 用于 LDAP uid 匹配) 与姓名/手机/邮箱(可空,失败不阻断)
  let jobNumber: string | undefined
  let name: string | undefined = me.nick
  let mobile: string | undefined = me.mobile
  let email: string | undefined
  try {
    const detailRes = await fetch(`${cfg.oapiBase}/topapi/v2/user/get?access_token=${encodeURIComponent(app.accessToken)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userid })
    })
    if (detailRes.ok) {
      const detail = (await detailRes.json()) as {
        result?: { job_number?: string; name?: string; mobile?: string; email?: string; org_email?: string }
      }
      const r = detail.result
      jobNumber = r?.job_number?.trim() || undefined
      name = r?.name || name
      mobile = r?.mobile || mobile
      email = (r?.org_email || r?.email || undefined)?.trim().toLowerCase() || undefined
    }
  } catch {
    // 员工详情可选,失败不阻断(仍可走钉钉号匹配)
  }

  return { userid, name, mobile, email, jobNumber }
}
