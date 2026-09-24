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
  const utRes = await fetch(`${cfg.apiBase}/v1.0/oauth2/userAccessToken`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: cfg.appKey,
      client_secret: cfg.appSecret,
      code: authCode,
      grant_type: 'authorization_code'
    })
  })
  if (!utRes.ok) throw new Error(`钉钉 userAccessToken 获取失败(HTTP ${utRes.status})`)
  const ut = (await utRes.json()) as { accessToken?: string; unionId?: string }
  if (!ut.accessToken || !ut.unionId) throw new Error('钉钉 userAccessToken 响应异常')

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
    body: JSON.stringify({ unionid: ut.unionId })
  })
  if (!mapRes.ok) throw new Error(`钉钉 unionId 映射失败(HTTP ${mapRes.status})`)
  const mapped = (await mapRes.json()) as { result?: { userid?: string }; errcode?: number; errmsg?: string }
  const userid = mapped.result?.userid
  if (!userid) throw new Error(`钉钉账号未关联企业员工(unionId=${ut.unionId})`)

  // 3) 联系人信息(姓名/手机号,辅助展示;目录为准)
  let name: string | undefined
  let mobile: string | undefined
  try {
    const contactRes = await fetch(`${cfg.apiBase}/v1.0/contact/users/${encodeURIComponent(ut.unionId)}`, {
      headers: { 'x-acs-dingtalk-access-token': app.accessToken }
    })
    if (contactRes.ok) {
      const contact = (await contactRes.json()) as { name?: string; mobile?: string }
      name = contact.name
      mobile = contact.mobile
    }
  } catch {
    // 联系人信息可选,失败不阻断
  }

  return { userid, name, mobile }
}
