import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { decodeProtectedHeader, jwtVerify, SignJWT, type JWTPayload } from 'jose'
import { config } from './config.ts'
import { getClient, expandRoles, refreshTtlHours } from './clients.ts'
import { audit } from './audit.ts'
import { rateLimit } from './ratelimit.ts'
import { getSigningKey, getPublicJwks, getPublicKeyFor, keyRing } from './keys.ts'
import {
  createSession, getSession, destroySession, destroySessionsForSub,
  putTx, takeTx, finishTx, issueCode, consumeCode,
  issueRefreshToken, consumeRefreshToken, revokeRefreshTokens,
  type PendingTx, type SsoSession
} from './store.ts'
import { createDirectory } from './directory.ts'
import { createPasswordVerifier } from './password.ts'
import { buildScanUrl, newDingtalkState, exchangeIdentity } from './dingtalk.ts'
import { config as cfgAll } from './config.ts'
import { homePage, loginPage, messagePage, profilePage } from './render.ts'
import { issueCsrf, verifyCsrf } from './csrf.ts'

const directory = createDirectory()
const verifier = createPasswordVerifier()

/** 钉钉 state → 登录事务(防回调伪造) */
const dingtalkStates = new Map<string, { txId: string; created_at: number }>()

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  if (!header) return out
  for (const part of header.split(';')) {
    const i = part.indexOf('=')
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim())
  }
  return out
}

function redirect(res: import('node:http').ServerResponse, location: string): void {
  res.writeHead(302, { Location: location })
  res.end()
}

function html(res: import('node:http').ServerResponse, status: number, body: string): void {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' })
  res.end(body)
}

function json(res: import('node:http').ServerResponse, status: number, payload: unknown, headers?: Record<string, string>): void {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers })
  res.end(JSON.stringify(payload))
}

async function readBody(req: import('node:http').IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []
  for await (const c of req) chunks.push(c as Buffer)
  return Buffer.concat(chunks)
}

function formToObject(body: Buffer): Record<string, string> {
  return Object.fromEntries(new URLSearchParams(body.toString('utf-8')))
}

function clientIp(req: import('node:http').IncomingMessage): string {
  return req.socket.remoteAddress ?? 'unknown'
}

// ---- discovery / jwks ----

export async function handleDiscovery(res: import('node:http').ServerResponse): Promise<void> {
  const iss = config.issuer
  json(res, 200, {
    issuer: iss,
    authorization_endpoint: `${iss}/authorize`,
    token_endpoint: `${iss}/token`,
    userinfo_endpoint: `${iss}/userinfo`,
    jwks_uri: `${iss}/.well-known/jwks.json`,
    end_session_endpoint: `${iss}/logout`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:token-exchange'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['openid', 'profile'],
    claims_supported: ['sub', 'name', 'dept', 'roles', 'dingtalk']
  })
}

export async function handleJwks(res: import('node:http').ServerResponse): Promise<void> {
  // 仅在密钥环为空时生成(空目录首次启动的自愈,避免发布空 JWKS 被客户端缓存 300 秒);
  // rotate 进行中旧 key 已降级但指针尚未切换时环内仍有钥匙,不会被误判为空而多生成一把
  if (getPublicJwks().keys.length === 0) await keyRing().ensureActive()
  json(res, 200, getPublicJwks())
}

// ---- authorize ----

export async function handleAuthorize(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, url: URL): Promise<void> {
  const ip = clientIp(req)
  if (!rateLimit(`authorize:${ip}`, 60, 60_000)) {
    return html(res, 429, messagePage('请求过于频繁', '请稍后再试', false))
  }
  const q = url.searchParams
  const client = getClient(q.get('client_id'))
  const redirectUri = q.get('redirect_uri') ?? ''
  if (!client || !client.redirect_uris.includes(redirectUri)) {
    return html(res, 400, messagePage('无效的接入方', 'client_id 或 redirect_uri 未注册', false))
  }
  if (q.get('response_type') !== 'code') {
    return html(res, 400, messagePage('不支持的反应类型', '仅支持 response_type=code', false))
  }
  const scope = q.get('scope') ?? ''
  if (!scope.split(' ').includes('openid')) {
    return html(res, 400, messagePage('缺少 scope', '必须包含 openid', false))
  }

  const tx: PendingTx = {
    id: randomBytes(16).toString('hex'),
    client_id: client.client_id,
    redirect_uri: redirectUri,
    scope,
    state: q.get('state') ?? undefined,
    nonce: q.get('nonce') ?? undefined,
    code_challenge: q.get('code_challenge') ?? undefined,
    created_at: Date.now()
  }
  if (tx.code_challenge && q.get('code_challenge_method') !== 'S256') {
    return html(res, 400, messagePage('不支持的 PKCE 方法', '仅支持 S256', false))
  }
  putTx(tx)

  // 已有 SSO 会话 → 直接发 code(单点登录的落点)
  const cookies = parseCookies(req.headers.cookie)
  const session = getSession(cookies['sso_sid'])
  if (session) {
    return issueCodeRedirect(res, tx, session)
  }
  redirect(res, `/login?tx=${tx.id}&tab=qr`)
}

function issueCodeRedirect(res: import('node:http').ServerResponse, tx: PendingTx, session: SsoSession): void {
  const code = issueCode(tx, session)
  const params = new URLSearchParams({ code, ...(tx.state ? { state: tx.state } : {}) })
  // 认证完成的同一响应下发会话 Cookie(单点登录凭据)
  res.setHeader('Set-Cookie', [
    `sso_sid=${session.sid}; ${sessionCookieAttrs()}; Max-Age=${Math.floor(config.sessionTtlMs / 1000)}`
  ])
  redirect(res, `${tx.redirect_uri}${tx.redirect_uri.includes('?') ? '&' : '?'}${params.toString()}`)
}

// ---- 首页 ----

/** GET /:直接访问 sso 域名时的落地页(避免裸 404);有会话则给账号设置入口 */
export async function handleHome(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse): Promise<void> {
  const cookies = parseCookies(req.headers.cookie)
  const session = getSession(cookies['sso_sid'])
  html(res, 200, homePage({
    signedIn: !!session,
    name: session?.name,
    sub: session?.sub
  }))
}

// ---- 登录页与双通道 ----

export async function handleLoginPage(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, url: URL): Promise<void> {
  const txId = url.searchParams.get('tx') ?? ''
  const tx = takeTx(txId)
  if (!tx) {
    return html(res, 400, messagePage('登录事务已过期', '请返回应用重新发起登录', false))
  }
  const client = getClient(tx.client_id)
  const qrEnabled = cfgAll.dingtalkConfigured
  const tab = url.searchParams.get('tab') === 'pwd' || !qrEnabled ? 'pwd' : 'qr'
  const error = url.searchParams.get('error') ?? undefined
  html(res, 200, loginPage({ txId, tab, clientName: client?.name, error, dingtalkEnabled: qrEnabled, csrf: issueCsrf(txId) }))
}

export async function handlePasswordLogin(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, url: URL): Promise<void> {
  const ip = clientIp(req)
  if (!rateLimit(`pwd:${ip}`, 10, 60_000)) {
    return html(res, 429, messagePage('尝试过于频繁', '请 1 分钟后再试', false))
  }
  const form = formToObject(await readBody(req))
  const txId = form.tx ?? ''
  const tx = takeTx(txId)
  if (!tx) {
    return html(res, 400, messagePage('登录事务已过期', '请返回应用重新发起登录', false))
  }
  // CSRF 先于凭据校验:token 与本次登录事务 tx 绑定
  if (!verifyCsrf(txId, form.csrf)) {
    return html(res, 400, messagePage('登录已过期', '页面已过期,请重新打开登录页', false))
  }
  const client = getClient(tx.client_id)
  const username = (form.username ?? '').trim()
  const password = form.password ?? ''

  const user = await verifier.verify(username, password)
  if (!user || user.status !== 'active') {
    audit({ event: 'login_password', ok: false, sub: user?.sub, ip, detail: user ? '账号已禁用' : '凭据错误' })
    const err = encodeURIComponent(user ? '账号已被禁用,请联系管理员' : '工号/手机号或密码不正确')
    return redirect(res, `/login?tx=${txId}&tab=pwd&error=${err}`)
  }

  audit({ event: 'login_password', ok: true, sub: user.sub, client_id: tx.client_id, ip })
  const session = createSession(user.sub, user.name, user.dept, 'pwd', user.dingtalkUserId, user.email)
  finishTx(txId)
  issueCodeRedirect(res, tx, session)
}

export async function handleDingtalkStart(res: import('node:http').ServerResponse, url: URL): Promise<void> {
  if (!cfgAll.dingtalkConfigured) {
    return html(res, 400, messagePage('钉钉扫码未配置', '管理员尚未配置 DINGTALK_APP_KEY/SECRET,请使用账号密码登录', false))
  }
  const txId = url.searchParams.get('tx') ?? ''
  const tx = takeTx(txId)
  if (!tx) {
    return html(res, 400, messagePage('登录事务已过期', '请返回应用重新发起登录', false))
  }
  const state = newDingtalkState()
  dingtalkStates.set(state, { txId, created_at: Date.now() })
  redirect(res, buildScanUrl(state))
}

export async function handleDingtalkCallback(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, url: URL): Promise<void> {
  const ip = clientIp(req)
  if (!rateLimit(`qr:${ip}`, 20, 60_000)) {
    return html(res, 429, messagePage('请求过于频繁', '请稍后再试', false))
  }
  const state = url.searchParams.get('state') ?? ''
  const authCode = url.searchParams.get('authCode') ?? url.searchParams.get('code') ?? ''
  const bound = dingtalkStates.get(state)
  dingtalkStates.delete(state)
  if (!bound || Date.now() - bound.created_at > config.txTtlMs) {
    return html(res, 400, messagePage('扫码状态已过期', '请返回应用重新发起登录', false))
  }
  const tx = takeTx(bound.txId)
  if (!tx) {
    return html(res, 400, messagePage('登录事务已过期', '请返回应用重新发起登录', false))
  }

  try {
    const identity = await exchangeIdentity(authCode)
    const user = await directory.findByDingtalkUserId(identity.userid)
    if (!user) {
      audit({ event: 'login_qr', ok: false, ip, detail: `目录中无此钉钉账号(userid=${identity.userid})` })
      return html(res, 403, messagePage('未找到对应员工', '你的钉钉账号未同步到公司目录,请联系管理员', false))
    }
    if (user.status !== 'active') {
      audit({ event: 'login_qr', ok: false, sub: user.sub, ip, detail: '账号已禁用' })
      return html(res, 403, messagePage('账号已禁用', '该账号已离职或被停用,如属误判请联系管理员', false))
    }
    audit({ event: 'login_qr', ok: true, sub: user.sub, client_id: tx.client_id, ip })
    const session = createSession(user.sub, user.name, user.dept, 'qr', user.dingtalkUserId, user.email)
    finishTx(tx.id)
    issueCodeRedirect(res, tx, session)
  } catch (err) {
    audit({ event: 'login_qr', ok: false, ip, detail: (err as Error).message })
    html(res, 502, messagePage('钉钉认证失败', (err as Error).message, false))
  }
}

// ---- token ----

export async function handleToken(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse): Promise<void> {
  const ip = clientIp(req)
  if (!rateLimit(`token:${ip}`, 60, 60_000)) {
    return json(res, 429, { error: 'slow_down' })
  }
  const raw = await readBody(req)
  const form = new URLSearchParams(raw.toString('utf-8'))

  // 客户端认证:Basic 或 form
  let clientId = form.get('client_id') ?? ''
  let clientSecret = form.get('client_secret') ?? ''
  const basic = req.headers.authorization
  if (basic?.startsWith('Basic ')) {
    const decoded = Buffer.from(basic.slice(6), 'base64').toString('utf-8')
    const i = decoded.indexOf(':')
    clientId = decodeURIComponent(decoded.slice(0, i))
    clientSecret = decodeURIComponent(decoded.slice(i + 1))
  }
  const client = getClient(clientId)
  if (!client || !clientSecret || !safeEqual(client.client_secret, clientSecret)) {
    audit({ event: 'token', ok: false, ip, detail: '客户端认证失败' })
    return json(res, 401, { error: 'invalid_client' })
  }

  // token-exchange grant(RFC 8693):把本客户端自己的 token 换成目标受众的短期 token
  if (form.get('grant_type') === 'urn:ietf:params:oauth:grant-type:token-exchange') {
    // subject_token_type 仅作协议兼容,不校验(id_token/access_token 均接受)
    const subjectToken = form.get('subject_token') ?? ''
    const audience = (form.get('audience') ?? '').trim()
    const allowed = Array.isArray(client.allowed_audiences) ? client.allowed_audiences : []
    if (!subjectToken || !audience) {
      audit({ event: 'token_exchange', ok: false, client_id: clientId, ip, detail: '缺少 subject_token 或 audience' })
      return json(res, 400, { error: 'invalid_request', error_description: '缺少 subject_token 或 audience' })
    }
    if (!allowed.includes(audience)) {
      audit({ event: 'token_exchange', ok: false, client_id: clientId, ip, detail: JSON.stringify({ audience, reason: '未授权' }) })
      return json(res, 400, { error: 'invalid_target' })
    }

    let payload: JWTPayload
    try {
      const header = decodeProtectedHeader(subjectToken)
      const pub = getPublicKeyFor(header.kid)
      if (!pub) throw new Error('unknown kid')
      const verified = await jwtVerify(subjectToken, pub, { issuer: config.issuer, algorithms: ['RS256'] })
      payload = verified.payload
    } catch {
      audit({ event: 'token_exchange', ok: false, client_id: clientId, ip, detail: 'subject_token 无效/过期' })
      return json(res, 400, { error: 'invalid_grant', error_description: 'subject_token 无效或已过期' })
    }
    if (payload.aud !== clientId || !payload.sub) {
      audit({ event: 'token_exchange', ok: false, client_id: clientId, ip, detail: 'subject_token 受众不符' })
      return json(res, 400, { error: 'invalid_grant', error_description: 'subject_token 受众与客户端不符' })
    }

    const ttl = config.exchangeTtlSeconds
    const now = Math.floor(Date.now() / 1000)
    const { privateKey, kid } = await getSigningKey()
    const accessToken = await new SignJWT({
      scope: 'openid profile',
      dept: payload.dept,
      roles: payload.roles,
      name: payload.name,
      ...(payload.email ? { email: payload.email } : {}),
      ...(payload.dingtalk ? { dingtalk: payload.dingtalk } : {}),
      act: clientId
    })
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuer(config.issuer)
      .setSubject(payload.sub)
      .setAudience(audience)
      .setIssuedAt(now)
      .setExpirationTime(now + ttl)
      .sign(privateKey)

    audit({ event: 'token_exchange', ok: true, sub: payload.sub, client_id: clientId, ip, detail: JSON.stringify({ audience }) })
    return json(res, 200, {
      access_token: accessToken,
      issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      token_type: 'Bearer',
      expires_in: ttl,
      scope: 'openid profile'
    })
  }

  // refresh_token grant:校验并轮换,签发新 token 组
  if (form.get('grant_type') === 'refresh_token') {
    const old = consumeRefreshToken(form.get('refresh_token') ?? '', clientId)
    if (!old) {
      audit({ event: 'token_refresh', ok: false, client_id: clientId, ip, detail: 'refresh_token 无效/过期/客户端不匹配' })
      return json(res, 400, { error: 'invalid_grant', error_description: 'refresh_token 无效或已过期' })
    }
    const refreshTtlMs = refreshTtlHours(client) * 3_600_000
    // 轮换必须沿用首次授权时间,绝对会话上限不因刷新而延长
    const newRefresh = issueRefreshToken(old.sub, old.name, old.dept, clientId, old.dingtalkUserId, refreshTtlMs, old.authTime, old.email)
    const now = Math.floor(Date.now() / 1000)
    const { privateKey, kid } = await getSigningKey()
    const roles = expandRoles(client, old.dept)
    const accessToken = await new SignJWT({ scope: 'openid profile', dept: old.dept, roles, name: old.name, ...dingtalkClaim(old.dingtalkUserId), ...(old.email ? { email: old.email } : {}) })
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuer(config.issuer)
      .setSubject(old.sub)
      .setAudience(clientId)
      .setIssuedAt(now)
      .setExpirationTime(now + config.accessTokenTtlSeconds)
      .sign(privateKey)
    const idToken = await new SignJWT({ name: old.name, dept: old.dept, roles, ...dingtalkClaim(old.dingtalkUserId), ...(old.email ? { email: old.email } : {}) })
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuer(config.issuer)
      .setSubject(old.sub)
      .setAudience(clientId)
      .setIssuedAt(now)
      .setExpirationTime(now + config.idTokenTtlSeconds)
      .sign(privateKey)
    audit({ event: 'token_refresh', ok: true, sub: old.sub, client_id: clientId, ip })
    return json(res, 200, {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: config.accessTokenTtlSeconds,
      id_token: idToken,
      refresh_token: newRefresh,
      scope: 'openid profile'
    })
  }

  const codeRecord = consumeCode(form.get('code') ?? '')
  if (!codeRecord) {
    return json(res, 400, { error: 'invalid_grant', error_description: '授权码无效或已使用' })
  }
  if (codeRecord.client_id !== clientId || codeRecord.redirect_uri !== (form.get('redirect_uri') ?? '')) {
    return json(res, 400, { error: 'invalid_grant', error_description: '授权码与请求不匹配' })
  }

  // PKCE 校验
  if (codeRecord.code_challenge) {
    const verifierValue = form.get('code_verifier') ?? ''
    const digest = createHash('sha256').update(verifierValue).digest('base64url')
    if (process.env.SSO_DEBUG) {
      console.log(`[debug] pkce received=${digest} stored=${codeRecord.code_challenge} verifierLen=${verifierValue.length}`)
    }
    if (!safeEqual(codeRecord.code_challenge, digest)) {
      return json(res, 400, { error: 'invalid_grant', error_description: 'PKCE 校验失败' })
    }
  }

  const roles = expandRoles(client, codeRecord.dept)
  const now = Math.floor(Date.now() / 1000)
  const { privateKey, kid } = await getSigningKey()

  const idToken = await new SignJWT({ name: codeRecord.name, dept: codeRecord.dept, roles, ...dingtalkClaim(codeRecord.dingtalkUserId), ...(codeRecord.email ? { email: codeRecord.email } : {}), ...(codeRecord.nonce ? { nonce: codeRecord.nonce } : {}) })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuer(config.issuer)
    .setSubject(codeRecord.sub)
    .setAudience(clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + config.idTokenTtlSeconds)
    .sign(privateKey)

  const accessToken = await new SignJWT({ scope: 'openid profile', dept: codeRecord.dept, roles, name: codeRecord.name, ...dingtalkClaim(codeRecord.dingtalkUserId), ...(codeRecord.email ? { email: codeRecord.email } : {}) })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuer(config.issuer)
    .setSubject(codeRecord.sub)
    .setAudience(clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + config.accessTokenTtlSeconds)
    .sign(privateKey)

  const refreshTtlMs = refreshTtlHours(client) * 3_600_000
  const authTime = Date.now()
  const refreshToken = issueRefreshToken(codeRecord.sub, codeRecord.name, codeRecord.dept, clientId, codeRecord.dingtalkUserId, refreshTtlMs, authTime, codeRecord.email)
  audit({ event: 'token', ok: true, sub: codeRecord.sub, client_id: clientId, ip })
  json(res, 200, {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: config.accessTokenTtlSeconds,
    id_token: idToken,
    refresh_token: refreshToken,
    scope: 'openid profile'
  })
}

export async function handleUserinfo(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse): Promise<void> {
  const auth = req.headers.authorization ?? ''
  if (process.env.SSO_DEBUG) console.log(`[debug] userinfo entered, auth=${auth ? auth.slice(0, 20) + '...' : 'EMPTY'}, method=${req.method}`)
  if (!auth.startsWith('Bearer ')) {
    return json(res, 401, { error: 'invalid_token' })
  }
  try {
    const header = decodeProtectedHeader(auth.slice(7))
    const pub = getPublicKeyFor(header.kid)
    if (!pub) return json(res, 401, { error: 'invalid_token' })
    const { payload } = await jwtVerify(auth.slice(7), pub, { issuer: config.issuer, algorithms: ['RS256'] })
    const claims: Record<string, unknown> = { sub: payload.sub, name: payload.name, dept: payload.dept, roles: payload.roles, ...(payload.email ? { email: payload.email } : {}) }
    if (payload.dingtalk) claims.dingtalk = payload.dingtalk
    json(res, 200, claims)
  } catch (err) {
    if (process.env.SSO_DEBUG) console.log('[debug] userinfo verify error:', (err as Error).message)
    json(res, 401, { error: 'invalid_token' })
  }
}

// ---- 登出 ----

export async function handleLogout(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, url: URL): Promise<void> {
  const cookies = parseCookies(req.headers.cookie)
  const session = getSession(cookies['sso_sid'])
  destroySession(cookies['sso_sid'])
  if (session) revokeRefreshTokens(session.sub)
  const clientId = url.searchParams.get('client_id') ?? ''
  const postLogout = url.searchParams.get('post_logout_redirect_uri') ?? ''
  const client = getClient(clientId)
  let target: string | null = null
  if (client && postLogout && (client.post_logout_redirect_uris ?? []).includes(postLogout)) {
    target = postLogout
  }
  res.setHeader('Set-Cookie', clearCookie())
  audit({ event: 'logout', ok: true, client_id: clientId || undefined })
  if (target) return redirect(res, target)
  html(res, 200, messagePage('已退出登录', '你已退出统一身份,可关闭本页面', true))
}

// ---- 账号设置(密码激活/修改) ----

export async function handleProfile(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, error?: string, success?: string): Promise<void> {
  const cookies = parseCookies(req.headers.cookie)
  const session = getSession(cookies['sso_sid'])
  if (!session) {
    return html(res, 401, messagePage('请先登录', '设置密码前请先通过扫码或密码登录', false))
  }
  const needCurrent = !(session.authMode === 'qr' && Date.now() - session.createdAt < 10 * 60_000)
  html(res, 200, profilePage({ sub: session.sub, name: session.name, dept: session.dept, needCurrent, error, success, csrf: issueCsrf(session.sid) }))
}

export async function handleProfilePassword(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse): Promise<void> {
  const cookies = parseCookies(req.headers.cookie)
  const session = getSession(cookies['sso_sid'])
  if (!session) {
    return html(res, 401, messagePage('请先登录', '设置密码前请先登录', false))
  }
  const form = formToObject(await readBody(req))
  const newPassword = form.new_password ?? ''
  const confirm = form.confirm ?? ''
  const needCurrent = !(session.authMode === 'qr' && Date.now() - session.createdAt < 10 * 60_000)
  const current = needCurrent ? (form.current_password ?? null) : null

  const back = (error: string) => handleProfile(req, res, error)
  // CSRF token 与当前会话 sid 绑定(与 profilePage 渲染时一致)
  if (!verifyCsrf(session.sid, form.csrf)) return back('页面已过期,请重新打开登录页')
  if (newPassword.length < 8) return back('新密码至少 8 位')
  if (newPassword !== confirm) return back('两次输入的新密码不一致')

  try {
    const user = await directory.findByIdentifier(session.sub)
    if (!user) throw new Error('目录中不存在该用户')
    // 扫码 10 分钟内的会话可免当前密码(激活场景);改密必须提供当前密码
    await verifier.setPassword(user, needCurrent ? current : null, newPassword)
    // 改密后立即吊销该用户全部 refresh token 与其它端的 SSO 会话(保留当前会话),
    // 其它端最迟在本端 access token TTL(默认 10 分钟)内失效;当前端不受影响
    revokeRefreshTokens(session.sub)
    destroySessionsForSub(session.sub, session.sid)
    audit({ event: 'password_set', ok: true, sub: session.sub })
    handleProfile(req, res, undefined, '密码已保存,可用于"账号密码"登录')
  } catch (err) {
    audit({ event: 'password_set', ok: false, sub: session.sub, detail: (err as Error).message })
    back((err as Error).message)
  }
}

// ---- 工具 ----

/** 仅当目录登记了钉钉号才下发 dingtalk claim(空值/缺失时不出现该 claim,保持向后兼容) */
function dingtalkClaim(dingtalkUserId?: string): Record<string, string> {
  return dingtalkUserId ? { dingtalk: dingtalkUserId } : {}
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf-8')
  const bb = Buffer.from(b, 'utf-8')
  if (ab.length !== bb.length) return false
  return timingSafeEqual(ab, bb)
}

/** https issuer 下会话 cookie 追加 Secure;本地 http 开发不加(否则浏览器不发送)。 */
function sessionCookieAttrs(): string {
  const secure = config.issuer.startsWith('https://') ? '; Secure' : ''
  return `Path=/; HttpOnly; SameSite=Lax${secure}`
}

function clearCookie(): string {
  return `sso_sid=; ${sessionCookieAttrs()}; Max-Age=0`
}
