/**
 * SSO 全流程烟测:
 *   启动 mock 钉钉 + SSO(文件目录),用 openid-client 标准客户端库走完整 OIDC 流程。
 * 覆盖:discovery/JWKS、扫码登录、密码登录、错误凭据、禁用账号拒绝、code 一次性、
 *       会话确认页(continue/switch/prompt=login)、密码激活、登出、客户端认证失败。
 */
import { spawn } from 'node:child_process'
import { rmSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs'
import { scryptSync, randomBytes } from 'node:crypto'
import * as oidc from 'openid-client'
import { jwtVerify, createRemoteJWKSet, decodeJwt } from 'jose'

const SSO_PORT = 18091
const SSO_TTL_PORT = 18092
const MOCK_PORT = 19080
const SSO = `http://127.0.0.1:${SSO_PORT}`
const REDIRECT_URI = 'http://127.0.0.1:19990/cb'

let passed = 0
let failed = 0
function assert(name, cond) {
  if (cond) {
    passed++
    console.log(`PASS | ${name}`)
  } else {
    failed++
    console.log(`FAIL | ${name}`)
  }
}

// ---- 测试数据 ----
function hashPassword(password) {
  const salt = randomBytes(16)
  const hash = scryptSync(password, salt, 32)
  return `scrypt:${salt.toString('hex')}:${hash.toString('hex')}`
}

function setupFixtures() {
  rmSync(new URL('./data', import.meta.url), { recursive: true, force: true })
  rmSync(new URL('./keys', import.meta.url), { recursive: true, force: true })
  mkdirSync(new URL('./data', import.meta.url), { recursive: true })
  const users = [
    { sub: '10001', name: '张三', dept: '平台组', mobile: '13800000001', email: 'zhangsan@xzrobot.com', dingtalkUserId: '10001', status: 'active', passwordHash: hashPassword('pass123') },
    { sub: '10002', name: '李四', dept: '业务组', mobile: '13800000002', dingtalkUserId: '10002', status: 'disabled' },
    { sub: '10003', name: '王五', dept: '平台组', mobile: '13800000003', dingtalkUserId: '10003', status: 'active' },
    // 无钉钉号的用户:验证 dingtalk claim 空值时不下发
    { sub: '10004', name: '赵六', dept: '平台组', mobile: '13800000004', dingtalkUserId: '', status: 'active', passwordHash: hashPassword('pass456') }
  ]
  writeFileSync(new URL('./data/users.json', import.meta.url), JSON.stringify(users, null, 2))
}

// ---- 简易 Cookie Jar ----
class Jar {
  constructor() {
    this.cookies = new Map()
  }

  absorb(res) {
    const setCookies = res.headers.getSetCookie?.() ?? []
    for (const c of setCookies) {
      const [pair] = c.split(';')
      const i = pair.indexOf('=')
      const name = pair.slice(0, i).trim()
      const value = pair.slice(i + 1).trim()
      if (value === '') this.cookies.delete(name)
      else this.cookies.set(name, value)
    }
  }

  header() {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join('; ')
  }
}

function ssoFetch(jar, url, opts = {}) {
  const headers = { ...(opts.headers ?? {}) }
  const cookie = jar.header()
  if (cookie) headers.Cookie = cookie
  return fetch(url, { ...opts, headers, redirect: 'manual' })
}

/** 从登录页/改密页 HTML 提取与当前 tx 或 sid 绑定的 CSRF token */
function extractCsrf(html) {
  const m = html.match(/name="csrf" value="([^"]+)"/)
  return m ? m[1] : ''
}

/** 解出 JWT payload、按 patch 修改后 base64url 重编码并拼回(不重签名):构造结构合法但验签必失败的篡改样本 */
function tamperJwtPayload(token, patch) {
  const [header, payload, signature] = token.split('.')
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8'))
  return [header, Buffer.from(JSON.stringify({ ...claims, ...patch }), 'utf-8').toString('base64url'), signature].join('.')
}

/** 取密码登录页并解析其 tx 绑定的 CSRF token */
async function csrfForLogin(jar, base, tx) {
  return extractCsrf(await (await ssoFetch(jar, `${base}/login?tx=${tx}&tab=pwd`)).text())
}

function spawnAndWait(cmd, args, env, healthUrl) {
  const child = spawn(cmd, args, { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] })
  child.stdout.on('data', (d) => process.stdout.write(`[child] ${d}`))
  child.stderr.on('data', (d) => process.stderr.write(`[child:err] ${d}`))
  return child
}

async function waitHealth(url, tries = 50) {
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(url)
      if (res.ok) return true
    } catch {}
    await new Promise((r) => setTimeout(r, 300))
  }
  return false
}

/** 走一遍密码通道(authorize → login/password → token),返回 /token 响应体;用于第二实例的 TTL 覆盖验证与 token-exchange 用例 */
async function passwordCodeGrant(base, username, password, clientId = 'test-web', clientSecret = 'test-secret', redirectUri = REDIRECT_URI) {
  const jar = new Jar()
  const authUrl = `${base}/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid&state=ttl&nonce=ttl`
  const rAuth = await ssoFetch(jar, authUrl, { redirect: 'manual' })
  const tx = new URL(rAuth.headers.get('location'), base).searchParams.get('tx')
  const csrf = await csrfForLogin(jar, base, tx)
  const rLogin = await ssoFetch(jar, `${base}/login/password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `tx=${tx}&username=${username}&password=${password}&csrf=${csrf}`,
    redirect: 'manual'
  })
  const code = new URL(rLogin.headers.get('location'), base).searchParams.get('code')
  const res = await fetch(`${base}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: clientId, client_secret: clientSecret })
  })
  return res.json()
}

/** 完整密码登录:返回独立 Jar、其 sso_sid 与授权码换取的 token 组 */
async function passwordLogin(configuration, username, password, state) {
  const jar = new Jar()
  const verifier = oidc.randomPKCECodeVerifier()
  const authUrl = oidc.buildAuthorizationUrl(configuration, {
    redirect_uri: REDIRECT_URI, scope: 'openid', state, nonce: state,
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256'
  })
  const rAuth = await ssoFetch(jar, authUrl, { redirect: 'manual' })
  const tx = new URL(rAuth.headers.get('location'), SSO).searchParams.get('tx')
  const csrf = await csrfForLogin(jar, SSO, tx)
  const rLogin = await ssoFetch(jar, `${SSO}/login/password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `tx=${tx}&username=${username}&password=${password}&csrf=${csrf}`,
    redirect: 'manual'
  })
  jar.absorb(rLogin)
  const cb = rLogin.headers.get('location') ?? ''
  const grant = await oidc.authorizationCodeGrant(configuration, new URL(cb), {
    expectedState: state, expectedNonce: state, pkceCodeVerifier: verifier
  })
  return { jar, sid: jar.cookies.get('sso_sid') ?? '', grant }
}

/** 用给定 sso_sid 走 /authorize,返回状态码、Location 与响应体 */
async function authorizeWithSid(configuration, sid, state) {
  const authUrl = oidc.buildAuthorizationUrl(configuration, {
    redirect_uri: REDIRECT_URI, scope: 'openid', state, nonce: state
  })
  const res = await fetch(authUrl, { headers: { Cookie: `sso_sid=${sid}` }, redirect: 'manual' })
  return { status: res.status, location: res.headers.get('location') ?? '', body: await res.text() }
}

// ---- 主流程 ----
async function main() {
  setupFixtures()

  const mock = spawnAndWait('node', ['test/mock-dingtalk.mjs'], { MOCK_DINGTALK_PORT: String(MOCK_PORT) })
  const sso = spawnAndWait('node', ['--experimental-strip-types', 'src/index.ts'], {
    SSO_PORT: String(SSO_PORT),
    SSO_ISSUER: SSO,
    SSO_DATA_DIR: 'test/data',
    SSO_KEYS_DIR: 'test/keys',
    SSO_CLIENTS_PATH: 'test/fixtures/clients.json',
    FILE_USERS_PATH: 'test/data/users.json',
    DINGTALK_APP_KEY: 'test-app-key',
    DINGTALK_APP_SECRET: 'test-app-secret',
    DINGTALK_API_BASE: `http://127.0.0.1:${MOCK_PORT}`,
    DINGTALK_OAPI_BASE: `http://127.0.0.1:${MOCK_PORT}`,
    DINGTALK_LOGIN_BASE: `http://127.0.0.1:${MOCK_PORT}/login`,
    SSO_DINGTALK_REDIRECT_URI: `${SSO}/dingtalk/callback`
  })

  try {
    assert('服务健康检查', await waitHealth(`${SSO}/healthz`))

    // T1 discovery + jwks
    const configuration = await oidc.discovery(new URL(SSO), 'test-web', 'test-secret', undefined, {
      execute: [oidc.allowInsecureRequests]
    })
    assert('discovery 发现端点', true)
    const jwks = await (await fetch(`${SSO}/.well-known/jwks.json`)).json()
    assert('JWKS 公钥集可用', Array.isArray(jwks.keys) && jwks.keys.length === 1)
    const discoveryMeta = await (await fetch(`${SSO}/.well-known/openid-configuration`)).json()
    assert('discovery 声明 token-exchange grant', (discoveryMeta.grant_types_supported ?? []).includes('urn:ietf:params:oauth:grant-type:token-exchange'))

    // ---- 密码通道 ----
    const jar1 = new Jar()
    const verifier1 = oidc.randomPKCECodeVerifier()
    const challenge1 = await oidc.calculatePKCECodeChallenge(verifier1)
    const authUrl1 = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: REDIRECT_URI,
      scope: 'openid profile',
      state: 'st1',
      nonce: 'n1',
      code_challenge: challenge1,
      code_challenge_method: 'S256'
    })

    const r1 = await ssoFetch(jar1, authUrl1, { redirect: 'manual' })
    const loginLoc = r1.headers.get('location') ?? ''
    assert('未登录 → 跳转登录页', r1.status === 302 && loginLoc.startsWith('/login?tx='))
    const loginPage = await (await ssoFetch(jar1, new URL(loginLoc, SSO))).text()
    assert('登录页含扫码与密码双通道', loginPage.includes('钉钉扫码') && loginPage.includes('账号密码'))

    const tx = new URL(loginLoc, SSO).searchParams.get('tx')

    // 密码页必须携带与当前 tx 绑定的 CSRF 隐藏字段
    const pwdPage = await (await ssoFetch(jar1, `${SSO}/login?tx=${tx}&tab=pwd`)).text()
    assert('登录页含 CSRF 隐藏字段', pwdPage.includes('name="csrf"'))
    const csrf1 = extractCsrf(pwdPage)

    // 缺少 CSRF 的登录必须被拒(400),且不消耗登录事务
    const rNoCsrf = await ssoFetch(jar1, `${SSO}/login/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${tx}&username=10001&password=pass123`,
      redirect: 'manual'
    })
    assert('缺少 CSRF 的密码登录被拒(400 + 提示)', rNoCsrf.status === 400 && (await rNoCsrf.text()).includes('页面已过期,请重新打开登录页'))

    // 错误密码(带 CSRF)
    const rWrong = await ssoFetch(jar1, `${SSO}/login/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${tx}&username=10001&password=wrong-password&csrf=${csrf1}`,
      redirect: 'manual'
    })
    const wrongLoc = rWrong.headers.get('location') ?? ''
    assert('错误凭据 → 回登录页并提示', rWrong.status === 302 && wrongLoc.includes('error='))

    // 正确密码 → code
    const rOk = await ssoFetch(jar1, `${SSO}/login/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${tx}&username=10001&password=pass123&csrf=${csrf1}`,
      redirect: 'manual'
    })
    const cbUrl1 = rOk.headers.get('location') ?? ''
    assert('密码登录成功 → 携带 code 回调', rOk.status === 302 && cbUrl1.startsWith(REDIRECT_URI) && cbUrl1.includes('code='))
    assert('登录响应下发会话 Cookie', (rOk.headers.getSetCookie?.() ?? []).some((c) => c.startsWith('sso_sid=')))
    jar1.absorb(rOk)

    const grant1 = await oidc.authorizationCodeGrant(configuration, new URL(cbUrl1), {
      expectedState: 'st1',
      expectedNonce: 'n1',
      pkceCodeVerifier: verifier1
    })
    // id_token 手动验签:走 JWKS 远程公钥(端到端验证 /jwks 端点正确性)
    const JWKS = createRemoteJWKSet(new URL(`${SSO}/.well-known/jwks.json`))
    const { payload: claims1 } = await jwtVerify(grant1.id_token, JWKS, {
      issuer: SSO,
      audience: 'test-web',
      nonce: 'n1'
    })
    assert('id_token 验签通过且 sub/roles 正确', claims1.sub === '10001' && JSON.stringify(claims1.roles) === JSON.stringify(['admin']))
    assert('id_token 携带 dingtalk claim(目录有钉钉号)', claims1.dingtalk === '10001')

    const info = await oidc.fetchUserInfo(configuration, grant1.access_token, '10001')
    assert('userinfo 返回用户信息', info.sub === '10001' && info.name === '张三')
    assert('userinfo 返回 dingtalk', info.dingtalk === '10001')

    const { payload: atClaims1 } = await jwtVerify(grant1.access_token, JWKS, { issuer: SSO, audience: 'test-web' })
    assert('access_token 携带 dingtalk claim', atClaims1.dingtalk === '10001')

    // ---- TTL 断言:默认 access/id token 均为 600 秒,且与响应体 expires_in 一致 ----
    const atTtl1 = decodeJwt(grant1.access_token)
    const idTtl1 = decodeJwt(grant1.id_token)
    assert('access_token TTL 为 600 秒', atTtl1.exp - atTtl1.iat === 600)
    assert('id_token TTL 为 600 秒', idTtl1.exp - idTtl1.iat === 600)
    assert('授权码响应 expires_in 为 600', grant1.expires_in === 600)

    // ---- refresh token 流程 ----
    assert('授权码响应发放 refresh_token', typeof grant1.refresh_token === 'string' && grant1.refresh_token.length > 20)
    const rfRes = await fetch(`${SSO}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: grant1.refresh_token, client_id: 'test-web', client_secret: 'test-secret' })
    })
    const rfBody = await rfRes.json()
    assert('refresh grant 换新 access_token', rfRes.ok && !!rfBody.access_token)
    assert('refresh token 轮换(响应含新 refresh_token)', typeof rfBody.refresh_token === 'string' && rfBody.refresh_token !== grant1.refresh_token)
    const { jwtVerify: jv2, createRemoteJWKSet: crjs } = await import('jose')
    const JW2 = crjs(new URL(`${SSO}/.well-known/jwks.json`))
    const rfClaims = await jv2(rfBody.access_token, JW2, { issuer: SSO, audience: 'test-web' })
    assert('刷新后的 access_token 验签有效', rfClaims.payload.sub === '10001')
    assert('刷新后的 access_token 携带 dingtalk claim', rfClaims.payload.dingtalk === '10001')
    const rfAtTtl = decodeJwt(rfBody.access_token)
    const rfIdTtl = decodeJwt(rfBody.id_token)
    assert('refresh grant access_token TTL 为 600 秒', rfAtTtl.exp - rfAtTtl.iat === 600)
    assert('refresh grant id_token TTL 为 600 秒', rfIdTtl.exp - rfIdTtl.iat === 600)
    assert('refresh grant expires_in 为 600', rfBody.expires_in === 600)

    // ---- refresh token 绝对上限接线:expires_at 恒为 auth_time + 12h,轮换复用 auth_time ----
    const TTL_12H = 12 * 3_600_000
    const refreshRecordsFile = new URL('./data/refresh_tokens.json', import.meta.url)
    const readRefreshRecords = () => JSON.parse(readFileSync(refreshRecordsFile, 'utf-8'))
    const recsBefore = readRefreshRecords()
    assert('refresh 记录数恰为 1(仅前面授权码换取的 refresh)', recsBefore.length === 1)
    assert('授权码换取的 refresh 记录自洽:expires_at-auth_time 恰为 12h', recsBefore.length === 1 && recsBefore[0].expires_at - recsBefore[0].auth_time === TTL_12H)
    const authTimeBefore = recsBefore[0]?.auth_time
    const rfRes2 = await fetch(`${SSO}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rfBody.refresh_token, client_id: 'test-web', client_secret: 'test-secret' })
    })
    const rfBody2 = await rfRes2.json()
    assert('第二次 refresh 轮换成功', rfRes2.ok && typeof rfBody2.refresh_token === 'string' && rfBody2.refresh_token !== rfBody.refresh_token)
    const recsAfter = readRefreshRecords()
    assert('轮换后 refresh 记录数仍为 1', recsAfter.length === 1)
    assert('轮换沿用首次授权时间 auth_time(未被重置为当前时间)', recsAfter.length === 1 && recsAfter[0].auth_time === authTimeBefore)
    assert('轮换后记录自洽:expires_at-auth_time 仍恰为 12h', recsAfter.length === 1 && recsAfter[0].expires_at - recsAfter[0].auth_time === TTL_12H)

    const rfReuse = await fetch(`${SSO}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: grant1.refresh_token, client_id: 'test-web', client_secret: 'test-secret' })
    })
    assert('旧 refresh_token 轮换后作废(复用被拒)', rfReuse.status === 400)

    // code 一次性
    const reuseRes = await fetch(`${SSO}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=authorization_code&code=${new URL(cbUrl1).searchParams.get('code')}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&client_id=test-web&client_secret=test-secret`
    })
    assert('授权码一次性(code 复用被拒)', reuseRes.status === 400)

    // ---- 无钉钉号用户:签发的 token/userinfo 均不含 dingtalk claim ----
    const jarNo = new Jar()
    const vNo = oidc.randomPKCECodeVerifier()
    const auNo = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: REDIRECT_URI, scope: 'openid profile', state: 'sno', nonce: 'nno',
      code_challenge: await oidc.calculatePKCECodeChallenge(vNo), code_challenge_method: 'S256'
    })
    const rNo1 = await ssoFetch(jarNo, auNo, { redirect: 'manual' })
    const txNo = new URL(rNo1.headers.get('location'), SSO).searchParams.get('tx')
    const csrfNo = await csrfForLogin(jarNo, SSO, txNo)
    const rNoLogin = await ssoFetch(jarNo, `${SSO}/login/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${txNo}&username=10004&password=pass456&csrf=${csrfNo}`,
      redirect: 'manual'
    })
    const cbNo = rNoLogin.headers.get('location') ?? ''
    const grantNo = await oidc.authorizationCodeGrant(configuration, new URL(cbNo), {
      expectedState: 'sno', expectedNonce: 'nno', pkceCodeVerifier: vNo
    })
    const { payload: claimsNo } = await jwtVerify(grantNo.id_token, JWKS, { issuer: SSO, audience: 'test-web', nonce: 'nno' })
    assert('无钉钉号用户 id_token 不含 dingtalk claim', claimsNo.sub === '10004' && !('dingtalk' in claimsNo))
    const { payload: atNo } = await jwtVerify(grantNo.access_token, JWKS, { issuer: SSO, audience: 'test-web' })
    assert('无钉钉号用户 access_token 不含 dingtalk claim', !('dingtalk' in atNo))
    const infoNo = await oidc.fetchUserInfo(configuration, grantNo.access_token, '10004')
    assert('无钉钉号用户 userinfo 不含 dingtalk', !('dingtalk' in infoNo))

    // ---- 改密吊销 refresh token 与其它端 SSO 会话 ----
    // 用 10004:其密码(pass456)在本脚本其它段落从不被修改,且后续无依赖;
    // 10001 的密码需保持 pass123 供下方 TTL 覆盖实例登录,故不能用 10001(仅作只读对照)。
    // 改密前建立两个独立的 10004 密码会话(各自 sso_sid),分别充当"旧端"与"当前端"。
    const sessOld = await passwordLogin(configuration, '10004', 'pass456', 'spw-old')
    const sessCur = await passwordLogin(configuration, '10004', 'pass456', 'spw-cur')
    const jarOld = sessOld.jar
    const jarCur = sessCur.jar
    const sso_sid_old = sessOld.sid
    const sso_sid_cur = sessCur.sid
    const oldRefresh = sessOld.grant.refresh_token
    assert('改密前签发 refresh_token', typeof oldRefresh === 'string' && oldRefresh.length > 20)
    assert('改密前两个 10004 会话各有独立 sso_sid', !!sso_sid_old && !!sso_sid_cur && sso_sid_old !== sso_sid_cur)

    // 跨用户对照:10001 的独立会话(其密码在本脚本内不被修改,仅供下方 TTL 实例登录复用)
    const sessCtrl = await passwordLogin(configuration, '10001', 'pass123', 'spw-ctrl')
    const ctrlRefresh = sessCtrl.grant.refresh_token
    assert('跨用户对照会话签发 refresh_token', typeof ctrlRefresh === 'string' && ctrlRefresh.length > 20)

    // 密码登录(authMode=pwd)改密必须提供 current_password;用 jarCur 使 session.sid = sso_sid_cur
    const csrfCur = extractCsrf(await (await ssoFetch(jarCur, `${SSO}/profile`)).text())
    const rChange = await ssoFetch(jarCur, `${SSO}/profile/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `csrf=${csrfCur}&current_password=pass456&new_password=newpass456&confirm=newpass456`
    })
    assert('改密成功', (await rChange.text()).includes('密码已保存'))

    // 改密后:旧端 SSO 会话已吊销(authorize 不再直接发 code),当前端会话保留
    const authOld = await authorizeWithSid(configuration, sso_sid_old, 'spw-check-old')
    assert('改密后旧端 sso_sid 被吊销(authorize 不发 code)', authOld.status === 302 && !authOld.location.includes('code=') && authOld.location.startsWith('/login'))
    const authCur = await authorizeWithSid(configuration, sso_sid_cur, 'spw-check-cur')
    assert('改密后当前端 sso_sid 仍有效(进入会话确认页)', authCur.status === 200 && !authCur.location && authCur.body.includes('已登录为'))

    const rOld = await fetch(`${SSO}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: oldRefresh, client_id: 'test-web', client_secret: 'test-secret' })
    })
    const oldBody = await rOld.json()
    assert('改密后旧 refresh_token 被吊销(400 invalid_grant)', rOld.status === 400 && oldBody.error === 'invalid_grant')

    // 跨用户隔离:10004 改密不影响 10001 的 refresh_token
    const rCtrl = await fetch(`${SSO}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: ctrlRefresh, client_id: 'test-web', client_secret: 'test-secret' })
    })
    const ctrlBody = await rCtrl.json()
    assert('跨用户隔离:10004 改密不影响 10001 的 refresh_token(200)', rCtrl.status === 200 && !!ctrlBody.access_token)

    // 负向对照:改密后重新登录签发的 refresh_token 仍可用(证明只吊销了旧 token)
    const jarPw2 = new Jar()
    const vPw2 = oidc.randomPKCECodeVerifier()
    const auPw2 = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: REDIRECT_URI, scope: 'openid', state: 'spw2', nonce: 'npw2',
      code_challenge: await oidc.calculatePKCECodeChallenge(vPw2), code_challenge_method: 'S256'
    })
    const rPw2 = await ssoFetch(jarPw2, auPw2, { redirect: 'manual' })
    const txPw2 = new URL(rPw2.headers.get('location'), SSO).searchParams.get('tx')
    const csrfPw2 = await csrfForLogin(jarPw2, SSO, txPw2)
    const rPw2Login = await ssoFetch(jarPw2, `${SSO}/login/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${txPw2}&username=10004&password=newpass456&csrf=${csrfPw2}`,
      redirect: 'manual'
    })
    const cbPw2 = rPw2Login.headers.get('location') ?? ''
    const grantPw2 = await oidc.authorizationCodeGrant(configuration, new URL(cbPw2), {
      expectedState: 'spw2', expectedNonce: 'npw2', pkceCodeVerifier: vPw2
    })
    const rNew = await fetch(`${SSO}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: grantPw2.refresh_token, client_id: 'test-web', client_secret: 'test-secret' })
    })
    const rNewBody = await rNew.json()
    assert('改密后新 refresh_token 仍可用', rNew.ok)

    // 客户端认证失败
    const badClient = await fetch(`${SSO}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=authorization_code&code=x&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&client_id=test-web&client_secret=wrong`
    })
    assert('客户端密钥错误 → 401', badClient.status === 401)

    // ---- 会话确认页:已有会话不再静默发码(continue/switch/prompt=login) ----
    // 沿用 jar1 已建立的 10001 密码会话;不新增密码登录,避免主实例限流(10 次/分钟)
    const verifier2 = oidc.randomPKCECodeVerifier()
    const authUrl2 = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: REDIRECT_URI,
      scope: 'openid profile',
      state: 'st2',
      nonce: 'n2',
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier2),
      code_challenge_method: 'S256'
    })
    const r2 = await ssoFetch(jar1, authUrl2, { redirect: 'manual' })
    const confirmHtml = await r2.text()
    assert('已有会话 → 200 会话确认页(无 302)', r2.status === 200 && !r2.headers.get('location'))
    assert('确认页含账号与两种选择', confirmHtml.includes('已登录为') && confirmHtml.includes('继续以该账号登录') && confirmHtml.includes('使用其他账号'))
    const tx2 = (confirmHtml.match(/name="tx" value="([^"]+)"/) ?? [])[1] ?? ''
    const csrf2 = extractCsrf(confirmHtml)
    assert('确认页含 tx 与 csrf 隐藏字段', !!tx2 && !!csrf2)

    // 失败路径:缺 CSRF → 400;事务不存在 → 400(且不消耗既有事务)
    const rContinueNoCsrf = await ssoFetch(jar1, `${SSO}/authorize/continue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${tx2}`,
      redirect: 'manual'
    })
    assert('continue 缺少 CSRF → 400', rContinueNoCsrf.status === 400)
    const rContinueBadTx = await ssoFetch(jar1, `${SSO}/authorize/continue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=deadbeef&csrf=${csrf2}`,
      redirect: 'manual'
    })
    assert('continue 无效事务 → 400 登录事务已过期', rContinueBadTx.status === 400 && (await rContinueBadTx.text()).includes('登录事务已过期'))

    // 继续以该账号登录 → 302 携带 code,可正常换 token
    const rContinue = await ssoFetch(jar1, `${SSO}/authorize/continue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${tx2}&csrf=${csrf2}`,
      redirect: 'manual'
    })
    const cbUrl2 = rContinue.headers.get('location') ?? ''
    assert('continue → 302 携带 code 回调', rContinue.status === 302 && cbUrl2.startsWith(REDIRECT_URI) && cbUrl2.includes('code='))
    const grant2 = await oidc.authorizationCodeGrant(configuration, new URL(cbUrl2), {
      expectedState: 'st2',
      expectedNonce: 'n2',
      pkceCodeVerifier: verifier2
    })
    const { payload: claims2 } = await jwtVerify(grant2.id_token, JWKS, { issuer: SSO, audience: 'test-web', nonce: 'n2' })
    assert('确认页 continue 的 code 换 token(sub=10001)', claims2.sub === '10001')

    // 事务一次性(顺序):同一 tx+csrf 再次 continue 必须被拒(第二次无法再签 code)
    const rContinueAgain = await ssoFetch(jar1, `${SSO}/authorize/continue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${tx2}&csrf=${csrf2}`,
      redirect: 'manual'
    })
    assert('同一 tx 重复 continue → 400(事务已消费)', rContinueAgain.status === 400 && (await rContinueAgain.text()).includes('登录事务已过期'))

    // 事务一次性(并发):同一 tx+csrf 并发 POST continue,恰一次成功
    const auConc = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: REDIRECT_URI, scope: 'openid', state: 'scc', nonce: 'ncc'
    })
    const rConcPage = await ssoFetch(jar1, auConc, { redirect: 'manual' })
    const concHtml = await rConcPage.text()
    const txConc = (concHtml.match(/name="tx" value="([^"]+)"/) ?? [])[1] ?? ''
    const csrfConc = extractCsrf(concHtml)
    const postConcContinue = () => ssoFetch(jar1, `${SSO}/authorize/continue`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${txConc}&csrf=${csrfConc}`,
      redirect: 'manual'
    })
    const [rc1, rc2] = await Promise.all([postConcContinue(), postConcContinue()])
    const concCodes = [rc1, rc2].filter((r) => r.status === 302 && (r.headers.get('location') ?? '').includes('code=')).length
    assert('并发 POST continue 恰一次成功(事务只消费一次)', concCodes === 1 && [rc1.status, rc2.status].includes(400))

    // prompt=login 跳过确认页:直接 302 登录页,响应不含确认页 HTML
    const promptUrl = new URL(authUrl2)
    promptUrl.searchParams.set('prompt', 'login')
    const rPrompt = await ssoFetch(jar1, promptUrl, { redirect: 'manual' })
    const promptLoc = rPrompt.headers.get('location') ?? ''
    assert('prompt=login → 302 登录页(不渲染确认页)', rPrompt.status === 302 && promptLoc.startsWith('/login?tx=') && !(await rPrompt.text()).includes('继续以该账号登录'))

    // prompt=none:有会话 → 静默发码(无 UI);无会话 → 302 回应用 error=login_required
    const auNone = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: REDIRECT_URI, scope: 'openid', state: 'snn', nonce: 'nnn'
    })
    auNone.searchParams.set('prompt', 'none')
    const rNone = await ssoFetch(jar1, auNone, { redirect: 'manual' })
    const noneLoc = rNone.headers.get('location') ?? ''
    assert('prompt=none 有会话 → 302 静默发码(带 state)', rNone.status === 302 && noneLoc.startsWith(REDIRECT_URI) && noneLoc.includes('code=') && noneLoc.includes('state=snn'))
    const jarSilent = new Jar()
    const rNoneAnon = await ssoFetch(jarSilent, auNone, { redirect: 'manual' })
    const noneAnonLoc = rNoneAnon.headers.get('location') ?? ''
    assert('prompt=none 无会话 → error=login_required(带 state,不跳登录页)', rNoneAnon.status === 302 && noneAnonLoc.startsWith(REDIRECT_URI) && noneAnonLoc.includes('error=login_required') && noneAnonLoc.includes('state=snn'))

    // prompt="login none":none 优先(确定性语义,见 handleAuthorize 注释),有会话仍静默发码
    const auBoth = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: REDIRECT_URI, scope: 'openid', state: 'sbn', nonce: 'nbn'
    })
    auBoth.searchParams.set('prompt', 'login none')
    const rBoth = await ssoFetch(jar1, auBoth, { redirect: 'manual' })
    const bothLoc = rBoth.headers.get('location') ?? ''
    assert('prompt="login none" → none 优先(302 发码,非登录页)', rBoth.status === 302 && bothLoc.startsWith(REDIRECT_URI) && bothLoc.includes('code='))

    // CSRF 与会话绑定:账号 A(10001/jar1)确认页的 csrf 在账号 B(10004/jarCur)会话下必须被拒
    const auCross = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: REDIRECT_URI, scope: 'openid', state: 'scr', nonce: 'ncr'
    })
    const rCrossPage = await ssoFetch(jar1, auCross, { redirect: 'manual' })
    const crossHtml = await rCrossPage.text()
    const txCross = (crossHtml.match(/name="tx" value="([^"]+)"/) ?? [])[1] ?? ''
    const csrfCross = extractCsrf(crossHtml)
    const postCross = (path) => ssoFetch(jarCur, `${SSO}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${txCross}&csrf=${csrfCross}`,
      redirect: 'manual'
    })
    const rCrossContinue = await postCross('/authorize/continue')
    const rCrossSwitch = await postCross('/authorize/switch')
    assert('A 的确认页 csrf 在 B 会话下 continue 被拒(400)', rCrossContinue.status === 400)
    assert('A 的确认页 csrf 在 B 会话下 switch 被拒(400)', rCrossSwitch.status === 400)
    const authCrossB = await authorizeWithSid(configuration, sso_sid_cur, 'scr-check')
    assert('跨会话 CSRF 被拒后 B 会话未被误销毁', authCrossB.status === 200 && authCrossB.body.includes('继续以该账号登录'))

    // 无会话 POST continue/switch → 先回登录页(tx 存在 → 会话缺失的校验顺序)
    const jarNoSess = new Jar()
    const auNoSess = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: REDIRECT_URI, scope: 'openid', state: 'sns', nonce: 'nns'
    })
    const rNoSessAuth = await ssoFetch(jarNoSess, auNoSess, { redirect: 'manual' })
    const txNoSess = new URL(rNoSessAuth.headers.get('location') ?? '/', SSO).searchParams.get('tx') ?? ''
    for (const path of ['/authorize/continue', '/authorize/switch']) {
      const rNoSessPost = await ssoFetch(jarNoSess, `${SSO}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `tx=${txNoSess}`,
        redirect: 'manual'
      })
      assert(`无会话 POST ${path} → 302 回登录页`, rNoSessPost.status === 302 && (rNoSessPost.headers.get('location') ?? '').startsWith(`/login?tx=${txNoSess}`))
    }

    // ---- 使用其他账号:销毁 SSO 会话,但不吊销 refresh token ----
    // 用 sessCtrl(10001 的独立会话);其 refresh 已在上面跨用户隔离用例中轮换为 ctrlBody.refresh_token
    const jarCtrl = sessCtrl.jar
    const vSwitch = oidc.randomPKCECodeVerifier()
    const auSwitch = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: REDIRECT_URI, scope: 'openid', state: 'ssw', nonce: 'nsw',
      code_challenge: await oidc.calculatePKCECodeChallenge(vSwitch), code_challenge_method: 'S256'
    })
    const rSwPage = await ssoFetch(jarCtrl, auSwitch, { redirect: 'manual' })
    const swHtml = await rSwPage.text()
    assert('切换前会话有效(确认页)', rSwPage.status === 200 && swHtml.includes('继续以该账号登录'))
    const txSw = (swHtml.match(/name="tx" value="([^"]+)"/) ?? [])[1] ?? ''
    const csrfSw = extractCsrf(swHtml)
    const rSwitch = await ssoFetch(jarCtrl, `${SSO}/authorize/switch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${txSw}&csrf=${csrfSw}`,
      redirect: 'manual'
    })
    const switchLoc = rSwitch.headers.get('location') ?? ''
    assert('switch → 302 登录页', rSwitch.status === 302 && switchLoc.startsWith(`/login?tx=${txSw}`))
    assert('switch 响应清除 sso_sid Cookie', (rSwitch.headers.getSetCookie?.() ?? []).some((c) => c.startsWith('sso_sid=;')))
    const authAfterSwitch = await authorizeWithSid(configuration, sessCtrl.sid, 'ssw-check')
    assert('switch 后旧 sso_sid 已失效(authorize 回登录页)', authAfterSwitch.status === 302 && !authAfterSwitch.location.includes('code=') && authAfterSwitch.location.startsWith('/login'))
    const rSwRefresh = await fetch(`${SSO}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: ctrlBody.refresh_token, client_id: 'test-web', client_secret: 'test-secret' })
    })
    const swRefreshBody = await rSwRefresh.json()
    assert('switch 不吊销原账号 refresh_token(仍可刷新)', rSwRefresh.status === 200 && !!swRefreshBody.access_token)

    // ---- 扫码通道(新会话) ----
    const jar2 = new Jar()
    const verifier3 = oidc.randomPKCECodeVerifier()
    const authUrl3 = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: REDIRECT_URI,
      scope: 'openid profile',
      state: 'st3',
      nonce: 'n3',
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier3),
      code_challenge_method: 'S256'
    })
    const r3 = await ssoFetch(jar2, authUrl3, { redirect: 'manual' })
    const loginLoc3 = r3.headers.get('location') ?? ''
    const tx3 = new URL(loginLoc3, SSO).searchParams.get('tx')
    const rStart = await ssoFetch(jar2, `${SSO}/dingtalk/start?tx=${tx3}`, { redirect: 'manual' })
    const startLoc = rStart.headers.get('location') ?? ''
    assert('扫码跳转钉钉授权页(mock)', startLoc.includes('/login/oauth/authorize'))

    // 模拟扫码:mock 直接 302 回 SSO callback;一路跟随
    let cur = startLoc
    let qrCb = ''
    for (let i = 0; i < 5; i++) {
      const rr = await ssoFetch(jar2, cur, { redirect: 'manual' })
      jar2.absorb(rr)
      const loc = rr.headers.get('location')
      if (!loc) break
      const next = new URL(loc, cur.startsWith('http') ? cur : SSO).href
      if (next.startsWith(REDIRECT_URI)) {
        qrCb = next
        break
      }
      cur = next
    }
    assert('扫码完成 → 回调携带 code', qrCb.startsWith(REDIRECT_URI) && qrCb.includes('code='))
    const grant3 = await oidc.authorizationCodeGrant(configuration, new URL(qrCb), {
      expectedState: 'st3',
      expectedNonce: 'n3',
      pkceCodeVerifier: verifier3
    })
    const { payload: claims3 } = await jwtVerify(grant3.id_token, JWKS, { issuer: SSO, audience: 'test-web', nonce: 'n3' })
    assert('扫码 id_token 验签通过(sub=10003)', claims3.sub === '10003')
    assert('扫码通道 id_token 也携带 dingtalk claim', claims3.dingtalk === '10003')

    // ---- 密码激活(扫码后 10 分钟内免当前密码) ----
    const sid = jar2.cookies.get('sso_sid') ?? ''
    const csrfQr = extractCsrf(await (await ssoFetch(jar2, `${SSO}/profile`)).text())
    const rSet = await ssoFetch(jar2, `${SSO}/profile/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `csrf=${csrfQr}&new_password=newpass123&confirm=newpass123`
    })
    const setBody = await rSet.text()
    assert('扫码后激活密码通道', setBody.includes('密码已保存'))
    // 新会话用新密码走密码登录
    const jarNew = new Jar()
    const vNew = oidc.randomPKCECodeVerifier()
    const auNew = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: REDIRECT_URI, scope: 'openid', state: 'sx', nonce: 'nx',
      code_challenge: await oidc.calculatePKCECodeChallenge(vNew), code_challenge_method: 'S256'
    })
    const rAu = await ssoFetch(jarNew, auNew, { redirect: 'manual' })
    const txNew = new URL(rAu.headers.get('location'), SSO).searchParams.get('tx')
    const csrfNew = await csrfForLogin(jarNew, SSO, txNew)
    const rNewLogin = await ssoFetch(jarNew, `${SSO}/login/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${txNew}&username=10003&password=newpass123&csrf=${csrfNew}`,
      redirect: 'manual'
    })
    jarNew.absorb(rNewLogin)
    assert('新设密码可登录', (rNewLogin.headers.get('location') ?? '').startsWith(REDIRECT_URI))
    // 用该授权码换取 token(10003 新 refresh_token),供下方个人页退出登录用例验证吊销
    const grantNew = await oidc.authorizationCodeGrant(configuration, new URL(rNewLogin.headers.get('location') ?? ''), {
      expectedState: 'sx', expectedNonce: 'nx', pkceCodeVerifier: vNew
    })
    assert('新密码登录的授权码可换取 refresh_token(前置)', typeof grantNew.refresh_token === 'string' && grantNew.refresh_token.length > 20)

    // ---- 禁用账号扫码拒绝 ----
    await fetch(`${SSO.replace(String(SSO_PORT), String(MOCK_PORT))}`)?.catch?.(() => {})
    const mockBase = `http://127.0.0.1:${MOCK_PORT}`
    await fetch(`${mockBase}/__set_next_user?user=disabled`)
    const jar3 = new Jar()
    const vDisabled = oidc.randomPKCECodeVerifier()
    const auDisabled = oidc.buildAuthorizationUrl(configuration, {
      redirect_uri: REDIRECT_URI, scope: 'openid', state: 'sd', nonce: 'nd',
      code_challenge: await oidc.calculatePKCECodeChallenge(vDisabled), code_challenge_method: 'S256'
    })
    const rD1 = await ssoFetch(jar3, auDisabled, { redirect: 'manual' })
    const lD1 = rD1.headers.get('location') ?? ''
    const txD = new URL(lD1, SSO).searchParams.get('tx')
    const rD2 = await ssoFetch(jar3, `${SSO}/dingtalk/start?tx=${txD}`, { redirect: 'manual' })
    let curD = rD2.headers.get('location') ?? ''
    let finalBody = ''
    for (let i = 0; i < 5; i++) {
      const rr = await ssoFetch(jar3, curD, { redirect: 'manual' })
      const loc = rr.headers.get('location')
      if (!loc) {
        finalBody = await rr.text()
        break
      }
      curD = new URL(loc, curD.startsWith('http') ? curD : SSO).href
    }
    assert('禁用账号扫码被拒(403 + 提示)', finalBody.includes('账号已禁用'))
    await fetch(`${mockBase}/__set_next_user?user=active`)

    // ---- 个人页:退出登录 / 切换其他账号(POST /profile/logout | /profile/switch) ----
    // 复用既有会话:jarCur/10004(refresh 取改密后新签的 rNewBody)验证切换;jarNew/10003(grantNew)验证退出登录
    const profileHtmlCur = await (await ssoFetch(jarCur, `${SSO}/profile`)).text()
    assert('个人页含退出登录与切换账号两个表单', profileHtmlCur.includes('action="/profile/logout"') && profileHtmlCur.includes('action="/profile/switch"') && profileHtmlCur.includes('退出登录') && profileHtmlCur.includes('切换其他账号'))

    // CSRF 缺失 → 400, 且会话保持有效
    for (const path of ['/profile/logout', '/profile/switch']) {
      const rProfileNoCsrf = await ssoFetch(jarCur, `${SSO}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: '',
        redirect: 'manual'
      })
      assert(`个人页 ${path} 缺少 CSRF → 400`, rProfileNoCsrf.status === 400)
    }
    const authAfterProfileNoCsrf = await authorizeWithSid(configuration, sso_sid_cur, 'sprof-nocsrf')
    assert('个人页 CSRF 被拒后会话仍有效', authAfterProfileNoCsrf.status === 200 && authAfterProfileNoCsrf.body.includes('已登录为'))

    // 切换其他账号:302 /login?tab=qr, 旧 sid 失效, refresh_token 不吊销
    const csrfProfileCur = extractCsrf(profileHtmlCur)
    const rProfileSwitch = await ssoFetch(jarCur, `${SSO}/profile/switch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `csrf=${csrfProfileCur}`,
      redirect: 'manual'
    })
    assert('个人页切换账号 → 302 /login?tab=qr', rProfileSwitch.status === 302 && (rProfileSwitch.headers.get('location') ?? '') === '/login?tab=qr')
    assert('个人页切换账号清除 sso_sid Cookie', (rProfileSwitch.headers.getSetCookie?.() ?? []).some((c) => c.startsWith('sso_sid=;')))
    const authAfterProfileSwitch = await authorizeWithSid(configuration, sso_sid_cur, 'sprof-sw')
    assert('个人页切换账号后旧 sso_sid 失效(authorize 回登录页)', authAfterProfileSwitch.status === 302 && !authAfterProfileSwitch.location.includes('code=') && authAfterProfileSwitch.location.startsWith('/login'))
    const rProfSwitchRefresh = await fetch(`${SSO}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rNewBody.refresh_token, client_id: 'test-web', client_secret: 'test-secret' })
    })
    const profSwitchRefreshBody = await rProfSwitchRefresh.json()
    assert('个人页切换账号不吊销原 refresh_token(仍可刷新)', rProfSwitchRefresh.status === 200 && !!profSwitchRefreshBody.access_token)

    // 退出登录:退出页 + 清 Cookie + refresh_token 吊销
    const csrfProfileNew = extractCsrf(await (await ssoFetch(jarNew, `${SSO}/profile`)).text())
    const rProfileLogout = await ssoFetch(jarNew, `${SSO}/profile/logout`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `csrf=${csrfProfileNew}`,
      redirect: 'manual'
    })
    const profileLogoutBody = await rProfileLogout.text()
    assert('个人页退出登录 → 已退出登录页', rProfileLogout.status === 200 && profileLogoutBody.includes('已退出登录'))
    assert('个人页退出登录清除 sso_sid Cookie', (rProfileLogout.headers.getSetCookie?.() ?? []).some((c) => c.startsWith('sso_sid=;')))
    const authAfterProfileLogout = await authorizeWithSid(configuration, jarNew.cookies.get('sso_sid'), 'sprof-lo')
    assert('个人页退出登录后旧 sso_sid 失效(authorize 回登录页)', authAfterProfileLogout.status === 302 && !authAfterProfileLogout.location.includes('code=') && authAfterProfileLogout.location.startsWith('/login'))
    const rProfLogoutRefresh = await fetch(`${SSO}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: grantNew.refresh_token, client_id: 'test-web', client_secret: 'test-secret' })
    })
    const profLogoutRefreshBody = await rProfLogoutRefresh.json()
    assert('个人页退出登录吊销 refresh_token(400 invalid_grant)', rProfLogoutRefresh.status === 400 && profLogoutRefreshBody.error === 'invalid_grant')

    // ---- 登出 ----
    await ssoFetch(jar1, `${SSO}/logout`)
    const rAfterLogout = await ssoFetch(jar1, authUrl1, { redirect: 'manual' })
    assert('登出后 authorize 需重新登录', (rAfterLogout.headers.get('location') ?? '').startsWith('/login'))

    // ---- token-exchange grant(RFC 8693):dashboard-gateway 把自己的 id_token 换成 aud=router 的 token ----
    const DG_REDIRECT_URI = 'http://127.0.0.1:18090/api/auth/oidc/callback'
    const dgTokens = await passwordCodeGrant(SSO, '10001', 'pass123', 'dashboard-gateway', 'e2e-gateway-secret', DG_REDIRECT_URI)
    assert('dashboard-gateway 授权码换取 id_token(前置)', typeof dgTokens.id_token === 'string' && dgTokens.id_token.length > 20)

    const EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange'
    const EXCHANGE_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token'
    const exchange = (fields) => fetch(`${SSO}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: EXCHANGE_GRANT, ...fields })
    })

    // 正常交换
    const exRes = await exchange({
      subject_token: dgTokens.id_token,
      subject_token_type: EXCHANGE_TOKEN_TYPE,
      audience: 'router',
      client_id: 'dashboard-gateway',
      client_secret: 'e2e-gateway-secret'
    })
    const exBody = await exRes.json()
    assert('token 交换成功(200 含 access_token/issued_token_type/expires_in)', exRes.status === 200 && typeof exBody.access_token === 'string' && exBody.issued_token_type === 'urn:ietf:params:oauth:token-type:access_token' && typeof exBody.expires_in === 'number')
    const exClaims = typeof exBody.access_token === 'string'
      ? (await jwtVerify(exBody.access_token, JWKS, { issuer: SSO, audience: 'router' })).payload
      : {}
    assert('交换所得 JWT aud=router / sub=工号 / act=dashboard-gateway', exClaims.aud === 'router' && exClaims.sub === '10001' && exClaims.act === 'dashboard-gateway')
    assert('交换所得 JWT 继承身份 claims(name/dept/roles)', exClaims.name === '张三' && exClaims.dept === '平台组' && JSON.stringify(exClaims.roles) === JSON.stringify(['user']))
    assert('交换所得 JWT 继承 dingtalk claim(与目录一致)', exClaims.dingtalk === '10001')
    assert('交换所得 JWT 继承 email claim(与目录一致)', exClaims.email === 'zhangsan@xzrobot.com')
    assert('token 交换响应 expires_in=3600', exBody.expires_in === 3600)
    assert('交换所得 JWT TTL 为 3600 秒', exClaims.exp - exClaims.iat === 3600)
    assert('token 交换响应不含 id_token/refresh_token', !('id_token' in exBody) && !('refresh_token' in exBody))

    // audience 未授权(不在 allowed_audiences)
    const exBadAud = await exchange({ subject_token: dgTokens.id_token, subject_token_type: EXCHANGE_TOKEN_TYPE, audience: 'market', client_id: 'dashboard-gateway', client_secret: 'e2e-gateway-secret' })
    const exBadAudBody = await exBadAud.json()
    assert('audience 未授权 → 400 invalid_target', exBadAud.status === 400 && exBadAudBody.error === 'invalid_target')

    // subject_token 篡改:改 payload.sub 后重编码(不重签名),验签实现必须拒绝
    const tampered = tamperJwtPayload(dgTokens.id_token, { sub: '99999' })
    const exTampered = await exchange({ subject_token: tampered, subject_token_type: EXCHANGE_TOKEN_TYPE, audience: 'router', client_id: 'dashboard-gateway', client_secret: 'e2e-gateway-secret' })
    const exTamperedBody = await exTampered.json()
    assert('篡改 subject_token(未重签名) → 400 invalid_grant', exTampered.status === 400 && exTamperedBody.error === 'invalid_grant' && exTamperedBody.error_description === 'subject_token 无效或已过期')

    // 畸形 subject_token(无法解码):同样应拒绝
    const exMalformed = await exchange({ subject_token: 'not-a-jwt', subject_token_type: EXCHANGE_TOKEN_TYPE, audience: 'router', client_id: 'dashboard-gateway', client_secret: 'e2e-gateway-secret' })
    const exMalformedBody = await exMalformed.json()
    assert('畸形 subject_token → 400 invalid_grant', exMalformed.status === 400 && exMalformedBody.error === 'invalid_grant')

    // subject_token 受众不符(用 test-web 的 id_token,aud=test-web 而非 dashboard-gateway)
    const exWrongSub = await exchange({ subject_token: grant1.id_token, subject_token_type: EXCHANGE_TOKEN_TYPE, audience: 'router', client_id: 'dashboard-gateway', client_secret: 'e2e-gateway-secret' })
    const exWrongSubBody = await exWrongSub.json()
    assert('subject_token 受众不符 → 400 invalid_grant', exWrongSub.status === 400 && exWrongSubBody.error === 'invalid_grant' && exWrongSubBody.error_description === 'subject_token 受众与客户端不符')

    // 客户端未认证(不带 client_secret)
    const exNoAuth = await exchange({ subject_token: dgTokens.id_token, subject_token_type: EXCHANGE_TOKEN_TYPE, audience: 'router', client_id: 'dashboard-gateway' })
    const exNoAuthBody = await exNoAuth.json()
    assert('token 交换客户端未认证 → 401 invalid_client', exNoAuth.status === 401 && exNoAuthBody.error === 'invalid_client')

    // 缺少 audience
    const exMissing = await exchange({ subject_token: dgTokens.id_token, subject_token_type: EXCHANGE_TOKEN_TYPE, audience: '', client_id: 'dashboard-gateway', client_secret: 'e2e-gateway-secret' })
    const exMissingBody = await exMissing.json()
    assert('缺少 audience → 400 invalid_request', exMissing.status === 400 && exMissingBody.error === 'invalid_request')

    // 审计:成功/invalid_target 的 detail 为 JSON 转义(防换行/ANSI 注入),缺失参数路径也有失败审计
    const auditEvents = readFileSync(new URL('./data/audit.jsonl', import.meta.url), 'utf-8').trim().split('\n').map((l) => JSON.parse(l))
    const exAudits = auditEvents
      .filter((e) => e.event === 'token_exchange' && typeof e.detail === 'string' && e.detail.startsWith('{'))
      .map((e) => JSON.parse(e.detail))
    assert('成功交换审计 detail 为 JSON 转义且含 audience', exAudits.some((d) => d.audience === 'router'))
    assert('invalid_target 审计 detail 同样转义且含 audience', exAudits.some((d) => d.audience === 'market' && d.reason === '未授权'))
    assert('invalid_request 缺失参数路径有失败审计', auditEvents.some((e) => e.event === 'token_exchange' && !e.ok && e.detail === '缺少 subject_token 或 audience'))

    // ---- TTL 可配置覆盖:第二实例(access 60s / id 120s)证明环境变量真正生效 ----
    const sso2Base = `http://127.0.0.1:${SSO_TTL_PORT}`
    const ttlDataDir = new URL('./data-ttl', import.meta.url)
    const ttlKeysDir = new URL('./keys-ttl', import.meta.url)
    rmSync(ttlDataDir, { recursive: true, force: true })
    rmSync(ttlKeysDir, { recursive: true, force: true })
    const sso2 = spawnAndWait('node', ['--experimental-strip-types', 'src/index.ts'], {
      SSO_PORT: String(SSO_TTL_PORT),
      SSO_ISSUER: sso2Base,
      SSO_DATA_DIR: 'test/data-ttl',
      SSO_KEYS_DIR: 'test/keys-ttl',
      SSO_CLIENTS_PATH: 'test/fixtures/clients.json',
      FILE_USERS_PATH: 'test/data/users.json',
      SSO_ACCESS_TOKEN_TTL_SECONDS: '60',
      SSO_ID_TOKEN_TTL_SECONDS: '120',
      SSO_EXCHANGE_TTL: '90'
    })
    try {
      assert('TTL 覆盖实例健康检查', await waitHealth(`${sso2Base}/healthz`))
      const ttlBody = await passwordCodeGrant(sso2Base, '10001', 'pass123')
      const ttlAt = decodeJwt(ttlBody.access_token)
      const ttlId = decodeJwt(ttlBody.id_token)
      assert('SSO_ACCESS_TOKEN_TTL_SECONDS=60 生效', ttlAt.exp - ttlAt.iat === 60)
      assert('SSO_ID_TOKEN_TTL_SECONDS=120 生效', ttlId.exp - ttlId.iat === 120)
      assert('TTL 覆盖实例 expires_in 为 60', ttlBody.expires_in === 60)

      // SSO_EXCHANGE_TTL 自定义值 90 生效(避开该实例 access=60/id=120,证明读的是 exchange 专用配置)
      const ttlDg = await passwordCodeGrant(sso2Base, '10001', 'pass123', 'dashboard-gateway', 'e2e-gateway-secret', DG_REDIRECT_URI)
      const ttlExRes = await fetch(`${sso2Base}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: EXCHANGE_GRANT, subject_token: ttlDg.id_token, subject_token_type: EXCHANGE_TOKEN_TYPE, audience: 'router', client_id: 'dashboard-gateway', client_secret: 'e2e-gateway-secret' })
      })
      const ttlExBody = await ttlExRes.json()
      const ttlExClaims = typeof ttlExBody.access_token === 'string' ? decodeJwt(ttlExBody.access_token) : {}
      assert('SSO_EXCHANGE_TTL=90 自定义值生效', ttlExRes.status === 200 && ttlExBody.expires_in === 90 && ttlExClaims.exp - ttlExClaims.iat === 90)
    } finally {
      sso2.kill()
      rmSync(ttlDataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
      rmSync(ttlKeysDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
    }

    // ---- 自助重置密码:GET /reset 两步表单 + 邮件验证码 + 重置后新密码生效 ----
    // 用独立第三实例:主实例的密码登录限流(每 IP 10 次/分钟)已被既有用例占用 9 次,
    // 本段还需 2 次 /login/password;新实例限流窗口干净,且共享同一文件目录 users.json
    const RESET_PORT = 18093
    const RESET = `http://127.0.0.1:${RESET_PORT}`
    // 文案与 src/reset.ts 保持一致(本脚本为 .mjs,无法 import TS 常量)
    const RESET_REQUEST_MESSAGE = '若该工号存在, 验证码已发送至其企业邮箱'
    const RESET_FAIL_MESSAGE = '验证码无效或已过期, 请重新获取'
    const resetDataDir = new URL('./data-reset', import.meta.url)
    const resetKeysDir = new URL('./keys-reset', import.meta.url)
    rmSync(resetDataDir, { recursive: true, force: true })
    rmSync(resetKeysDir, { recursive: true, force: true })
    mkdirSync(resetDataDir, { recursive: true })
    const sso3 = spawnAndWait('node', ['--experimental-strip-types', 'src/index.ts'], {
      SSO_PORT: String(RESET_PORT),
      SSO_ISSUER: RESET,
      SSO_DATA_DIR: 'test/data-reset',
      SSO_KEYS_DIR: 'test/keys-reset',
      SSO_CLIENTS_PATH: 'test/fixtures/clients.json',
      FILE_USERS_PATH: 'test/data/users.json',
      // 显式非生产:避免父进程 APP_ENV=prod/production 时 FAKE_CAPTURE 被生产守卫忽略
      NODE_ENV: 'test',
      APP_ENV: '',
      // 验证码邮件写入文件而非真实 SMTP
      SSO_SMTP_FAKE_CAPTURE: 'test/data-reset/smtp-capture.jsonl'
    })
    try {
      assert('重置实例健康检查', await waitHealth(`${RESET}/healthz`))
      // 重置前先拿一份 refresh_token, 供重置后验证被吊销
      const preResetTokens = await passwordCodeGrant(RESET, '10001', 'pass123')
      assert('重置前取得 refresh_token(前置)', typeof preResetTokens.refresh_token === 'string' && preResetTokens.refresh_token.length > 20)
      const captureFile = new URL('./data-reset/smtp-capture.jsonl', import.meta.url)
      const captureMails = () => {
        try {
          return readFileSync(captureFile, 'utf-8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
        } catch {
          return []
        }
      }
      // 发信已转后台:轮询等待捕获落盘
      const waitForMails = async (n, timeoutMs = 3000) => {
        const deadline = Date.now() + timeoutMs
        while (Date.now() < deadline && captureMails().length < n) {
          await new Promise((r) => setTimeout(r, 20))
        }
        return captureMails()
      }
      const postForm = (path, body) => fetch(`${RESET}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body
      })

      const rResetPage = await fetch(`${RESET}/reset`)
      const resetPageHtml = await rResetPage.text()
      assert('GET /reset 返回 200 且含第一步表单', rResetPage.status === 200 && resetPageHtml.includes('action="/reset/request"') && resetPageHtml.includes('name="sub"'))

      const rResetReq = await postForm('/reset/request', 'sub=10001')
      const resetReqHtml = await rResetReq.text()
      assert('重置请求 200:渲染 step2 并显示统一文案', rResetReq.status === 200 && resetReqHtml.includes('action="/reset/confirm"') && resetReqHtml.includes(RESET_REQUEST_MESSAGE))
      const mails1 = await waitForMails(1)
      assert('捕获文件新增一封验证码邮件', mails1.length === 1)
      const resetMail = mails1[0] ?? {}
      const codeMatch = String(resetMail.text ?? '').match(/验证码为:(\d{6})/)
      assert('验证码邮件收件人与 6 位码正确', resetMail.to === 'zhangsan@xzrobot.com' && !!codeMatch)
      const resetCode = codeMatch?.[1] ?? ''

      const wrongCode = resetCode === '000000' ? '000001' : '000000'
      const rWrongCode = await postForm('/reset/confirm', `sub=10001&code=${wrongCode}&new_password=newpass789&confirm=newpass789`)
      assert('错码 → 统一失败文案', (await rWrongCode.text()).includes(RESET_FAIL_MESSAGE))

      const rPwdMismatch = await postForm('/reset/confirm', `sub=10001&code=${resetCode}&new_password=newpass789&confirm=newpass790`)
      assert('两次密码不一致 → 提示且验证码未被消费', (await rPwdMismatch.text()).includes('两次输入的密码不一致'))

      const rResetOk = await postForm('/reset/confirm', `sub=10001&code=${resetCode}&new_password=newpass789&confirm=newpass789`)
      assert('正确码重置成功(回执含成功提示)', rResetOk.status === 200 && (await rResetOk.text()).includes('密码已重置'))

      const tryPasswordLogin = async (password, state) => {
        const jar = new Jar()
        const au = `${RESET}/authorize?client_id=test-web&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=openid&state=${state}&nonce=${state}`
        const r1 = await ssoFetch(jar, au, { redirect: 'manual' })
        const tx = new URL(r1.headers.get('location'), RESET).searchParams.get('tx')
        const csrf = await csrfForLogin(jar, RESET, tx)
        const r2 = await ssoFetch(jar, `${RESET}/login/password`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `tx=${tx}&username=10001&password=${password}&csrf=${csrf}`,
          redirect: 'manual'
        })
        return { status: r2.status, location: r2.headers.get('location') ?? '' }
      }
      const oldPwdLogin = await tryPasswordLogin('pass123', 'sreset-old')
      assert('重置后旧密码登录失败', oldPwdLogin.status === 302 && oldPwdLogin.location.includes('error='))
      const newPwdLogin = await tryPasswordLogin('newpass789', 'sreset-new')
      assert('重置后新密码登录成功(302 携带 code)', newPwdLogin.status === 302 && newPwdLogin.location.startsWith(REDIRECT_URI) && newPwdLogin.location.includes('code='))

      // 重置成功必须吊销该用户全部 refresh token
      const rStaleRefresh = await fetch(`${RESET}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: preResetTokens.refresh_token, client_id: 'test-web', client_secret: 'test-secret' })
      })
      const staleRefreshBody = await rStaleRefresh.json()
      assert('重置后旧 refresh_token 被吊销(400 invalid_grant)', rStaleRefresh.status === 400 && staleRefreshBody.error === 'invalid_grant')

      const mailsBeforeProbe = captureMails().length
      const rGhost = await postForm('/reset/request', 'sub=19999')
      assert('不存在工号 → 统一文案', (await rGhost.text()).includes(RESET_REQUEST_MESSAGE))
      const rNoEmail = await postForm('/reset/request', 'sub=10003')
      assert('无邮箱用户 → 统一文案', (await rNoEmail.text()).includes(RESET_REQUEST_MESSAGE))
      assert('不存在工号/无邮箱用户均不触发发信', captureMails().length === mailsBeforeProbe)
    } finally {
      sso3.kill()
      rmSync(resetDataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
      rmSync(resetKeysDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
    }

    console.log(`\n结果:${passed} 通过,${failed} 失败`)
    if (failed > 0) process.exit(1)
  } finally {
    mock.kill()
    sso.kill()
  }
}

main().catch((err) => {
  console.error('SMOKE ERROR:', err)
  process.exit(1)
})
