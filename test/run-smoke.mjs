/**
 * SSO 全流程烟测:
 *   启动 mock 钉钉 + SSO(文件目录),用 openid-client 标准客户端库走完整 OIDC 流程。
 * 覆盖:discovery/JWKS、扫码登录、密码登录、错误凭据、禁用账号拒绝、code 一次性、
 *       单点登录、密码激活、登出、客户端认证失败。
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
    { sub: '10001', name: '张三', dept: '平台组', mobile: '13800000001', dingtalkUserId: '10001', status: 'active', passwordHash: hashPassword('pass123') },
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

/** 走一遍密码通道(authorize → login/password → token),返回 /token 响应体;用于第二实例的 TTL 覆盖验证 */
async function passwordCodeGrant(base, username, password) {
  const jar = new Jar()
  const authUrl = `${base}/authorize?client_id=test-web&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=openid&state=ttl&nonce=ttl`
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
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, client_id: 'test-web', client_secret: 'test-secret' })
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

/** 用给定 sso_sid 走 /authorize,返回状态码与 Location */
async function authorizeWithSid(configuration, sid, state) {
  const authUrl = oidc.buildAuthorizationUrl(configuration, {
    redirect_uri: REDIRECT_URI, scope: 'openid', state, nonce: state
  })
  const res = await fetch(authUrl, { headers: { Cookie: `sso_sid=${sid}` }, redirect: 'manual' })
  return { status: res.status, location: res.headers.get('location') ?? '' }
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
    assert('改密后当前端 sso_sid 仍有效(authorize 发 code)', authCur.status === 302 && authCur.location.startsWith(REDIRECT_URI) && authCur.location.includes('code='))

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
    assert('改密后新 refresh_token 仍可用', rNew.ok)

    // 客户端认证失败
    const badClient = await fetch(`${SSO}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=authorization_code&code=x&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&client_id=test-web&client_secret=wrong`
    })
    assert('客户端密钥错误 → 401', badClient.status === 401)

    // ---- 单点登录(同会话第二次 authorize 免登录) ----
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
    const cbUrl2 = r2.headers.get('location') ?? ''
    assert('单点登录:第二次 authorize 直接发 code', r2.status === 302 && cbUrl2.startsWith(REDIRECT_URI) && cbUrl2.includes('code='))
    const grant2 = await oidc.authorizationCodeGrant(configuration, new URL(cbUrl2), {
      expectedState: 'st2',
      expectedNonce: 'n2',
      pkceCodeVerifier: verifier2
    })
    assert('单点 code 换 token 成功', !!grant2.id_token)

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
    assert('新设密码可登录', (rNewLogin.headers.get('location') ?? '').startsWith(REDIRECT_URI))

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

    // ---- 登出 ----
    await ssoFetch(jar1, `${SSO}/logout`)
    const rAfterLogout = await ssoFetch(jar1, authUrl1, { redirect: 'manual' })
    assert('登出后 authorize 需重新登录', (rAfterLogout.headers.get('location') ?? '').startsWith('/login'))

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
      SSO_ID_TOKEN_TTL_SECONDS: '120'
    })
    try {
      assert('TTL 覆盖实例健康检查', await waitHealth(`${sso2Base}/healthz`))
      const ttlBody = await passwordCodeGrant(sso2Base, '10001', 'pass123')
      const ttlAt = decodeJwt(ttlBody.access_token)
      const ttlId = decodeJwt(ttlBody.id_token)
      assert('SSO_ACCESS_TOKEN_TTL_SECONDS=60 生效', ttlAt.exp - ttlAt.iat === 60)
      assert('SSO_ID_TOKEN_TTL_SECONDS=120 生效', ttlId.exp - ttlId.iat === 120)
      assert('TTL 覆盖实例 expires_in 为 60', ttlBody.expires_in === 60)
    } finally {
      sso2.kill()
      rmSync(ttlDataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
      rmSync(ttlKeysDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
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
