/**
 * SSO 全流程烟测:
 *   启动 mock 钉钉 + SSO(文件目录),用 openid-client 标准客户端库走完整 OIDC 流程。
 * 覆盖:discovery/JWKS、扫码登录、密码登录、错误凭据、禁用账号拒绝、code 一次性、
 *       单点登录、密码激活、登出、客户端认证失败。
 */
import { spawn } from 'node:child_process'
import { rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { scryptSync, randomBytes } from 'node:crypto'
import * as oidc from 'openid-client'
import { jwtVerify, createRemoteJWKSet } from 'jose'

const SSO_PORT = 18091
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

    // 错误密码
    const rWrong = await ssoFetch(jar1, `${SSO}/login/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${tx}&username=10001&password=wrong-password`,
      redirect: 'manual'
    })
    const wrongLoc = rWrong.headers.get('location') ?? ''
    assert('错误凭据 → 回登录页并提示', rWrong.status === 302 && wrongLoc.includes('error='))

    // 正确密码 → code
    const rOk = await ssoFetch(jar1, `${SSO}/login/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${tx}&username=10001&password=pass123`,
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
    const rNoLogin = await ssoFetch(jarNo, `${SSO}/login/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${txNo}&username=10004&password=pass456`,
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
    const rSet = await ssoFetch(jar2, `${SSO}/profile/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'new_password=newpass123&confirm=newpass123'
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
    const rNewLogin = await ssoFetch(jarNew, `${SSO}/login/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `tx=${txNew}&username=10003&password=newpass123`,
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
