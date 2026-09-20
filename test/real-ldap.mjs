/**
 * 真实 LDAP 集成验证(需 .env 指向真实服务器):
 *   启动 SSO → OIDC 流程 → 账号密码登录(真实 LDAP bind)→ code 换 token → JWKS 验签
 * 用法:node --env-file=.env test/real-ldap.mjs <登录账号> <密码>
 */
import { spawn } from 'node:child_process'
import { createRemoteJWKSet, jwtVerify } from 'jose'

const [, , username = 'admin', password = ''] = process.argv
const SSO_BASE = process.env.SSO_BASE ?? `http://127.0.0.1:${Number(process.env.SSO_PORT ?? 8091)}`
const SSO = SSO_BASE
const CLIENT_ID = 'dashboard-gateway'
const CLIENT_SECRET = process.env.SSO_SECRET_DASHBOARD ?? ''
const REDIRECT_URI = 'http://127.0.0.1:8090/api/auth/oidc/callback'

let passed = 0
let failed = 0
function assert(name, cond, detail = '') {
  if (cond) {
    passed++
    console.log(`PASS | ${name}`)
  } else {
    failed++
    console.log(`FAIL | ${name} ${detail}`)
  }
}

function spawnSSO() {
  const child = spawn('node', ['--experimental-strip-types', '--env-file=.env', 'src/index.ts'], {
    cwd: new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'),
    stdio: ['ignore', 'pipe', 'pipe']
  })
  child.stdout.on('data', (d) => process.stdout.write(`[sso] ${d}`))
  child.stderr.on('data', (d) => process.stderr.write(`[sso:err] ${d}`))
  return child
}

async function waitHealth() {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`${SSO}/healthz`)
      if (r.ok) return true
    } catch {}
    await new Promise((r) => setTimeout(r, 300))
  }
  return false
}

const jar = new Map()
function cookieHeader() {
  return [...jar].map(([k, v]) => `${k}=${v}`).join('; ')
}

async function main() {
  const local = !process.env.SSO_BASE
  if (!CLIENT_SECRET) {
    console.error('缺少 SSO_SECRET_DASHBOARD(请用 --env-file=.env 运行)')
    process.exit(1)
  }
  const child = local ? spawnSSO() : null
  try {
    if (local) assert('SSO 启动', await waitHealth())
    else assert('远端 SSO 可达', await waitHealth())

    // 1) 授权请求(用 openssl 替代库:PKCE 手工生成)
    const verifier = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ'
    const { createHash } = await import('node:crypto')
    const challenge = createHash('sha256').update(verifier).digest('base64url')
    const authorizeUrl =
      `${SSO}/authorize?response_type=code&client_id=${CLIENT_ID}` +
      `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=openid%20profile` +
      `&state=real-ldap&nonce=real-nonce&code_challenge=${challenge}&code_challenge_method=S256`

    const r1 = await fetch(authorizeUrl, { redirect: 'manual' })
    const loginLoc = r1.headers.get('location') ?? ''
    assert('跳转登录页', r1.status === 302 && loginLoc.startsWith('/login?tx='))

    const tx = new URL(loginLoc, SSO).searchParams.get('tx')

    // 2) 真实 LDAP bind:错误密码
    const rWrong = await fetch(`${SSO}/login/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookieHeader() },
      body: `tx=${tx}&username=${encodeURIComponent(username)}&password=definitely-wrong`,
      redirect: 'manual'
    })
    const wrongLoc = rWrong.headers.get('location') ?? ''
    assert('真实 LDAP:错误密码被拒', rWrong.status === 302 && wrongLoc.includes('error='))

    // 3) 真实 LDAP bind:正确密码
    const rOk = await fetch(`${SSO}/login/password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookieHeader() },
      body: `tx=${tx}&username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
      redirect: 'manual'
    })
    const cbUrl = rOk.headers.get('location') ?? ''
    if (!(rOk.status === 302 && cbUrl.startsWith(REDIRECT_URI))) {
      console.log('  [debug] rOk.status =', rOk.status, '| location =', cbUrl.slice(0, 120))
      console.log('  [debug] body =', (await rOk.text()).slice(0, 300))
    }
    assert('真实 LDAP:正确密码登录成功 → 回调携带 code', rOk.status === 302 && cbUrl.startsWith(REDIRECT_URI) && cbUrl.includes('code='))

    // 4) code 换 token
    const code = new URL(cbUrl).searchParams.get('code')
    const tokenRes = await fetch(`${SSO}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code_verifier: verifier
      })
    })
    assert('code 换 token 成功', tokenRes.ok)
    const tokens = await tokenRes.json()

    // 5) JWKS 验签 + 属性断言(证明读取的是真实 LDAP 条目)
    const JWKS = createRemoteJWKSet(new URL(`${SSO}/.well-known/jwks.json`))
    const { payload } = await jwtVerify(tokens.id_token, JWKS, {
      issuer: SSO,
      audience: CLIENT_ID,
      nonce: 'real-nonce'
    })
    console.log('  id_token claims:', JSON.stringify({ sub: payload.sub, name: payload.name, dept: payload.dept, roles: payload.roles }))
    assert('id_token 验签通过(JWKS)', payload.sub === username)
    assert('角色展开有效', Array.isArray(payload.roles) && payload.roles.length > 0)

    // 6) userinfo
    const ui = await fetch(`${SSO}/userinfo`, { headers: { Authorization: `Bearer ${tokens.access_token}` } })
    assert('userinfo 可用', ui.ok)

    console.log(`\n结果:${passed} 通过,${failed} 失败`)
    if (failed > 0) process.exitCode = 1
  } finally {
    if (child) child.kill()
  }
}

main().catch((err) => {
  console.error('REAL-LDAP TEST ERROR:', err.message, err.cause?.code ?? '')
  process.exit(1)
})
