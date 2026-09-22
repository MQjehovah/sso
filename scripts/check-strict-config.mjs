/**
 * 弱配置拒绝启动断言(CI 用,也可本地执行:npm run check:strict-config)。
 *
 * 用故意缺失/弱化的配置启动真实服务,断言以下弱配置都在监听端口前失败:
 *   1. 缺失 SSO_ISSUER;
 *   2. clients.json 的 client_secret 引用未设置的 ${ENV:...} 变量;
 *   3. clients.json 的 client_secret 为空串;
 *   4. 公共客户端(public=true)配置了非空 client_secret(互斥,fail-closed);
 *   5. public 字段非布尔值。
 * 另加一条正例:public=true 的公共客户端不带 client_secret 也必须正常启动(改用 PKCE)。
 * 每个负例都要求:非 0 退出、从未绑定端口、无启动成功日志、输出点名问题变量/中文提示。
 * 脚本不需要任何真实密钥,并自行清理临时目录。
 */
import { spawn } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import net from 'node:net'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const NODE = process.execPath
const STARTUP_MARK = '统一认证服务已启动'
const CASE_TIMEOUT_MS = 15_000

/** 脚本自行管理的环境变量:先清空,避免宿主机环境污染导致用例不成立 */
const MANAGED_ENV = [
  'SSO_ISSUER', 'SSO_PORT', 'SSO_DATA_DIR', 'SSO_KEYS_DIR', 'SSO_CLIENTS_PATH',
  'FILE_USERS_PATH', 'LDAP_URL', 'LDAP_BIND_DN', 'LDAP_BIND_PASSWORD', 'LDAP_BASE_DN',
  'SSO_STRICT_MISSING_SECRET'
]

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/** 申请一个当前空闲的端口,用于证伪"服务曾监听" */
function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.once('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
  })
}

function canConnect(port, timeout = 200) {
  return new Promise((resolve) => {
    const sock = net.connect({ host: '127.0.0.1', port })
    let settled = false
    const finish = (ok) => {
      if (settled) return
      settled = true
      sock.destroy()
      resolve(ok)
    }
    sock.once('connect', () => finish(true))
    sock.once('error', () => finish(false))
    sock.setTimeout(timeout, () => finish(false))
  })
}

async function runCase({ name, setIssuer, clients, expected }) {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'sso-strict-'))
  const clientsPath = join(dir, 'clients.json')
  writeFileSync(clientsPath, JSON.stringify({ clients }, null, 2))
  writeFileSync(join(dir, 'users.json'), '[]')

  const env = { ...process.env }
  for (const key of MANAGED_ENV) delete env[key]
  Object.assign(env, {
    SSO_PORT: String(port),
    SSO_DATA_DIR: join(dir, 'data'),
    SSO_KEYS_DIR: join(dir, 'keys'),
    SSO_CLIENTS_PATH: clientsPath,
    FILE_USERS_PATH: join(dir, 'users.json')
  })
  if (setIssuer) env.SSO_ISSUER = `http://127.0.0.1:${port}`

  const child = spawn(NODE, ['--experimental-strip-types', 'src/index.ts'], {
    cwd: repoRoot,
    env,
    stdio: ['ignore', 'pipe', 'pipe']
  })

  let output = ''
  child.stdout.on('data', (chunk) => { output += chunk })
  child.stderr.on('data', (chunk) => { output += chunk })

  let bound = false
  let probing = true
  const probe = (async () => {
    while (probing) {
      if (await canConnect(port)) bound = true
      await delay(15)
    }
  })()

  const exited = new Promise((resolve) => {
    child.once('exit', (code, signal) => resolve({ code, signal }))
    child.once('error', (error) => resolve({ code: null, signal: null, error }))
  })

  let result = await Promise.race([exited, delay(CASE_TIMEOUT_MS).then(() => 'timeout')])
  if (result === 'timeout') {
    child.kill()
    await Promise.race([exited, delay(2_000).then(() => child.kill('SIGKILL'))])
    result = { code: null, signal: null, timedOut: true }
  }
  probing = false
  await probe
  if (await canConnect(port)) bound = true
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })

  const problems = []
  if (result.timedOut) problems.push(`未在 ${CASE_TIMEOUT_MS}ms 内退出`)
  if (result.error) problems.push(`进程启动失败:${result.error.message}`)
  if (result.code === 0) problems.push('退出码为 0(应非 0)')
  if (bound) problems.push('端口曾被绑定')
  if (output.includes(STARTUP_MARK)) problems.push('出现了启动成功日志')
  if (!expected.test(output)) problems.push(`输出未命中期望 ${expected}`)

  if (problems.length) {
    console.log(`FAIL | ${name} -> ${problems.join(';')}`)
    console.log(`       exit=${String(result.code)} signal=${String(result.signal)}`)
    for (const line of output.split('\n')) console.log(`       | ${line}`)
    return false
  }
  console.log(`PASS | ${name}(exit=${result.code},从未监听端口,信息命中)`)
  return true
}

/** 正例:给定 clients.json 必须能正常启动(用于公共客户端跳过 secret 校验的断言) */
async function runStartCase({ name, clients }) {
  const port = await freePort()
  const dir = mkdtempSync(join(tmpdir(), 'sso-strict-'))
  const clientsPath = join(dir, 'clients.json')
  writeFileSync(clientsPath, JSON.stringify({ clients }, null, 2))
  writeFileSync(join(dir, 'users.json'), '[]')

  const env = { ...process.env }
  for (const key of MANAGED_ENV) delete env[key]
  Object.assign(env, {
    SSO_PORT: String(port),
    SSO_ISSUER: `http://127.0.0.1:${port}`,
    SSO_DATA_DIR: join(dir, 'data'),
    SSO_KEYS_DIR: join(dir, 'keys'),
    SSO_CLIENTS_PATH: clientsPath,
    FILE_USERS_PATH: join(dir, 'users.json')
  })

  const child = spawn(NODE, ['--experimental-strip-types', 'src/index.ts'], {
    cwd: repoRoot,
    env,
    stdio: ['ignore', 'pipe', 'pipe']
  })

  let output = ''
  child.stdout.on('data', (chunk) => { output += chunk })
  child.stderr.on('data', (chunk) => { output += chunk })

  const deadline = Date.now() + CASE_TIMEOUT_MS
  while (!output.includes(STARTUP_MARK) && Date.now() < deadline) {
    await delay(15)
  }
  const started = output.includes(STARTUP_MARK)
  child.kill()
  await Promise.race([new Promise((resolve) => child.once('exit', resolve)), delay(2_000).then(() => child.kill('SIGKILL'))])
  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })

  if (!started) {
    console.log(`FAIL | ${name} -> 未在 ${CASE_TIMEOUT_MS}ms 内正常启动`)
    for (const line of output.split('\n')) console.log(`       | ${line}`)
    return false
  }
  console.log(`PASS | ${name}(正常启动,公共客户端无 secret 不拦截)`)
  return true
}

async function main() {
  const cases = [
    {
      name: '缺失 SSO_ISSUER 拒绝启动',
      setIssuer: false,
      clients: [{ client_id: 'ok', client_secret: 'literal-secret', redirect_uris: ['http://127.0.0.1/cb'] }],
      expected: /SSO_ISSUER/
    },
    {
      name: 'client_secret 引用未设置环境变量拒绝启动',
      setIssuer: true,
      clients: [{ client_id: 'strict-env', client_secret: '${ENV:SSO_STRICT_MISSING_SECRET}', redirect_uris: ['http://127.0.0.1/cb'] }],
      expected: /SSO_STRICT_MISSING_SECRET|未设置环境变量/
    },
    {
      name: '空 client_secret 拒绝启动',
      setIssuer: true,
      clients: [{ client_id: 'strict-empty', client_secret: '', redirect_uris: ['http://127.0.0.1/cb'] }],
      expected: /client_secret|缺失或为空/
    },
    {
      name: '公共客户端配置 client_secret 拒绝启动(fail-closed)',
      setIssuer: true,
      clients: [{ client_id: 'public-with-secret', public: true, client_secret: 'literal-secret', redirect_uris: ['http://127.0.0.1/cb'] }],
      expected: /不得配置 client_secret|public/
    },
    {
      name: 'public 非布尔值拒绝启动',
      setIssuer: true,
      clients: [{ client_id: 'public-bad-type', public: 'true', redirect_uris: ['http://127.0.0.1/cb'] }],
      expected: /public 必须是布尔值/
    }
  ]

  let ok = true
  for (const testCase of cases) {
    if (!(await runCase(testCase))) ok = false
  }
  if (!(await runStartCase({
    name: '公共客户端(public=true)无 secret 允许启动',
    clients: [
      { client_id: 'public-ok', public: true, redirect_uris: ['http://127.0.0.1/cb'] }
    ]
  }))) ok = false
  if (!ok) {
    console.log('\n严格配置检查失败:存在弱配置仍能启动(或未点名问题变量)')
    process.exit(1)
  }
  console.log('\n严格配置检查通过:三类弱配置均在监听端口前被拒绝;公共客户端无 secret 正常启动')
}

main().catch((error) => {
  console.error('check-strict-config error:', error)
  process.exit(1)
})
