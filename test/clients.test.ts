import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { expandSecret } from '../src/clients.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const tmpDirs: string[] = []

afterEach(() => {
  delete process.env.TEST_SECRET_X
  delete process.env.TEST_SECRET_EMPTY
  delete process.env.TEST_SECRET_MISSING
  delete process.env.TEST_SECRET_BLANK
  for (const dir of tmpDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

/**
 * loadClients 是模块单例(30s 缓存),无法在同一进程里测多组配置;
 * 因此在子进程中以临时 clients.json 调用,非法配置会让进程以非 0 退出。
 * 成功时 stdout 打印加载后的客户端 JSON,便于断言 secret 是否被展开。
 */
function loadClientsWith(client: Record<string, unknown>) {
  const dir = mkdtempSync(join(tmpdir(), 'sso-clients-'))
  tmpDirs.push(dir)
  const path = join(dir, 'clients.json')
  writeFileSync(path, JSON.stringify({ clients: [client] }))
  return spawnSync(process.execPath, ['--experimental-strip-types', '-e', "import('./src/clients.ts').then(m => { const c = m.loadClients().get(process.argv[1]); console.log(JSON.stringify(c)) })", String(client.client_id)], {
    cwd: repoRoot,
    env: { ...process.env, SSO_CLIENTS_PATH: path },
    encoding: 'utf-8'
  })
}

/** 机密客户端(默认形态):恒定带 client_secret;用于 allowed_audiences 与 secret 校验类用例 */
function loadConfidentialWith(overrides: Record<string, unknown>) {
  return loadClientsWith({ client_id: 'test', client_secret: 's', redirect_uris: [], ...overrides })
}

test('${ENV:NAME} 占位被环境变量替换', () => {
  process.env.TEST_SECRET_X = 's3cret'
  assert.equal(expandSecret('${ENV:TEST_SECRET_X}'), 's3cret')
})

test('缺失的环境变量抛错', () => {
  delete process.env.TEST_SECRET_MISSING
  assert.throws(() => expandSecret('${ENV:TEST_SECRET_MISSING}'), /未设置环境变量/)
})

test('环境变量为空串抛错(避免空 secret 鉴权绕过)', () => {
  process.env.TEST_SECRET_EMPTY = ''
  assert.throws(() => expandSecret('${ENV:TEST_SECRET_EMPTY}'), /未设置环境变量/)
})

test('环境变量为空白串视为未设置并抛错', () => {
  process.env.TEST_SECRET_BLANK = '   '
  assert.throws(() => expandSecret('${ENV:TEST_SECRET_BLANK}'), /未设置环境变量/)
})

test('环境变量首尾空白被裁剪', () => {
  process.env.TEST_SECRET_X = '  s3cret  '
  assert.equal(expandSecret('${ENV:TEST_SECRET_X}'), 's3cret')
})

test('非法占位格式抛错', () => {
  for (const bad of ['${ENV:}', '${ENV:1x}', '${env:X}', ' ${ENV:X}']) {
    assert.throws(() => expandSecret(bad), /占位格式非法/, bad)
  }
})

test('非占位值原样返回', () => {
  assert.equal(expandSecret('plain'), 'plain')
})

test('allowed_audiences 未配置合法(不启用交换)', () => {
  const r = loadConfidentialWith({ allowed_audiences: undefined })
  assert.equal(r.status, 0, r.stderr)
})

test('allowed_audiences 为非数组抛错', () => {
  const r = loadConfidentialWith({ allowed_audiences: 'router' })
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /allowed_audiences 必须是非空字符串数组/)
})

test('allowed_audiences 为空数组抛错', () => {
  const r = loadConfidentialWith({ allowed_audiences: [] })
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /allowed_audiences 必须是非空字符串数组/)
})

test('allowed_audiences 含非字符串元素抛错', () => {
  const r = loadConfidentialWith({ allowed_audiences: ['router', 123] })
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /allowed_audiences 必须是非空字符串数组/)
})

test('allowed_audiences 含空串元素抛错', () => {
  const r = loadConfidentialWith({ allowed_audiences: [''] })
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /allowed_audiences 必须是非空字符串数组/)
})

test('公共客户端(public=true)无 client_secret 可加载', () => {
  const r = loadClientsWith({ client_id: 'pub', public: true, redirect_uris: [] })
  assert.equal(r.status, 0, r.stderr)
  const client = JSON.parse(r.stdout.trim())
  assert.equal(client.client_id, 'pub')
  assert.equal(client.client_secret, undefined)
})

test('公共客户端即使写了 client_secret 占位也不展开', () => {
  delete process.env.TEST_SECRET_MISSING
  const r = loadClientsWith({ client_id: 'pub', public: true, client_secret: '${ENV:TEST_SECRET_MISSING}', redirect_uris: [] })
  assert.equal(r.status, 0, r.stderr)
  const client = JSON.parse(r.stdout.trim())
  assert.equal(client.client_secret, '${ENV:TEST_SECRET_MISSING}')
})

test('公共客户端即使写了空 client_secret 也不报错', () => {
  const r = loadClientsWith({ client_id: 'pub', public: true, client_secret: '', redirect_uris: [] })
  assert.equal(r.status, 0, r.stderr)
})

test('非 public 缺 client_secret 仍抛错', () => {
  const r = loadClientsWith({ client_id: 'conf', redirect_uris: [] })
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /client_secret 缺失或为空/)
})

test('非 public 空 client_secret 仍抛错', () => {
  const r = loadClientsWith({ client_id: 'conf', client_secret: '', redirect_uris: [] })
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /client_secret 缺失或为空/)
})
