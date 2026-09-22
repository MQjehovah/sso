import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const MANAGED = ['SSO_ACCESS_TOKEN_TTL_SECONDS', 'SSO_ID_TOKEN_TTL_SECONDS', 'SSO_KEY_RETIRE_AFTER_HOURS', 'SSO_EXCHANGE_TTL']

/**
 * config.ts 是模块单例,导入即求值,无法在同一进程里测多组环境变量。
 * 因此在子进程中导入并打印目标字段;非法值会让导入抛错并以非 0 退出。
 */
function readConfig(overrides: Record<string, string>, expr: string) {
  const env = { ...process.env } as Record<string, string>
  for (const k of MANAGED) delete env[k]
  Object.assign(env, overrides)
  const code = `import('./src/config.ts').then(m => console.log(${expr}))`
  return spawnSync(process.execPath, ['--experimental-strip-types', '-e', code], {
    cwd: repoRoot,
    env,
    encoding: 'utf-8'
  })
}

const accessTtl = 'm.config.accessTokenTtlSeconds'

test('未设置时使用默认值 600', () => {
  const r = readConfig({}, accessTtl)
  assert.equal(r.status, 0, r.stderr)
  assert.equal(r.stdout.trim(), '600')
})

test('空串不产生 0,回落默认值 600', () => {
  const r = readConfig({ SSO_ACCESS_TOKEN_TTL_SECONDS: '' }, accessTtl)
  assert.equal(r.status, 0, r.stderr)
  assert.equal(r.stdout.trim(), '600')
})

test('合法数字被采用', () => {
  const r = readConfig({ SSO_ACCESS_TOKEN_TTL_SECONDS: '3600' }, accessTtl)
  assert.equal(r.status, 0, r.stderr)
  assert.equal(r.stdout.trim(), '3600')
})

test('非数字快速失败且错误信息含变量名', () => {
  const r = readConfig({ SSO_ACCESS_TOKEN_TTL_SECONDS: 'abc' }, accessTtl)
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /SSO_ACCESS_TOKEN_TTL_SECONDS/)
})

test('0 低于最小值,快速失败', () => {
  const r = readConfig({ SSO_ACCESS_TOKEN_TTL_SECONDS: '0' }, accessTtl)
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /SSO_ACCESS_TOKEN_TTL_SECONDS/)
})

test('keyRetireAfterHours 允许 0(立即退休)', () => {
  const r = readConfig({ SSO_KEY_RETIRE_AFTER_HOURS: '0' }, 'm.config.keyRetireAfterHours')
  assert.equal(r.status, 0, r.stderr)
  assert.equal(r.stdout.trim(), '0')
})

test('SSO_EXCHANGE_TTL 未设置时默认 3600', () => {
  const r = readConfig({}, 'm.config.exchangeTtlSeconds')
  assert.equal(r.status, 0, r.stderr)
  assert.equal(r.stdout.trim(), '3600')
})

test('SSO_EXCHANGE_TTL 合法数字被采用', () => {
  const r = readConfig({ SSO_EXCHANGE_TTL: '90' }, 'm.config.exchangeTtlSeconds')
  assert.equal(r.status, 0, r.stderr)
  assert.equal(r.stdout.trim(), '90')
})

test('SSO_EXCHANGE_TTL 非数字快速失败且错误信息含变量名', () => {
  const r = readConfig({ SSO_EXCHANGE_TTL: 'abc' }, 'm.config.exchangeTtlSeconds')
  assert.notEqual(r.status, 0)
  assert.match(r.stderr, /SSO_EXCHANGE_TTL/)
})
