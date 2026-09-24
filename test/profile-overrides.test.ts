import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { applyProfileOverrides } from '../src/directory.ts'
import type { DirectoryUser } from '../src/directory.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const SUB = '202202100024'

const BASE: DirectoryUser = {
  sub: SUB, name: '季明清', dept: '旧部门', email: 'old@corp.com', mobile: '13900000000',
  dingtalkUserId: 'old-dt', status: 'active'
}

const OVERRIDE = {
  [SUB]: { name: '季明清', dept: '应用软件部', mobile: '13800000000', email: 'a@b.c', dingtalkUserId: '1642483198771392' }
}

// ---- applyProfileOverrides(纯函数) ----

test('命中 sub:非空覆盖 name/dept/mobile/email/dingtalkUserId', () => {
  const u = applyProfileOverrides(BASE, OVERRIDE)
  assert.ok(u)
  assert.equal(u.name, '季明清')
  assert.equal(u.dept, '应用软件部')
  assert.equal(u.mobile, '13800000000')
  assert.equal(u.email, 'a@b.c')
  assert.equal(u.dingtalkUserId, '1642483198771392')
  assert.equal(u.sub, SUB, 'sub 不因映射改变')
  assert.equal(u.status, 'active', '未覆盖字段保持原值')
})

test('空串不覆盖:保留目录原值', () => {
  const u = applyProfileOverrides(BASE, { [SUB]: { name: '', dept: '', mobile: '', email: '', dingtalkUserId: '' } })
  assert.deepEqual(u, BASE)
})

test('未命中 sub:原样返回(不改写对象)', () => {
  const u = applyProfileOverrides(BASE, { '9999': { mobile: '13800000000' } })
  assert.equal(u, BASE)
})

test('目录无结果(null)直接返回 null', () => {
  assert.equal(applyProfileOverrides(null, OVERRIDE), null)
})

test('目录 dingtalkUserId 为空串时,覆盖后仍为 string', () => {
  const u = applyProfileOverrides({ ...BASE, dingtalkUserId: '' }, { [SUB]: { mobile: '13800000000' } })
  assert.equal(typeof u?.dingtalkUserId, 'string')
  assert.equal(u?.dingtalkUserId, '')
})

// ---- SSO_PROFILE_OVERRIDES 解析(子进程,config 为模块单例) ----

function readOverrides(raw: string | undefined) {
  const env = { ...process.env } as Record<string, string>
  if (raw === undefined) delete env.SSO_PROFILE_OVERRIDES
  else env.SSO_PROFILE_OVERRIDES = raw
  const code = "import('./src/config.ts').then(m => console.log(JSON.stringify(m.config.profileOverrides)))"
  return spawnSync(process.execPath, ['--experimental-strip-types', '-e', code], { cwd: repoRoot, env, encoding: 'utf-8' })
}

test('SSO_PROFILE_OVERRIDES 合法 JSON 被解析', () => {
  const r = readOverrides(JSON.stringify(OVERRIDE))
  assert.equal(r.status, 0, r.stderr)
  assert.deepEqual(JSON.parse(r.stdout.trim()), OVERRIDE)
})

test('SSO_PROFILE_OVERRIDES 未设置/空串 → 空映射', () => {
  for (const raw of [undefined, '', '   ']) {
    const r = readOverrides(raw)
    assert.equal(r.status, 0, r.stderr)
    assert.deepEqual(JSON.parse(r.stdout.trim()), {})
  }
})

test('SSO_PROFILE_OVERRIDES 非法 JSON → 空映射并告警,不崩溃', () => {
  const r = readOverrides('{not json')
  assert.equal(r.status, 0, r.stderr)
  assert.deepEqual(JSON.parse(r.stdout.trim()), {})
  assert.match(r.stderr, /SSO_PROFILE_OVERRIDES/)
})

test('SSO_PROFILE_OVERRIDES 顶层非对象(数组)→ 空映射并告警', () => {
  const r = readOverrides('[1,2]')
  assert.equal(r.status, 0, r.stderr)
  assert.deepEqual(JSON.parse(r.stdout.trim()), {})
  assert.match(r.stderr, /SSO_PROFILE_OVERRIDES/)
})

test('SSO_PROFILE_OVERRIDES 值为非字符串 → 整体空并告警', () => {
  const r = readOverrides(JSON.stringify({ [SUB]: { mobile: 13800000000 } }))
  assert.equal(r.status, 0, r.stderr)
  assert.deepEqual(JSON.parse(r.stdout.trim()), {})
  assert.match(r.stderr, /SSO_PROFILE_OVERRIDES/)
})

// ---- 目录查询入口应用映射(子进程,文件目录) ----

const FILE_USERS = [
  { sub: SUB, name: '季明清', dept: '旧部门', email: 'old@corp.com', mobile: '13900000000', dingtalkUserId: 'old-dt', status: 'active' }
]

function directoryLookup(overrides: string | undefined, expr: string) {
  const dir = mkdtempSync(join(tmpdir(), 'sso-overrides-'))
  try {
    const path = join(dir, 'users.json')
    writeFileSync(path, JSON.stringify(FILE_USERS), 'utf-8')
    const env = { ...process.env } as Record<string, string>
    delete env.LDAP_URL
    env.FILE_USERS_PATH = path
    if (overrides === undefined) delete env.SSO_PROFILE_OVERRIDES
    else env.SSO_PROFILE_OVERRIDES = overrides
    const code = `import('./src/directory.ts').then(async m => { const d = m.createDirectory(); console.log(JSON.stringify(await d.${expr})) })`
    return spawnSync(process.execPath, ['--experimental-strip-types', '-e', code], { cwd: repoRoot, env, encoding: 'utf-8' })
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

test('文件目录 findByIdentifier:命中 sub 时返回覆盖后的 dingtalkUserId/mobile/dept', () => {
  const r = directoryLookup(JSON.stringify(OVERRIDE), `findByIdentifier('${SUB}')`)
  assert.equal(r.status, 0, r.stderr)
  const u = JSON.parse(r.stdout.trim())
  assert.equal(u.dingtalkUserId, '1642483198771392')
  assert.equal(u.mobile, '13800000000')
  assert.equal(u.dept, '应用软件部')
})

test('文件目录 findByIdentifier:按原手机号查到后同样应用覆盖', () => {
  const r = directoryLookup(JSON.stringify(OVERRIDE), "findByIdentifier('13900000000')")
  assert.equal(r.status, 0, r.stderr)
  const u = JSON.parse(r.stdout.trim())
  assert.equal(u.sub, SUB)
  assert.equal(u.mobile, '13800000000')
})

test('文件目录 findByDingtalkUserId:补充映射覆盖原钉钉号', () => {
  const r = directoryLookup(JSON.stringify(OVERRIDE), "findByDingtalkUserId('old-dt')")
  assert.equal(r.status, 0, r.stderr)
  const u = JSON.parse(r.stdout.trim())
  assert.equal(u.dingtalkUserId, '1642483198771392')
})

test('补充映射非法 JSON:目录行为不变(仍按原值返回)', () => {
  const r = directoryLookup('{bad', `findByIdentifier('${SUB}')`)
  assert.equal(r.status, 0, r.stderr)
  assert.deepEqual(JSON.parse(r.stdout.trim()), FILE_USERS[0])
  assert.match(r.stderr, /SSO_PROFILE_OVERRIDES/)
})

test('补充映射为空:目录行为不变', () => {
  const r = directoryLookup(undefined, `findByIdentifier('${SUB}')`)
  assert.equal(r.status, 0, r.stderr)
  assert.deepEqual(JSON.parse(r.stdout.trim()), FILE_USERS[0])
})
