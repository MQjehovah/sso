import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mapLdapEntry } from '../src/directory.ts'
import type { LdapAttrs } from '../src/directory.ts'

/**
 * LDAP 条目映射必须是「属性名全来自配置」:mobile 尤其不能写死 e.mobile,
 * 否则 LDAP_ATTR_MOBILE 指向自定义属性(如 mobileNumber)时永远取不到值。
 */
const ATTRS: LdapAttrs = {
  sub: 'employeeNumber',
  name: 'displayName',
  dept: 'departmentNumber',
  mobile: 'mobileNumber',
  mail: 'mail',
  dingtalk: 'description',
  status: 'aiStatus'
}

const ENTRY: Record<string, unknown> = {
  employeeNumber: '202202100024',
  displayName: '季明清',
  departmentNumber: '应用软件部',
  mobileNumber: '13800000000',
  mobile: '13900000000', // 干扰项:未配置的默认属性名不得被读取
  mail: '  A@B.C  ',
  description: '1642483198771392',
  aiStatus: 'active',
  dn: 'uid=202202100024,ou=people,dc=corp'
}

test('mobile 取自 LDAP_ATTR_MOBILE 对应属性,而非硬编码 e.mobile', () => {
  const u = mapLdapEntry(ENTRY, ATTRS, 'disabled')
  assert.equal(u.mobile, '13800000000')
  assert.equal(u.sub, '202202100024')
  assert.equal(u.name, '季明清')
  assert.equal(u.dept, '应用软件部')
  assert.equal(u.email, 'a@b.c', 'email 仍按配置属性并裁剪小写')
  assert.equal(u.dingtalkUserId, '1642483198771392')
  assert.equal(u.status, 'active')
  assert.equal(u.dn, 'uid=202202100024,ou=people,dc=corp')
})

test('默认属性布局(mobile/mail/dingtalkUserId)同样可用', () => {
  const attrs: LdapAttrs = {
    sub: 'employeeNumber', name: 'cn', dept: 'departmentNumber',
    mobile: 'mobile', mail: 'mail', dingtalk: 'dingtalkUserId', status: 'aiStatus'
  }
  const u = mapLdapEntry(
    { employeeNumber: '1', cn: '张三', departmentNumber: '平台组', mobile: '13800000001', mail: 'x@y.z', dingtalkUserId: 'dt-1', aiStatus: 'active' },
    attrs,
    'disabled'
  )
  assert.equal(u.mobile, '13800000001')
  assert.equal(u.dingtalkUserId, 'dt-1')
})

test('mobile 缺失/空值时返回 undefined(不产生空串 claim)', () => {
  const u = mapLdapEntry({ employeeNumber: '1', displayName: '张三' }, ATTRS, 'disabled')
  assert.equal(u.mobile, undefined)
  const empty = mapLdapEntry({ employeeNumber: '1', displayName: '张三', mobileNumber: '' }, ATTRS, 'disabled')
  assert.equal(empty.mobile, undefined)
})

test('name 配置属性缺失时回落 cn;status 命中禁用标记 → disabled', () => {
  const u = mapLdapEntry({ employeeNumber: '1', cn: '张三', aiStatus: 'ACCOUNT-DISABLED' }, ATTRS, 'disabled')
  assert.equal(u.name, '张三')
  assert.equal(u.status, 'disabled')
})
