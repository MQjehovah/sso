import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  PASSWORD_POLICY_HINT, checkPasswordStrength, describePasswordIssues, friendlyPasswordError
} from '../src/password-policy.ts'

// ---- checkPasswordStrength ----

test('checkPasswordStrength: 合规密码返回空数组', () => {
  assert.deepEqual(checkPasswordStrength('Abcdef1!'), [])
  assert.deepEqual(checkPasswordStrength('Newpass456!'), [])
})

test('checkPasswordStrength: 恰好 8 位合规通过, 7 位报不足', () => {
  assert.deepEqual(checkPasswordStrength('Abcde1!x'), [])
  assert.ok(checkPasswordStrength('Abcde1!').includes('不足 8 位'))
})

test('checkPasswordStrength: 逐项缺什么报什么', () => {
  assert.deepEqual(checkPasswordStrength('short'), ['不足 8 位', '缺大写字母', '缺数字', '缺特殊字符'])
  assert.deepEqual(checkPasswordStrength('abcdefg1!'), ['缺大写字母'])
  assert.deepEqual(checkPasswordStrength('ABCDEFG1!'), ['缺小写字母'])
  assert.deepEqual(checkPasswordStrength('Abcdefg!!'), ['缺数字'])
  assert.deepEqual(checkPasswordStrength('Abcdefg1'), ['缺特殊字符'])
})

test('checkPasswordStrength: 特殊字符定义宽松(常见符号与非字母数字均算)', () => {
  for (const special of ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '-', '+', '=', '[', ']', '{', '}', ';', ':', ',', '.', '<', '>', '?', '~', '|', '/', '\\', '`', '"', "'"]) {
    assert.deepEqual(checkPasswordStrength(`Abcdefg1${special}`), [], `特殊字符 ${special} 应被接受`)
  }
})

test('describePasswordIssues: 拼接为具体缺项提示', () => {
  assert.equal(
    describePasswordIssues(['不足 8 位', '缺大写字母', '缺数字', '缺特殊字符']),
    '新密码不符合要求: 不足 8 位、缺大写字母、缺数字、缺特殊字符'
  )
})

// ---- friendlyPasswordError ----

test('friendlyPasswordError: SynoSpecialChar → 特殊字符提示(0x13 不覆盖具体规则)', () => {
  assert.equal(
    friendlyPasswordError(new Error('设置密码失败: SynoSpecialChar Code: 0x13')),
    '新密码需包含特殊字符（如 !@#$%^&*）'
  )
})

test('friendlyPasswordError: SynoMixedCase → 大小写提示', () => {
  assert.equal(
    friendlyPasswordError(new Error('SynoMixedCase Code: 0x13')),
    '新密码需同时包含大写和小写字母'
  )
})

test('friendlyPasswordError: SynoDigit / SynoNumeric → 数字提示', () => {
  assert.equal(friendlyPasswordError(new Error('SynoDigit Code: 0x13')), '新密码需包含数字')
  assert.equal(friendlyPasswordError(new Error('SynoNumeric Code: 0x13')), '新密码需包含数字')
})

test('friendlyPasswordError: SynoTooShort / SynoPasswordLength → 长度提示', () => {
  assert.equal(friendlyPasswordError(new Error('SynoTooShort Code: 0x13')), '新密码长度不足')
  assert.equal(friendlyPasswordError(new Error('SynoPasswordLength Code: 0x13')), '新密码长度不足')
})

test('friendlyPasswordError: 仅 0x13(无 Syno token) → 域策略提示', () => {
  assert.equal(
    friendlyPasswordError(new Error('Constraint violation Code: 0x13')),
    `不符合域密码策略：${PASSWORD_POLICY_HINT}`
  )
})

test('friendlyPasswordError: 未知 Syno 规则 → 保留 token 便于定位', () => {
  assert.equal(
    friendlyPasswordError(new Error('SynoPasswordHistory Code: 0x13')),
    '不符合域密码策略（目录错误: SynoPasswordHistory）'
  )
})

test('friendlyPasswordError: 无 Syno 特征 → 原 message 原样返回', () => {
  assert.equal(friendlyPasswordError(new Error('LDAP 不可用')), 'LDAP 不可用')
  assert.equal(friendlyPasswordError('当前密码不正确'), '当前密码不正确')
})

test('friendlyPasswordError: 空/缺失错误 → 兜底文案, 不返回空串', () => {
  assert.equal(friendlyPasswordError(new Error('')), '设置密码失败, 请稍后重试或联系管理员')
  assert.equal(friendlyPasswordError(undefined), '设置密码失败, 请稍后重试或联系管理员')
})
