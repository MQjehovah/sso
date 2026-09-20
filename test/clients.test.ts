import { test } from 'node:test'
import assert from 'node:assert/strict'
import { expandSecret } from '../src/clients.ts'

test('${ENV:NAME} 占位被环境变量替换', () => {
  process.env.TEST_SECRET_X = 's3cret'
  assert.equal(expandSecret('${ENV:TEST_SECRET_X}'), 's3cret')
})

test('缺失的环境变量抛错', () => {
  delete process.env.TEST_SECRET_MISSING
  assert.throws(() => expandSecret('${ENV:TEST_SECRET_MISSING}'), /未设置环境变量/)
})

test('非占位值原样返回', () => {
  assert.equal(expandSecret('plain'), 'plain')
})
