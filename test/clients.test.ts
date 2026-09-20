import { test, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { expandSecret } from '../src/clients.ts'

afterEach(() => {
  delete process.env.TEST_SECRET_X
  delete process.env.TEST_SECRET_EMPTY
  delete process.env.TEST_SECRET_MISSING
  delete process.env.TEST_SECRET_BLANK
})

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
