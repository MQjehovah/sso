import { test } from 'node:test'
import assert from 'node:assert/strict'
import { clientIp } from '../src/protocol.ts'

interface FakeReq {
  socket: { remoteAddress?: string }
  headers: Record<string, string | string[] | undefined>
}

function req(headers: Record<string, string | string[] | undefined>, remoteAddress = '10.0.0.1'): FakeReq {
  return { socket: { remoteAddress }, headers }
}

function withEnv(vars: Record<string, string | undefined>, fn: () => void): void {
  const saved: Record<string, string | undefined> = {}
  for (const k of Object.keys(vars)) saved[k] = process.env[k]
  for (const [k, v] of Object.entries(vars)) {
    if (v === undefined) delete process.env[k]
    else process.env[k] = v
  }
  try {
    fn()
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
}

test('trustProxy 关闭(默认):忽略伪造的转发头, 用 socket 地址', () => {
  withEnv({ SSO_TRUST_PROXY: undefined }, () => {
    assert.equal(clientIp(req({ 'x-real-ip': '203.0.113.9', 'x-forwarded-for': '198.51.100.1, 203.0.113.9' })), '10.0.0.1')
  })
})

test('trustProxy 开启:x-real-ip 优先于 x-forwarded-for', () => {
  withEnv({ SSO_TRUST_PROXY: 'true' }, () => {
    assert.equal(clientIp(req({ 'x-real-ip': '203.0.113.9', 'x-forwarded-for': '198.51.100.1' })), '203.0.113.9')
  })
})

test('trustProxy 开启:无 x-real-ip 时取 x-forwarded-for 最后一段', () => {
  withEnv({ SSO_TRUST_PROXY: 'true' }, () => {
    assert.equal(clientIp(req({ 'x-forwarded-for': '198.51.100.1, 203.0.113.9' })), '203.0.113.9')
  })
})

test('trustProxy 开启:非法头值回退 socket(防头部注入)', () => {
  withEnv({ SSO_TRUST_PROXY: 'true' }, () => {
    assert.equal(clientIp(req({ 'x-real-ip': 'evil, 1.2.3.4' })), '10.0.0.1')
    assert.equal(clientIp(req({ 'x-forwarded-for': 'not-an-ip' })), '10.0.0.1')
  })
})

test('trustProxy 开启:合法 IPv6 采用', () => {
  withEnv({ SSO_TRUST_PROXY: 'true' }, () => {
    assert.equal(clientIp(req({ 'x-real-ip': '2001:db8::1' })), '2001:db8::1')
  })
})

test('trustProxy 开启:头缺失回退 socket', () => {
  withEnv({ SSO_TRUST_PROXY: 'true' }, () => {
    assert.equal(clientIp(req({})), '10.0.0.1')
    assert.equal(clientIp({ socket: {}, headers: {} }), 'unknown')
  })
})

test('SSO_TRUST_PROXY 大小写与空格容错', () => {
  withEnv({ SSO_TRUST_PROXY: ' TRUE ' }, () => {
    assert.equal(clientIp(req({ 'x-real-ip': '203.0.113.9' })), '203.0.113.9')
  })
})
