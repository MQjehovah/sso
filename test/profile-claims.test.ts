import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { decodeJwt } from 'jose'
import type { PendingTx } from '../src/store.ts'

/**
 * 个人信息 claim 链路:目录 mobile → 会话/授权码/refresh 记录 → id_token/access_token/userinfo。
 * store.ts 与 protocol.ts 均在导入时捕获 config,故先设置环境变量再动态 import。
 */
let store: typeof import('../src/store.ts')
let protocol: typeof import('../src/protocol.ts')

const SUB = '202202100024'
const MOBILE = '13800000000'
const REDIRECT = 'http://127.0.0.1:19990/cb'

const clientReq = () => ({ client_id: 'test-web', client_secret: 'test-secret', redirect_uri: REDIRECT })

before(async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sso-claims-'))
  writeFileSync(join(dir, 'clients.json'), JSON.stringify({
    clients: [
      { client_id: 'test-web', client_secret: 'test-secret', redirect_uris: [REDIRECT], allowed_audiences: ['router'] }
    ]
  }), 'utf-8')
  process.env.SSO_DATA_DIR = join(dir, 'data')
  process.env.SSO_KEYS_DIR = join(dir, 'keys')
  process.env.SSO_ISSUER = 'http://127.0.0.1:18091'
  process.env.SSO_CLIENTS_PATH = join(dir, 'clients.json')
  delete process.env.LDAP_URL
  store = await import('../src/store.ts')
  protocol = await import('../src/protocol.ts')
})

type TokenReq = Parameters<typeof protocol.handleToken>[0]
type TokenRes = Parameters<typeof protocol.handleToken>[1]

function fakeRequest(fields: Record<string, string>): TokenReq {
  const raw = Buffer.from(new URLSearchParams(fields).toString(), 'utf-8')
  return {
    method: 'POST',
    socket: { remoteAddress: '127.0.0.1' },
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    async *[Symbol.asyncIterator]() { yield raw }
  } as unknown as TokenReq
}

function fakeResponse(): { res: TokenRes; status: () => number; body: () => string } {
  let status = 0
  let payload = ''
  const res = {
    writeHead: (code: number) => { status = code },
    end: (chunk?: string) => { payload = chunk ?? '' },
    setHeader: () => {}
  } as unknown as TokenRes
  return { res, status: () => status, body: () => payload }
}

/** 用给定目录字段建会话并签授权码,模拟登录后换 token 的输入 */
function issueCodeFor(user: { email?: string; mobile?: string; dingtalkUserId?: string }): string {
  const session = store.createSession(SUB, '季明清', '应用软件部', 'pwd', user.dingtalkUserId, user.email, user.mobile)
  const tx: PendingTx = {
    id: `tx-${Math.random().toString(16).slice(2)}`,
    client_id: 'test-web',
    redirect_uri: REDIRECT,
    scope: 'openid profile',
    nonce: 'n-claims',
    created_at: Date.now()
  }
  store.putTx(tx)
  return store.issueCode(tx, session)
}

async function postToken(fields: Record<string, string>): Promise<{ status: number; body: Record<string, string> }> {
  const { res, status, body } = fakeResponse()
  await protocol.handleToken(fakeRequest(fields), res)
  return { status: status(), body: body() ? JSON.parse(body()) : {} }
}

async function grant(code: string) {
  return postToken({ grant_type: 'authorization_code', code, ...clientReq() })
}

async function userinfo(accessToken: string) {
  const { res, status, body } = fakeResponse()
  const req = { headers: { authorization: `Bearer ${accessToken}` } } as unknown as Parameters<typeof protocol.handleUserinfo>[0]
  await protocol.handleUserinfo(req, res)
  return { status: status(), body: body() ? JSON.parse(body()) : {} }
}

test('discovery claims_supported 声明 email 与 mobile', async () => {
  const { res, status, body } = fakeResponse()
  await protocol.handleDiscovery(res)
  assert.equal(status(), 200)
  const meta = JSON.parse(body())
  assert.ok(meta.claims_supported.includes('email'))
  assert.ok(meta.claims_supported.includes('mobile'))
})

test('授权码换 token:id_token/access_token/userinfo 携带 mobile', async () => {
  const code = issueCodeFor({ mobile: MOBILE, email: 'a@b.c', dingtalkUserId: '1642483198771392' })
  const r = await grant(code)
  assert.equal(r.status, 200, JSON.stringify(r.body))
  const id = decodeJwt(r.body.id_token)
  const at = decodeJwt(r.body.access_token)
  assert.equal(id.mobile, MOBILE)
  assert.equal(at.mobile, MOBILE)
  assert.equal(id.email, 'a@b.c')
  assert.equal(id.dingtalk, '1642483198771392')
  assert.equal(id.nonce, 'n-claims')

  const ui = await userinfo(r.body.access_token)
  assert.equal(ui.status, 200)
  assert.equal(ui.body.mobile, MOBILE)
  assert.equal(ui.body.email, 'a@b.c')
})

test('refresh 轮换:新 token 组保留 mobile(经 refresh 记录透传)', async () => {
  const code = issueCodeFor({ mobile: MOBILE })
  const first = await grant(code)
  assert.equal(first.status, 200, JSON.stringify(first.body))
  const second = await postToken({ grant_type: 'refresh_token', refresh_token: first.body.refresh_token, ...clientReq() })
  assert.equal(second.status, 200, JSON.stringify(second.body))
  assert.equal(decodeJwt(second.body.id_token).mobile, MOBILE)
  assert.equal(decodeJwt(second.body.access_token).mobile, MOBILE)
})

test('目录未登记 mobile 时:id_token/access_token/userinfo 均不下发该 claim', async () => {
  const code = issueCodeFor({ email: 'a@b.c' })
  const r = await grant(code)
  assert.equal(r.status, 200, JSON.stringify(r.body))
  assert.ok(!('mobile' in decodeJwt(r.body.id_token)))
  assert.ok(!('mobile' in decodeJwt(r.body.access_token)))
  const ui = await userinfo(r.body.access_token)
  assert.ok(!('mobile' in ui.body))
})

test('token-exchange 继承 mobile claim', async () => {
  const code = issueCodeFor({ mobile: MOBILE })
  const first = await grant(code)
  const ex = await postToken({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: first.body.id_token,
    audience: 'router',
    ...clientReq()
  })
  assert.equal(ex.status, 200, JSON.stringify(ex.body))
  const claims = decodeJwt(ex.body.access_token)
  assert.equal(claims.aud, 'router')
  assert.equal(claims.mobile, MOBILE)
})
