/**
 * 模拟钉钉开放平台(仅烟测用):
 * - /login/oauth2/auth          扫码页:立即"扫码成功",302 回 SSO callback(authCode)
 * - /__set_next_user            测试钩子:切换下一个"扫码"的用户(active/disabled 两种场景)
 * - /v1.0/oauth2/userAccessToken  authCode → 用户 accessToken(真实响应不含 unionId)
 * - /v1.0/oauth2/accessToken    企业 app token
 * - /v1.0/contact/users/me      用户信息(unionId/昵称/手机号)
 * - /topapi/user/getbyunionid   unionId → userid
 */
import { createServer } from 'node:http'

/** 当前"扫码"的用户:默认张三(在职);可切换李四(已禁用) */
let nextUser = 'active'

const USERS = {
  active: { unionId: 'union-10003', userid: '10003', name: '王五', mobile: '13800000003' },
  disabled: { unionId: 'union-10002', userid: '10002', name: '李四', mobile: '13800000002' }
}

const json = (res, status, body) => {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(body))
}

const server = createServer((req, res) => {
  const url = new URL(req.url, 'http://local')
  const path = url.pathname

  if (path === '/__set_next_user') {
    nextUser = url.searchParams.get('user') ?? 'active'
    return json(res, 200, { nextUser })
  }

    if (path === '/login/oauth2/auth' && req.method === 'GET') {
    // 模拟用户瞬间扫码确认:302 回 SSO callback
    const redirectUri = url.searchParams.get('redirect_uri') ?? ''
    const state = url.searchParams.get('state') ?? ''
    const sep = redirectUri.includes('?') ? '&' : '?'
    res.writeHead(302, { Location: `${redirectUri}${sep}authCode=mock-auth-${nextUser}&state=${encodeURIComponent(state)}` })
    return res.end()
  }

  if (path === '/v1.0/oauth2/userAccessToken' && req.method === 'POST') {
    return json(res, 200, { accessToken: `mock-ut-${nextUser}`, expireIn: 7200 })
  }

  if (path === '/v1.0/oauth2/accessToken' && req.method === 'POST') {
    return json(res, 200, { accessToken: 'mock-app-token', expireIn: 7200 })
  }

  if (path === '/v1.0/contact/users/me' && req.method === 'GET') {
    const u = USERS[nextUser]
    return json(res, 200, { unionId: u.unionId, nick: u.name, mobile: u.mobile })
  }

  if (path === '/topapi/user/getbyunionid' && req.method === 'POST') {
    const u = USERS[nextUser]
    return json(res, 200, { errcode: 0, result: { userid: u.userid } })
  }

  json(res, 404, { error: 'not found' })
})

const port = Number(process.env.MOCK_DINGTALK_PORT ?? 19080)
server.listen(port, '127.0.0.1', () => {
  console.log(`[mock-dingtalk] :${port}`)
})
