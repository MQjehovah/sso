import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { config } from './config.ts'
import { loadClients } from './clients.ts'
import {
  handleAuthorize, handleDiscovery, handleDingtalkCallback, handleDingtalkStart,
  handleHome,
  handleJwks, handleLoginPage, handleLogout, handlePasswordLogin,
  handleProfile, handleProfilePassword, handleToken, handleUserinfo
} from './protocol.ts'
import { HttpError } from './errors.ts'

function html(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' })
  res.end(body)
}

function json(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' })
  res.end(JSON.stringify(payload))
}

async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', config.issuer)
  const path = url.pathname

  if (path === '/healthz') return json(res, 200, { status: 'ok' })

  if (path === '/') return handleHome(req, res)

  if (path === '/.well-known/openid-configuration') return handleDiscovery(res)
  if (path === '/.well-known/jwks.json') return handleJwks(res)

  if (path === '/authorize') return handleAuthorize(req, res, url)
  if (path === '/login' && req.method === 'GET') return handleLoginPage(req, res, url)
  if (path === '/login/password' && req.method === 'POST') return handlePasswordLogin(req, res, url)
  if (path === '/dingtalk/start') return handleDingtalkStart(res, url)
  if (path === '/dingtalk/callback') return handleDingtalkCallback(req, res, url)
  if (path === '/token' && req.method === 'POST') return handleToken(req, res)
  if (path === '/userinfo') return handleUserinfo(req, res)
  if (path === '/logout') return handleLogout(req, res, url)
  if (path === '/profile') return handleProfile(req, res)
  if (path === '/profile/password' && req.method === 'POST') return handleProfilePassword(req, res)

  html(res, 404, 'Not Found')
}

const server = createServer((req, res) => {
  route(req, res).catch((err: unknown) => {
    const status = err instanceof HttpError ? err.status : 500
    if (!res.headersSent) {
      if (req.url?.startsWith('/token') || req.url?.startsWith('/userinfo')) {
        json(res, status, { error: (err as Error).message })
      } else {
        html(res, status, `服务错误:${(err as Error).message}`)
      }
    } else {
      res.destroy()
    }
  })
})

// 启动自检:必需配置与客户端注册文件必须在监听端口前校验(弱配置直接退出,不占用端口)
const issuer = config.issuer
loadClients()

server.listen(config.port, '0.0.0.0', () => {
  console.log(`[sso] 统一认证服务已启动 ${issuer}(端口 ${config.port})`)
  const provider = process.env.LDAP_URL ? 'OpenLDAP' : '文件目录(开发模式)'
  console.log(`[sso] 用户目录:${provider} · 认证:钉钉扫码 + 账号密码(LDAP bind)`)
})

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => server.close(() => process.exit(0)))
}
