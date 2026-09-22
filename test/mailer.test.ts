import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createMailer } from '../src/mailer.ts'
import type { MailerConfig } from '../src/mailer.ts'

const dir = mkdtempSync(join(tmpdir(), 'sso-mailer-'))

after(() => {
  rmSync(dir, { recursive: true, force: true })
})

const SMTP = { host: 'smtp.corp.com', port: 465, secure: true, username: 'sso@corp.com', password: 'secret', fromName: '零号员工', from: '' }
const EMPTY_CFG: MailerConfig = { smtp: { host: '', port: 465, secure: true, username: '', password: '', fromName: '零号员工', from: '' } }

function cfgOf(over: Partial<MailerConfig['smtp']> = {}): MailerConfig {
  return { smtp: { ...SMTP, ...over } }
}

/** 在指定环境变量下执行并恢复原值 */
async function withEnv(vars: Record<string, string | undefined>, fn: () => Promise<void>): Promise<void> {
  const saved: Record<string, string | undefined> = {}
  for (const k of Object.keys(vars)) saved[k] = process.env[k]
  Object.assign(process.env, vars)
  try {
    await fn()
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
}

test('未配置 SMTP 时 isConfigured=false 且发送抛错', async () => {
  const mailer = createMailer({ cfg: EMPTY_CFG })
  assert.equal(mailer.isConfigured(), false)
  await assert.rejects(() => mailer.sendVerificationCode({ to: 'a@b.c', code: '123456', ttlMinutes: 10 }), /邮件服务未配置/)
  await assert.rejects(() => mailer.sendPasswordChangedNotice({ to: 'a@b.c' }), /邮件服务未配置/)
})

test('注入 sendMailImpl 捕获验证码邮件的 from/收件人/主题/正文', async () => {
  const sent: Array<{ from: string; to: string; subject: string; text: string }> = []
  const mailer = createMailer({ cfg: cfgOf(), sendMailImpl: async (msg) => { sent.push(msg) } })
  assert.equal(mailer.isConfigured(), true)
  await mailer.sendVerificationCode({ to: 'u@corp.com', code: '654321', ttlMinutes: 10 })
  assert.equal(sent.length, 1)
  assert.equal(sent[0].from, '"零号员工" <sso@corp.com>')
  assert.equal(sent[0].to, 'u@corp.com')
  assert.equal(sent[0].subject, '【零号员工】密码重置验证码')
  assert.match(sent[0].text, /654321/)
  assert.match(sent[0].text, /10 分钟/)
  assert.match(sent[0].text, /若非本人操作请忽略本邮件/)
})

test('from 配置优先于 username,fromName 可变', async () => {
  const sent: Array<{ from: string }> = []
  const mailer = createMailer({ cfg: cfgOf({ fromName: 'IT 支持', from: 'noreply@corp.com' }), sendMailImpl: async (msg) => { sent.push(msg) } })
  await mailer.sendPasswordChangedNotice({ to: 'u@corp.com' })
  assert.equal(sent[0].from, '"IT 支持" <noreply@corp.com>')
})

test('密码变更通知使用约定主题', async () => {
  const sent: Array<{ to: string; subject: string; text: string }> = []
  const mailer = createMailer({ cfg: cfgOf(), sendMailImpl: async (msg) => { sent.push(msg) } })
  await mailer.sendPasswordChangedNotice({ to: 'u@corp.com' })
  assert.equal(sent.length, 1)
  assert.equal(sent[0].to, 'u@corp.com')
  assert.equal(sent[0].subject, '【零号员工】登录密码已变更')
})

test('非生产 + SSO_SMTP_FAKE_CAPTURE 落盘一行 JSON(含验证码)', async () => {
  const file = join(dir, 'capture.jsonl')
  await withEnv({ NODE_ENV: 'test', SSO_SMTP_FAKE_CAPTURE: file }, async () => {
    const mailer = createMailer({ cfg: EMPTY_CFG })
    assert.equal(mailer.isConfigured(), true)
    await mailer.sendVerificationCode({ to: 'cap@corp.com', code: '112233', ttlMinutes: 10 })
  })
  const lines = readFileSync(file, 'utf-8').trim().split('\n')
  assert.equal(lines.length, 1)
  const rec = JSON.parse(lines[0]) as { to: string; subject: string; text: string }
  assert.equal(rec.to, 'cap@corp.com')
  assert.match(rec.text, /112233/)
  // Windows 上 chmod/mode 语义不可靠,仅在 POSIX 断言 0600
  if (process.platform !== 'win32') assert.equal(statSync(file).mode & 0o777, 0o600)
})

test('生产环境忽略 SSO_SMTP_FAKE_CAPTURE:未配置、不写文件、告警一次', async () => {
  const file = join(dir, 'prod-capture.jsonl')
  const warns: string[] = []
  const origWarn = console.warn
  console.warn = (...args: unknown[]) => { warns.push(args.map(String).join(' ')) }
  try {
    await withEnv({ NODE_ENV: 'production', SSO_SMTP_FAKE_CAPTURE: file }, async () => {
      const mailer = createMailer({ cfg: EMPTY_CFG })
      assert.equal(mailer.isConfigured(), false)
      await assert.rejects(() => mailer.sendVerificationCode({ to: 'x@corp.com', code: '000000', ttlMinutes: 10 }), /邮件服务未配置/)
      await assert.rejects(() => mailer.sendPasswordChangedNotice({ to: 'x@corp.com' }), /邮件服务未配置/)
    })
  } finally {
    console.warn = origWarn
  }
  assert.equal(existsSync(file), false)
  assert.equal(warns.filter((w) => w.includes('SSO_SMTP_FAKE_CAPTURE')).length, 1)
})
