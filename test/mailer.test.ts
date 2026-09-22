import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/**
 * mailer 依赖 config 单例(导入即求值),为测"未配置"分支先清掉进程内可能的 SSO_SMTP_* 再动态导入。
 */
for (const k of Object.keys(process.env)) {
  if (k.startsWith('SSO_SMTP_')) delete process.env[k]
}

let createMailer: typeof import('../src/mailer.ts').createMailer
const dir = mkdtempSync(join(tmpdir(), 'sso-mailer-'))

before(async () => {
  createMailer = (await import('../src/mailer.ts')).createMailer
})

after(() => {
  rmSync(dir, { recursive: true, force: true })
})

test('未配置 SMTP 时 isConfigured=false 且发送抛错', async () => {
  const mailer = createMailer()
  assert.equal(mailer.isConfigured(), false)
  await assert.rejects(() => mailer.sendVerificationCode({ to: 'a@b.c', code: '123456', ttlMinutes: 10 }), /邮件服务未配置/)
  await assert.rejects(() => mailer.sendPasswordChangedNotice({ to: 'a@b.c' }), /邮件服务未配置/)
})

test('注入 sendMailImpl 捕获验证码邮件的收件人/主题/正文', async () => {
  const sent: Array<{ from: string; to: string; subject: string; text: string }> = []
  const mailer = createMailer({ sendMailImpl: async (msg) => { sent.push(msg) } })
  assert.equal(mailer.isConfigured(), true)
  await mailer.sendVerificationCode({ to: 'u@corp.com', code: '654321', ttlMinutes: 10 })
  assert.equal(sent.length, 1)
  assert.equal(sent[0].to, 'u@corp.com')
  assert.equal(sent[0].subject, '【零号员工】密码重置验证码')
  assert.match(sent[0].text, /654321/)
  assert.match(sent[0].text, /10 分钟/)
  assert.match(sent[0].text, /若非本人操作请忽略本邮件/)
})

test('密码变更通知使用约定主题', async () => {
  const sent: Array<{ to: string; subject: string; text: string }> = []
  const mailer = createMailer({ sendMailImpl: async (msg) => { sent.push(msg) } })
  await mailer.sendPasswordChangedNotice({ to: 'u@corp.com' })
  assert.equal(sent.length, 1)
  assert.equal(sent[0].to, 'u@corp.com')
  assert.equal(sent[0].subject, '【零号员工】登录密码已变更')
})

test('SSO_SMTP_FAKE_CAPTURE 落盘一行 JSON 且含验证码', async () => {
  const file = join(dir, 'capture.jsonl')
  process.env.SSO_SMTP_FAKE_CAPTURE = file
  try {
    const mailer = createMailer()
    assert.equal(mailer.isConfigured(), true)
    await mailer.sendVerificationCode({ to: 'cap@corp.com', code: '112233', ttlMinutes: 10 })
    const lines = readFileSync(file, 'utf-8').trim().split('\n')
    assert.equal(lines.length, 1)
    const rec = JSON.parse(lines[0]) as { to: string; subject: string; text: string }
    assert.equal(rec.to, 'cap@corp.com')
    assert.match(rec.text, /112233/)
  } finally {
    delete process.env.SSO_SMTP_FAKE_CAPTURE
  }
})
