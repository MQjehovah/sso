import { appendFileSync } from 'node:fs'
import { createTransport } from 'nodemailer'
import type { Transporter } from 'nodemailer'
import { config } from './config.ts'

/**
 * 邮件发送(nodemailer,SMTP 可选)。
 * - 未配置(SMTP host/username/password 缺任一)时自助重置降级提示,不影响 SSO 启动。
 * - 测试/烟测注入 sendMailImpl,或设 SSO_SMTP_FAKE_CAPTURE=<file> 以一行 JSON 追加捕获
 *   (仅非生产生效;生产环境忽略并告警一次)。
 */
export interface Mailer {
  isConfigured(): boolean
  sendVerificationCode(input: { to: string; code: string; ttlMinutes: number }): Promise<void>
  sendPasswordChangedNotice(input: { to: string }): Promise<void>
}

export type SendMailMessage = { from: string; to: string; subject: string; text: string }

/** 仅需 smtp 段,便于测试注入字面量(生产直接传 config) */
export type MailerConfig = Pick<typeof config, 'smtp'>

export function createMailer(deps?: { cfg?: MailerConfig; sendMailImpl?: (msg: SendMailMessage) => Promise<unknown> }): Mailer {
  let transport: Transporter | null = null
  let warnedFakeCaptureInProd = false
  const cfg = deps?.cfg ?? config

  /** 烟测捕获钩子:env 每次调用时读取;生产环境忽略(告警一次)并返回空 */
  function captureFile(): string {
    const file = (process.env.SSO_SMTP_FAKE_CAPTURE ?? '').trim()
    if (!file) return ''
    if ((process.env.NODE_ENV ?? '').trim().toLowerCase() === 'production') {
      if (!warnedFakeCaptureInProd) {
        warnedFakeCaptureInProd = true
        console.warn('[sso] 检测到 SSO_SMTP_FAKE_CAPTURE, 生产环境已忽略(该变量仅用于测试)')
      }
      return ''
    }
    return file
  }

  function isConfigured(): boolean {
    if (deps?.sendMailImpl) return true
    if (captureFile()) return true
    const s = cfg.smtp
    return !!s.host && !!s.username && !!s.password
  }

  async function sendMail(msg: { to: string; subject: string; text: string }): Promise<void> {
    const s = cfg.smtp
    const from = `"${s.fromName}" <${s.from || s.username}>`
    if (deps?.sendMailImpl) {
      await deps.sendMailImpl({ from, ...msg })
      return
    }
    const capture = captureFile()
    if (capture) {
      appendFileSync(capture, JSON.stringify(msg) + '\n', { encoding: 'utf-8', flag: 'a', mode: 0o600 })
      return
    }
    if (!s.host || !s.username || !s.password) throw new Error('邮件服务未配置')
    transport ??= createTransport({
      host: s.host,
      port: s.port,
      secure: s.secure,
      auth: { user: s.username, pass: s.password }
    })
    await transport.sendMail({ from, ...msg })
  }

  return {
    isConfigured,
    async sendVerificationCode({ to, code, ttlMinutes }) {
      await sendMail({
        to,
        subject: '【零号员工】密码重置验证码',
        text: `您正在重置 SSO 登录密码,验证码为:${code}\n\n验证码 ${ttlMinutes} 分钟内有效,请勿泄露给任何人。\n若非本人操作请忽略本邮件。`
      })
    },
    async sendPasswordChangedNotice({ to }) {
      await sendMail({
        to,
        subject: '【零号员工】登录密码已变更',
        text: '您的 SSO 登录密码已变更,如非本人操作请立即联系 IT。'
      })
    }
  }
}
