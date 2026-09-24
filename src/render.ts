/** 登录页与简单页面模板(内联样式,无前端框架依赖) */

import { LOGO_SVG } from './brand.ts'
import { PASSWORD_POLICY_HINT } from './password-policy.ts'

const BASE_STYLE = `
  *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;background:#161616;color:#e8e8e8;
         display:flex;min-height:100vh;padding:24px 0}
    .card{width:440px;background:#1e1e1e;border:1px solid #2e2e2e;border-radius:14px;padding:32px;margin:auto}
  .logo{width:36px;height:36px;margin:0 auto 14px}
  .logo svg{width:100%;height:100%;display:block}
  .logo .mark{width:36px;height:36px;border-radius:9px;background:linear-gradient(135deg,#409eff,#7c3aed);
        color:#fff;font-weight:700;display:flex;align-items:center;justify-content:center}
  h1{font-size:17px;text-align:center;margin-bottom:6px;font-weight:600}
  .sub{text-align:center;color:#9b9b9b;font-size:12.5px;margin-bottom:22px}
  .tabs{display:flex;border:1px solid #2e2e2e;border-radius:9px;overflow:hidden;margin-bottom:20px}
  .tabs a{flex:1;text-align:center;padding:8px 0;font-size:13px;color:#9b9b9b;text-decoration:none}
  .tabs a.on{background:#2a2a2a;color:#e8e8e8}
  .tabs a:hover{color:#e8e8e8}
  .qr-wrap{display:flex;flex-direction:column;align-items:center}
  .card.qr{width:520px}
  .qr-frame{width:100%;max-width:100%;height:620px;border:0;border-radius:10px;background:#fff;box-shadow:0 2px 10px rgba(0,0,0,.35)}
  .btn{display:block;width:100%;padding:10px 0;border:none;border-radius:9px;cursor:pointer;
       font-size:14px;text-align:center;text-decoration:none;background:#e8e8e8;color:#141414}
  .btn.primary{background:linear-gradient(135deg,#409eff,#2979ff);color:#fff}
  .btn.primary:hover{filter:brightness(1.1)}
  label{display:block;font-size:12.5px;color:#9b9b9b;margin:12px 0 6px}
  input{width:100%;padding:9px 12px;border:1px solid #333;border-radius:8px;background:#181818;
        color:#e8e8e8;font-size:14px;outline:none}
  input:focus{border-color:#4a4a4a}
  .err{background:#2b1b1b;border:1px solid #5a2a2a;color:#e39393;border-radius:8px;
       padding:8px 12px;font-size:12.5px;margin-bottom:14px}
  .hint{text-align:center;color:#9b9b9b;font-size:11.5px;margin-top:16px}
`

/** 绿色成功提示块(与 .err 同布局,换配色);无文案返回空串 */
function successBlock(text?: string): string {
  return text ? `<div class="err" style="background:#1b2b1e;border-color:#2a5a32;color:#8fd19a">${escapeHtml(text)}</div>` : ''
}

/** 新密码强度要求提示(左对齐,紧跟密码输入框;文案与后端预检共用) */
const PASSWORD_HINT_HTML = `<div class="hint" style="text-align:left;margin:6px 0 0">${PASSWORD_POLICY_HINT}</div>`

export function loginPage(opts: {
  txId: string
  tab: 'qr' | 'pwd'
  csrf: string
  clientName?: string
  error?: string
  /** 成功提示(如重置密码完成);与 error 同风格,绿色块 */
  notice?: string
  dingtalkEnabled?: boolean
}): string {
  const { txId, tab, csrf, clientName, error, notice, dingtalkEnabled = true } = opts
  const err = error ? `<div class="err">${escapeHtml(error)}</div>` : ''
  const ok = successBlock(notice)
  // txId 为空=重置完成后的回执页:没有登录事务,不渲染标签页与登录表单,避免死链/无效提交
  const hasTx = !!txId
  const tabs = hasTx
    ? `<div class="tabs">
    <a href="/login?tx=${txId}&tab=pwd" class="${tab === 'pwd' || !dingtalkEnabled ? 'on' : ''}">账号密码</a>
    ${dingtalkEnabled ? `<a href="/login?tx=${txId}&tab=qr" class="${tab === 'qr' ? 'on' : ''}">钉钉登录</a>` : ''}
  </div>`
    : ''
  const wide = hasTx && tab === 'qr' && dingtalkEnabled
  const panel = !hasTx
    ? `<div class="hint" style="margin:0">请返回业务系统重新发起登录</div>`
    : tab === 'qr' && dingtalkEnabled
      ? `<div class="qr-wrap">
        <iframe class="qr-frame" src="/dingtalk/start?tx=${txId}" title="钉钉登录" loading="lazy"></iframe>
      </div>`
      : `${err}<form method="post" action="/login/password">
        <input type="hidden" name="tx" value="${txId}" />
        <input type="hidden" name="csrf" value="${csrf}" />
        <label>工号或手机号</label><input name="username" autocomplete="username" required />
        <label>密码</label><input name="password" type="password" autocomplete="current-password" required />
        <label></label><button class="btn primary" type="submit">登 录</button>
      </form>
      <div class="hint" style="margin-top:12px"><a href="/reset" style="color:#409eff;text-decoration:none">忘记密码?</a></div>`
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>统一登录</title>
<style>${BASE_STYLE}</style></head><body>
<div class="card${wide ? ' qr' : ''}">
  <div class="logo">${LOGO_SVG}</div>
  <h1>统一身份登录</h1>
  <div class="sub">${clientName ? escapeHtml(clientName) + ' · ' : ''}使用公司统一账号继续</div>
  ${tabs}
  ${ok}
  ${panel}
</div>
</body></html>`
}

/** 会话确认页:已有 SSO 会话时让用户确认继续用该账号,或换账号(销毁会话回登录页) */
export function sessionConfirmPage(opts: {
  txId: string
  csrf: string
  name: string
  sub: string
  dept: string
  clientName?: string
}): string {
  const { txId, csrf, name, sub, dept, clientName } = opts
  const hidden = `<input type="hidden" name="tx" value="${escapeHtml(txId)}" />
    <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />`
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>确认登录账号</title>
<style>${BASE_STYLE}</style></head><body>
<div class="card">
  <div class="logo">${LOGO_SVG}</div>
  <h1>已登录为 ${escapeHtml(name)}</h1>
  <div class="sub">工号 ${escapeHtml(sub)} · ${escapeHtml(dept)}${clientName ? ' · ' + escapeHtml(clientName) : ''}</div>
  <form method="post" action="/authorize/continue">
    ${hidden}
    <button class="btn primary" type="submit">继续以该账号登录</button>
  </form>
  <form method="post" action="/authorize/switch" style="margin-top:10px">
    ${hidden}
    <button class="btn" type="submit">使用其他账号</button>
  </form>
  <div class="hint">不是本人?选择「使用其他账号」退出当前统一身份后重新登录</div>
</div>
</body></html>`
}

/** 自助重置页:step1 工号 → 发码;step2 验证码 + 新密码。无会话/事务,不走 CSRF token 机制 */
export function resetPage(opts: { step: 1 | 2; sub?: string; notice?: string; error?: string }): string {
  const { step, sub, notice, error } = opts
  const err = error ? `<div class="err">${escapeHtml(error)}</div>` : ''
  const ok = successBlock(notice)
  const form = step === 1
    ? `<form method="post" action="/reset/request">
        <label>工号或手机号</label><input name="sub" autocomplete="username" required />
        <label></label><button class="btn primary" type="submit">发送验证码</button>
      </form>`
    : `<form method="post" action="/reset/confirm">
        <input type="hidden" name="sub" value="${escapeHtml(sub ?? '')}" />
        <label>邮箱验证码</label><input name="code" inputmode="numeric" maxlength="6" autocomplete="one-time-code" required />
        <label>新密码</label><input name="new_password" type="password" minlength="8" required />
        ${PASSWORD_HINT_HTML}
        <label>确认新密码</label><input name="confirm" type="password" minlength="8" required />
        <label></label><button class="btn primary" type="submit">重置密码</button>
      </form>`
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>重置登录密码</title>
<style>${BASE_STYLE}</style></head><body>
<div class="card">
  <div class="logo">${LOGO_SVG}</div>
  <h1>重置登录密码</h1>
  <div class="sub">${step === 1 ? '输入工号, 验证码将发送至企业邮箱' : '输入邮箱收到的验证码并设置新密码'}</div>
  ${ok}${err}
  ${form}
  <div class="hint"><a href="/" style="color:#409eff;text-decoration:none">返回首页</a></div>
</div>
</body></html>`
}

/** 根路径首页:直接访问 sso 域名时不再显示裸 404 */
export function homePage(opts: { signedIn: boolean; name?: string; sub?: string }): string {
  const { signedIn, name, sub } = opts
  const body = signedIn
    ? `<div class="sub">已登录:${escapeHtml(name ?? '')}${sub ? '（' + escapeHtml(sub) + '）' : ''}</div>
       <a class="btn primary" href="/profile">账号设置(修改登录密码)</a>`
    : `<div class="sub">请从业务系统进入并点击登录</div>
       <div class="hint" style="margin:0 0 14px">
         本服务为公司统一身份认证入口,用于「零号员工」平台各业务系统登录。<br />
         直接打开本页面不需要操作,请回到业务系统(如 ai.xzrobot.com)发起登录。
       </div>`
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>统一身份认证</title>
<style>${BASE_STYLE}</style></head><body>
<div class="card">
  <div class="logo">${LOGO_SVG}</div>
  <h1>统一身份认证服务</h1>
  ${body}
  <div class="hint">仅限公司内部系统使用</div>
</div>
</body></html>`
}

export function messagePage(title: string, detail: string, ok: boolean): string {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<style>${BASE_STYLE}</style></head><body>
<div class="card">
  <div class="logo"><span class="mark">${ok ? '✓' : '!'}</span></div>
  <h1>${escapeHtml(title)}</h1>
  <p class="sub">${escapeHtml(detail)}</p>
</div>
</body></html>`
}

/**
 * 扫码 iframe 内登录完成后的跳出页:把顶层窗口导航到业务回调 URL。
 * target 由服务端构造(注册的 redirect_uri + code + state),JS 侧用 JSON 字符串字面量防注入。
 */
export function breakoutPage(target: string): string {
  const safe = JSON.stringify(target)
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>登录成功</title>
<style>${BASE_STYLE}</style></head><body>
<div class="card" style="text-align:center">
  <div class="logo"><span class="mark">✓</span></div>
  <h1>登录成功</h1>
  <p class="sub">正在跳转…</p>
  <noscript><a class="btn primary" href="${escapeHtml(target)}">继续</a></noscript>
</div>
<script>try{window.top.location.replace(${safe})}catch(e){window.location.replace(${safe})}</script>
</body></html>`
}

export function profilePage(opts: {
  sub: string
  name: string
  dept: string
  needCurrent: boolean
  csrf: string
  error?: string
  success?: string
}): string {
  const { sub, name, dept, needCurrent, csrf, error, success } = opts
  const err = error ? `<div class="err">${escapeHtml(error)}</div>` : ''
  const ok = successBlock(success)
  const current = needCurrent
    ? `<label>当前密码</label><input name="current_password" type="password" autocomplete="current-password" />`
    : `<div class="hint" style="margin:0 0 4px">首次设置密码(当前账号尚未设置密码)</div>`
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>账号设置</title>
<style>${BASE_STYLE}</style></head><body>
<div class="card">
  <div class="logo">${LOGO_SVG}</div>
  <h1>账号设置 · 登录密码</h1>
  <div class="sub">${escapeHtml(name)}(${escapeHtml(sub)}) · ${escapeHtml(dept)}</div>
  ${err}${ok}
  <form method="post" action="/profile/password">
    <input type="hidden" name="csrf" value="${csrf}" />
    ${current}
    <label>新密码</label><input name="new_password" type="password" minlength="8" required />
    ${PASSWORD_HINT_HTML}
    <label>确认新密码</label><input name="confirm" type="password" minlength="8" required />
    <label></label><button class="btn primary" type="submit">保存密码</button>
  </form>
  <form method="post" action="/profile/logout" style="margin-top:10px">
    <input type="hidden" name="csrf" value="${csrf}" />
    <button class="btn" type="submit">退出登录</button>
  </form>
  <form method="post" action="/profile/switch" style="margin-top:10px">
    <input type="hidden" name="csrf" value="${csrf}" />
    <button class="btn" type="submit">使用其他账号</button>
  </form>
  <div class="hint">密码用于"账号密码"登录通道,同样适用于其他接入统一认证的系统</div>
</div>
</body></html>`
}

function escapeHtml(v: string): string {
  return v.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c)
}
