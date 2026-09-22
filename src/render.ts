/** 登录页与简单页面模板(内联样式,无前端框架依赖) */

import { LOGO_SVG } from './brand.ts'

const BASE_STYLE = `
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;background:#161616;color:#e8e8e8;
       display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{width:400px;background:#1e1e1e;border:1px solid #2e2e2e;border-radius:14px;padding:32px}
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
  const ok = notice ? `<div class="err" style="background:#1b2b1e;border-color:#2a5a32;color:#8fd19a">${escapeHtml(notice)}</div>` : ''
  // txId 为空=重置完成后的回执页:没有登录事务,不渲染标签页与登录表单,避免死链/无效提交
  const hasTx = !!txId
  const tabs = hasTx
    ? `<div class="tabs">
    ${dingtalkEnabled ? `<a href="/login?tx=${txId}&tab=qr" class="${tab === 'qr' ? 'on' : ''}">钉钉扫码</a>` : ''}
    <a href="/login?tx=${txId}&tab=pwd" class="${tab === 'pwd' || !dingtalkEnabled ? 'on' : ''}">账号密码</a>
  </div>`
    : ''
  const panel = !hasTx
    ? `<div class="hint" style="margin:0">请返回业务系统重新发起登录</div>`
    : tab === 'qr' && dingtalkEnabled
      ? `<a class="btn primary" href="/dingtalk/start?tx=${txId}">打开钉钉扫码</a>`
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
<div class="card">
  <div class="logo">${LOGO_SVG}</div>
  <h1>统一身份登录</h1>
  <div class="sub">${clientName ? escapeHtml(clientName) + ' · ' : ''}使用公司统一账号继续</div>
  ${tabs}
  ${ok}
  ${panel}
  <div class="hint">登录即代表同意公司信息安全规范 · 凭据仅用于身份验证</div>
</div>
</body></html>`
}

/** 自助重置页:step1 工号 → 发码;step2 验证码 + 新密码。无会话/事务,不走 CSRF token 机制 */
export function resetPage(opts: { step: 1 | 2; sub?: string; notice?: string; error?: string }): string {
  const { step, sub, notice, error } = opts
  const err = error ? `<div class="err">${escapeHtml(error)}</div>` : ''
  const ok = notice ? `<div class="err" style="background:#1b2b1e;border-color:#2a5a32;color:#8fd19a">${escapeHtml(notice)}</div>` : ''
  const form = step === 1
    ? `<form method="post" action="/reset/request">
        <label>工号或手机号</label><input name="sub" autocomplete="username" required />
        <label></label><button class="btn primary" type="submit">发送验证码</button>
      </form>`
    : `<form method="post" action="/reset/confirm">
        <input type="hidden" name="sub" value="${escapeHtml(sub ?? '')}" />
        <label>邮箱验证码</label><input name="code" inputmode="numeric" maxlength="6" autocomplete="one-time-code" required />
        <label>新密码(至少 8 位)</label><input name="new_password" type="password" minlength="8" required />
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
  const ok = success ? `<div class="err" style="background:#1b2b1e;border-color:#2a5a32;color:#8fd19a">${escapeHtml(success)}</div>` : ''
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
    <label>新密码(至少 8 位)</label><input name="new_password" type="password" minlength="8" required />
    <label>确认新密码</label><input name="confirm" type="password" minlength="8" required />
    <label></label><button class="btn primary" type="submit">保存密码</button>
  </form>
  <div class="hint">密码用于"账号密码"登录通道,同样适用于其他接入统一认证的系统</div>
</div>
</body></html>`
}

function escapeHtml(v: string): string {
  return v.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c)
}
