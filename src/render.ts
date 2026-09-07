/** 登录页与简单页面模板(内联样式,无前端框架依赖) */

const BASE_STYLE = `
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;background:#161616;color:#e8e8e8;
       display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{width:400px;background:#1e1e1e;border:1px solid #2e2e2e;border-radius:14px;padding:32px}
  .logo{width:36px;height:36px;border-radius:9px;background:linear-gradient(135deg,#409eff,#7c3aed);
        color:#fff;font-weight:700;display:flex;align-items:center;justify-content:center;margin:0 auto 14px}
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
  clientName?: string
  error?: string
  dingtalkEnabled?: boolean
}): string {
  const { txId, tab, clientName, error, dingtalkEnabled = true } = opts
  const err = error ? `<div class="err">${escapeHtml(error)}</div>` : ''
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>统一登录</title>
<style>${BASE_STYLE}</style></head><body>
<div class="card">
  <div class="logo">Z</div>
  <h1>统一身份登录</h1>
  <div class="sub">${clientName ? escapeHtml(clientName) + ' · ' : ''}使用公司统一账号继续</div>
  <div class="tabs">
    ${dingtalkEnabled ? `<a href="/login?tx=${txId}&tab=qr" class="${tab === 'qr' ? 'on' : ''}">钉钉扫码</a>` : ''}
    <a href="/login?tx=${txId}&tab=pwd" class="${tab === 'pwd' || !dingtalkEnabled ? 'on' : ''}">钉钉扫码</a>
    <a href="/login?tx=${txId}&tab=pwd" class="${tab === 'pwd' ? 'on' : ''}">账号密码</a>
  </div>
  ${tab === 'qr' && dingtalkEnabled
    ? `<a class="btn primary" href="/dingtalk/start?tx=${txId}">打开钉钉扫码</a>`
    : `${err}<form method="post" action="/login/password">
        <input type="hidden" name="tx" value="${txId}" />
        <label>工号或手机号</label><input name="username" autocomplete="username" required />
        <label>密码</label><input name="password" type="password" autocomplete="current-password" required />
        <label></label><button class="btn primary" type="submit">登 录</button>
      </form>`}
  <div class="hint">登录即代表同意公司信息安全规范 · 凭据仅用于身份验证</div>
</div>
</body></html>`
}

export function messagePage(title: string, detail: string, ok: boolean): string {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<style>${BASE_STYLE}</style></head><body>
<div class="card">
  <div class="logo">${ok ? '✓' : '!'}</div>
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
  error?: string
  success?: string
}): string {
  const { sub, name, dept, needCurrent, error, success } = opts
  const err = error ? `<div class="err">${escapeHtml(error)}</div>` : ''
  const ok = success ? `<div class="err" style="background:#1b2b1e;border-color:#2a5a32;color:#8fd19a">${escapeHtml(success)}</div>` : ''
  const current = needCurrent
    ? `<label>当前密码</label><input name="current_password" type="password" autocomplete="current-password" />`
    : `<div class="hint" style="margin:0 0 4px">首次设置密码(当前账号尚未设置密码)</div>`
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>账号设置</title>
<style>${BASE_STYLE}</style></head><body>
<div class="card">
  <div class="logo">Z</div>
  <h1>账号设置 · 登录密码</h1>
  <div class="sub">${escapeHtml(name)}(${escapeHtml(sub)}) · ${escapeHtml(dept)}</div>
  ${err}${ok}
  <form method="post" action="/profile/password">
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
