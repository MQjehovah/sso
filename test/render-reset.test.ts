import { test } from 'node:test'
import assert from 'node:assert/strict'
import { loginPage, resetPage } from '../src/render.ts'
import { PASSWORD_POLICY_HINT } from '../src/password-policy.ts'

test('重置页 step2 含验证码与新密码表单, 并展示密码策略提示', () => {
  const html = resetPage({ step: 2, sub: '10001' })
  assert.match(html, /action="\/reset\/confirm"/)
  assert.match(html, /name="new_password"/)
  assert.ok(html.includes(PASSWORD_POLICY_HINT))
})

test('重置页 step1 只收集工号, 不展示密码提示', () => {
  const html = resetPage({ step: 1 })
  assert.match(html, /action="\/reset\/request"/)
  assert.ok(!html.includes(PASSWORD_POLICY_HINT))
})

test('重置页错误文案经 HTML 转义后展示(防目录错误注入)', () => {
  const html = resetPage({ step: 2, sub: '10001', error: '<script>alert(1)</script>' })
  assert.ok(!html.includes('<script>alert(1)</script>'))
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'))
})

test('登录回执页对重置完成提示做 HTML 转义', () => {
  const html = loginPage({ txId: '', tab: 'pwd', csrf: '', notice: '<b>密码已重置</b>' })
  assert.ok(!html.includes('<b>密码已重置</b>'))
  assert.ok(html.includes('&lt;b&gt;密码已重置&lt;/b&gt;'))
})

test('扫码页签内嵌二维码 iframe，不再用跳转按钮', () => {
  const html = loginPage({ txId: 'tx1', tab: 'qr', csrf: 'c', dingtalkEnabled: true })
  assert.match(html, /<iframe class="qr-frame" src="\/dingtalk\/start\?tx=tx1"/)
  assert.ok(!html.includes('打开钉钉扫码'))
  assert.ok(html.includes('用钉钉 App 扫码'))
})

test('未启用钉钉时无扫码页签与 iframe', () => {
  const html = loginPage({ txId: 'tx1', tab: 'pwd', csrf: 'c', dingtalkEnabled: false })
  assert.ok(!html.includes('qr-frame'))
  assert.ok(!html.includes('钉钉扫码'))
})
