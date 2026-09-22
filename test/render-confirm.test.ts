import { test } from 'node:test'
import assert from 'node:assert/strict'
import { sessionConfirmPage } from '../src/render.ts'

const base = {
  txId: 'tx-abc123',
  csrf: '1700000000000.deadbeef',
  name: '张三',
  sub: '10001',
  dept: '平台组'
}

test('会话确认页包含两个提交表单与各两个隐藏 tx/csrf', () => {
  const html = sessionConfirmPage({ ...base, clientName: '零号员工' })
  assert.match(html, /action="\/authorize\/continue"/)
  assert.match(html, /action="\/authorize\/switch"/)
  assert.equal((html.match(/name="tx" value="tx-abc123"/g) ?? []).length, 2)
  assert.equal((html.match(/name="csrf" value="1700000000000.deadbeef"/g) ?? []).length, 2)
  assert.ok(html.includes('继续以该账号登录'))
  assert.ok(html.includes('使用其他账号'))
})

test('会话确认页展示当前账号与工号/部门', () => {
  const html = sessionConfirmPage(base)
  assert.ok(html.includes('已登录为 张三'))
  assert.ok(html.includes('工号 10001 · 平台组'))
})

test('会话确认页对 name/sub/dept/clientName 做 HTML 转义(防 XSS)', () => {
  const html = sessionConfirmPage({
    ...base,
    name: '<script>alert(1)</script>',
    sub: '"><img src=x onerror=alert(2)>',
    dept: `平台组'"><svg onload=alert(3)>`,
    clientName: '<b>零号员工</b>'
  })
  assert.ok(!html.includes('<script>'), 'name 注入的 <script> 必须被转义')
  assert.ok(!html.includes('<img src=x'), 'sub 注入的 <img> 必须被转义')
  assert.ok(!html.includes('<svg onload'), 'dept 注入的 <svg> 必须被转义')
  assert.ok(!html.includes('<b>零号员工</b>'), 'clientName 注入的标签必须被转义')
  assert.ok(html.includes('&lt;script&gt;'))
  assert.ok(html.includes('&lt;img src=x onerror=alert(2)&gt;'))
  assert.ok(html.includes('&lt;svg onload=alert(3)&gt;'))
  assert.ok(html.includes('&lt;b&gt;零号员工&lt;/b&gt;'))
})
