import { test } from 'node:test'
import assert from 'node:assert/strict'
import { profilePage } from '../src/render.ts'

const html = profilePage({
  sub: '10001',
  name: '张三',
  dept: '平台组',
  needCurrent: true,
  csrf: '1700000000000.deadbeef'
})

test('个人页含改密/退出登录/使用其他账号三个表单与各 csrf', () => {
  assert.match(html, /action="\/profile\/password"/)
  assert.match(html, /action="\/profile\/logout"/)
  assert.match(html, /action="\/profile\/switch"/)
  assert.equal((html.match(/name="csrf" value="1700000000000.deadbeef"/g) ?? []).length, 3)
  assert.ok(html.includes('保存密码'))
  assert.ok(html.includes('退出登录'))
  assert.ok(html.includes('使用其他账号'))
  assert.ok(!html.includes('切换其他账号'))
})

test('个人页按钮样式:保存密码为主按钮,退出/使用其他账号为次按钮', () => {
  const form = (action: string): string =>
    html.match(new RegExp(`<form method="post" action="${action}"[\\s\\S]*?<\\/form>`))?.[0] ?? ''
  assert.ok(form('/profile/password').includes('class="btn primary"'))
  for (const action of ['/profile/logout', '/profile/switch']) {
    const f = form(action)
    assert.ok(f.includes('class="btn"') && !f.includes('btn primary'), `${action} 应为次按钮样式`)
  }
})
