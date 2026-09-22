import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import type { PendingTx } from '../src/store.ts'

/**
 * 登录事务(tx)的认领语义:takeTx 只读、finishTx 原子消费。
 * store.ts 在导入时捕获 config.dataDir,故先设置 SSO_DATA_DIR 再动态 import。
 */
let store: typeof import('../src/store.ts')

before(async () => {
  process.env.SSO_DATA_DIR = mkdtempSync(join(tmpdir(), 'tx-'))
  process.env.SSO_ISSUER = 'http://127.0.0.1:18091'
  store = await import('../src/store.ts')
})

function pendingTx(id: string): PendingTx {
  return { id, client_id: 'c-test', redirect_uri: 'http://127.0.0.1:19990/cb', scope: 'openid', created_at: Date.now() }
}

test('finishTx 原子认领:同一 tx 第二次返回 null(并发签码只可能一次)', () => {
  store.putTx(pendingTx('tx-claim'))
  assert.ok(store.finishTx('tx-claim'))
  assert.equal(store.finishTx('tx-claim'), null)
})

test('takeTx 只读不消费:可反复读取,finishTx 后才消失', () => {
  store.putTx(pendingTx('tx-peek'))
  assert.ok(store.takeTx('tx-peek'))
  assert.ok(store.takeTx('tx-peek'))
  assert.ok(store.finishTx('tx-peek'))
  assert.equal(store.takeTx('tx-peek'), null)
})
