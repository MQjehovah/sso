import { keyRing } from '../keys.ts'
import { config } from '../config.ts'

/**
 * 密钥运维 CLI:
 *   node --experimental-strip-types src/cli/keys.ts rotate
 *   node --experimental-strip-types src/cli/keys.ts list
 *   node --experimental-strip-types src/cli/keys.ts prune
 *   node --experimental-strip-types src/cli/keys.ts retire <kid>
 */
async function main(): Promise<void> {
  const [cmd, arg] = process.argv.slice(2)
  const ring = keyRing()

  switch (cmd) {
    case 'rotate': {
      await ring.ensureActive()
      const { previous, current } = await ring.rotate()
      console.log(`[keys] 轮换完成: ${previous ?? '(无)'} -> ${current}`)
      console.log(`[keys] 旧密钥保留验签 ${config.keyRetireAfterHours} 小时后可执行 prune 退休`)
      return
    }
    case 'list': {
      const keys = ring.list()
      if (keys.length === 0) {
        console.log('[keys] 无密钥')
        return
      }
      for (const k of keys) {
        console.log(`${k.status.padEnd(9)} ${k.kid}  ${new Date(k.createdAt).toISOString()}`)
      }
      return
    }
    case 'prune': {
      const retired = await ring.prune(config.keyRetireAfterHours)
      console.log(retired.length ? `[keys] 已退休: ${retired.join(', ')}` : '[keys] 无需退休')
      return
    }
    case 'retire': {
      if (!arg) throw new Error('用法: keys.ts retire <kid>')
      console.log(ring.retire(arg) ? `[keys] ${arg} 已退休` : `[keys] 无法退休 ${arg}(不存在或仍是 active)`)
      return
    }
    default:
      console.log('用法: keys.ts <rotate|list|prune|retire <kid>>')
      process.exitCode = 1
  }
}

main().catch((err: unknown) => {
  console.error('[keys] 失败:', (err as Error).message)
  process.exitCode = 1
})
