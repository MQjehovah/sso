/** 内存滑动窗口限流(单实例部署;多副本时前移至反代/网关) */
interface Window {
  timestamps: number[]
  /** 最近一次访问该键所用的窗口;周期清理按各键自身窗口裁剪,避免不同窗口的键互相误伤 */
  windowMs: number
}

const windows = new Map<string, Window>()
let lastPrune = Date.now()

export function rateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now()
  // 周期清理,防 Map 无限增长:按各键记录的 windowMs 裁剪,绝不能用当前调用的 windowMs 扫所有键——
  // 一次 60s 窗口调用会把 1h 窗口键(reset:ip / reset:send:h)的旧时间戳裁掉,削弱小时配额
  if (now - lastPrune > 60_000) {
    for (const [k, w] of windows) {
      w.timestamps = w.timestamps.filter((t) => now - t < w.windowMs)
      if (w.timestamps.length === 0) windows.delete(k)
    }
    lastPrune = now
  }
  const w = windows.get(key) ?? { timestamps: [], windowMs }
  w.windowMs = windowMs
  w.timestamps = w.timestamps.filter((t) => now - t < windowMs)
  if (w.timestamps.length >= limit) {
    windows.set(key, w)
    return false
  }
  w.timestamps.push(now)
  windows.set(key, w)
  return true
}
