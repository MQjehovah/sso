/** 内存滑动窗口限流(单实例部署;多副本时前移至反代/网关) */
interface Window {
  timestamps: number[]
}

const windows = new Map<string, Window>()
let lastPrune = Date.now()

export function rateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now()
  // 周期清理,防 Map 无限增长
  if (now - lastPrune > 60_000) {
    for (const [k, w] of windows) {
      w.timestamps = w.timestamps.filter((t) => now - t < windowMs)
      if (w.timestamps.length === 0) windows.delete(k)
    }
    lastPrune = now
  }
  const w = windows.get(key) ?? { timestamps: [] }
  w.timestamps = w.timestamps.filter((t) => now - t < windowMs)
  if (w.timestamps.length >= limit) {
    windows.set(key, w)
    return false
  }
  w.timestamps.push(now)
  windows.set(key, w)
  return true
}
