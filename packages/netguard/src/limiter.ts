/**
 * Fixed-window counter per key with a hard bound on memory.
 * When the table is full, expired keys go first, then the oldest key (insertion order). An attacker who can present more distinct
 * keys than `maxKeys` within one window can therefore reset other keys' counters: the ceiling is documented, a shared store removes it.
 * Per process: several instances multiply the effective limit by their number.
 */
export class RateLimiter {
  private readonly windows = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly maxKeys = 10_000,
  ) {
    if (!(limit >= 1) || !(windowMs >= 1) || !(maxKeys >= 1)) throw new Error("invalid rate limit");
  }

  /** counts one request; `ok` is false once the key is over the limit (the refused request still counts toward nothing more) */
  hit(key: string, now = Date.now()): { ok: boolean; retryAfterSeconds: number } {
    let w = this.windows.get(key);
    if (!w || w.resetAt <= now) {
      if (!w && this.windows.size >= this.maxKeys) this.makeRoom(now);
      this.windows.delete(key); // re-insert at the end: recently active keys are evicted last
      w = { count: 0, resetAt: now + this.windowMs };
      this.windows.set(key, w);
    }
    if (w.count >= this.limit) return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((w.resetAt - now) / 1000)) };
    w.count++;
    return { ok: true, retryAfterSeconds: 0 };
  }

  /** true when the key has reached the limit, without counting (used for failure counters) */
  blocked(key: string, now = Date.now()): boolean {
    const w = this.windows.get(key);
    return !!w && w.resetAt > now && w.count >= this.limit;
  }

  get size(): number {
    return this.windows.size;
  }

  private makeRoom(now: number): void {
    for (const [k, w] of this.windows) if (w.resetAt <= now) this.windows.delete(k);
    if (this.windows.size >= this.maxKeys) {
      const oldest = this.windows.keys().next().value;
      if (oldest !== undefined) this.windows.delete(oldest);
    }
  }
}
