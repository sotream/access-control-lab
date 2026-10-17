import { Inject, Injectable } from "@nestjs/common";
import { CONFIG, type AppConfig } from "../config.js";

/**
 * Counts failed authentications per client address in a sliding window.
 * ponytail: in-memory, per process. A multi-instance deployment needs a shared store (Redis) and
 * a trusted proxy header policy; the API is only reachable from the BFF on loopback today.
 */
@Injectable()
export class AuthFailureLimiter {
  private readonly hits = new Map<string, number[]>();

  constructor(@Inject(CONFIG) private readonly cfg: AppConfig) {}

  private prune(key: string, now: number): number[] {
    const live = (this.hits.get(key) ?? []).filter((t) => now - t < this.cfg.authFailWindowMs);
    if (live.length) this.hits.set(key, live);
    else this.hits.delete(key);
    return live;
  }

  blocked(key: string, now = Date.now()): boolean {
    return this.prune(key, now).length >= this.cfg.authFailLimit;
  }

  /** returns seconds until the oldest failure leaves the window */
  retryAfter(key: string, now = Date.now()): number {
    const live = this.prune(key, now);
    return live.length ? Math.max(1, Math.ceil((live[0]! + this.cfg.authFailWindowMs - now) / 1000)) : 1;
  }

  fail(key: string, now = Date.now()): void {
    const live = this.prune(key, now);
    live.push(now);
    this.hits.set(key, live);
    // bound memory: drop idle keys when the table grows
    if (this.hits.size > 10_000) for (const k of this.hits.keys()) this.prune(k, now);
  }
}
