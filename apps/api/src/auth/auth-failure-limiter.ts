import { Inject, Injectable } from "@nestjs/common";
import { RateLimiter } from "@acl/netguard";
import { CONFIG, type AppConfig } from "../config.js";

/**
 * Rate limits of the API, all bounded in memory (see RateLimiter for the ceiling):
 * - failed authentications per socket address (a failure budget; the socket peer is the BFF, so this mostly protects against a direct caller),
 * - requests per verified subject (the BFF multiplexes every user over one address, so the address is no key for authenticated traffic),
 * - requests per socket address on public routes.
 * ponytail: per process. A multi-instance deployment needs a shared store; the ceiling is documented in docs/hardening.md.
 */
@Injectable()
export class AuthFailureLimiter {
  private readonly failures: RateLimiter;
  private readonly subjects: RateLimiter;
  private readonly publicHits: RateLimiter;

  constructor(@Inject(CONFIG) cfg: AppConfig) {
    this.failures = new RateLimiter(cfg.authFailLimit, cfg.authFailWindowMs);
    this.subjects = new RateLimiter(cfg.throttleLimit, cfg.throttleWindowMs);
    this.publicHits = new RateLimiter(cfg.throttleLimit, cfg.throttleWindowMs);
  }

  blocked(key: string, now = Date.now()): boolean {
    return this.failures.blocked(key, now);
  }

  /** seconds until the failure window of this key ends */
  retryAfter(key: string, now = Date.now()): number {
    return this.failures.hit(key, now).retryAfterSeconds || 1;
  }

  fail(key: string, now = Date.now()): void {
    this.failures.hit(key, now);
  }

  /** counts one request of an authenticated subject; refused requests carry a Retry-After */
  subject(sub: string, now = Date.now()) {
    return this.subjects.hit(sub, now);
  }

  publicRoute(ip: string, now = Date.now()) {
    return this.publicHits.hit(ip, now);
  }
}
