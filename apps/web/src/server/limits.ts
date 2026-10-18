import { RateLimiter } from "@acl/netguard";
import { config } from "./config";
import { NextResponse } from "next/server";
import { clientAddress, currentHeaders } from "./client";

// Route handlers are bundled separately: the tables live on globalThis so every handler of a process shares them.
const KEY = Symbol.for("acl.web.limiters");
type Tables = Map<string, RateLimiter>;
const tables = (): Tables => ((globalThis as Record<symbol, unknown>)[KEY] ??= new Map()) as Tables;

function limiter(name: string, perMinute: number): RateLimiter {
  const t = tables();
  let l = t.get(name);
  if (!l) t.set(name, (l = new RateLimiter(perMinute, 60_000)));
  return l;
}

/** test hook */
export const resetLimits = (): void => tables().clear();

export type Scope = "auth" | "user";

/**
 * Counts this request against the per-address backstop and the scope's own limit.
 * `auth` (login, callback, logout, session): per client address. `user` (everything behind a session): per user, plus the address backstop.
 * Returns the 429 to send, or undefined to proceed. The user key must come from a validated session, never from the request.
 */
export async function limited(scope: Scope, userKey?: string): Promise<NextResponse | undefined> {
  const h = await currentHeaders();
  const ip = h ? clientAddress(h) : "direct";
  const c = config();
  const checks: [RateLimiter, string][] = [[limiter("ip", c.rateIpPerMinute), ip]];
  if (scope === "auth") checks.push([limiter("auth", c.rateAuthPerMinute), ip]);
  else if (userKey) checks.push([limiter("user", c.rateUserPerMinute), userKey]);
  for (const [l, key] of checks) {
    const r = l.hit(key);
    if (!r.ok) return NextResponse.json({ error: "rate_limited" }, { status: 429, headers: { "cache-control": "no-store", "retry-after": String(r.retryAfterSeconds) } });
  }
  return undefined;
}

/** Refresh grants per user: serialised per session by the row lock already; this stops a user with many sessions from hammering the token endpoint. */
export const refreshAllowed = (userSub: string): boolean => limiter("refresh", 10).hit(userSub).ok;
