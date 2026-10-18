// Stage 8 at the BFF: rate limits, trusted-proxy contract and the signed network zone (T-22, T-27, T-44, T-45).
import { afterAll, describe, expect, it } from "vitest";
import { parseZoneKeys, verifyZone } from "@acl/netguard";
import { Browser, PROXY_SECRET, startStubApi, startWeb, viaProxy, WEB, type Seen, type WebServer } from "./harness.js";

const RING = process.env.ZONE_SIGNING_KEYS!;
let web: WebServer | undefined;
let stub: Awaited<ReturnType<typeof startStubApi>> | undefined;
afterAll(async () => {
  await web?.stop();
  await stub?.stop();
});

async function restart(over: Record<string, string> = {}) {
  await web?.stop();
  web = await startWeb(over);
}

describe("network zone: the BFF signs it, nobody else can claim it (T-44)", () => {
  const zoneSeen = async (browser: Browser, extra: Record<string, string> = {}) => {
    const before = stub!.seen.length;
    const r = await browser.req("/bff/me", { headers: extra });
    expect(r.status).toBe(200);
    const seen: Seen = stub!.seen[before]!;
    const sub = JSON.parse((await browser.req("/api/auth/session")).text).sub as string;
    return { header: seen.headers["x-acl-zone"] as string | undefined, sub };
  };

  it("sends a zone header signed for the session's user, unmanaged unless a trusted proxy vouches for a managed address", async () => {
    stub = await startStubApi(() => ({ status: 200, body: "{}" }));
    await restart();
    const b = new Browser();
    await b.login("analyst-official");
    const now = () => Math.floor(Date.now() / 1000);
    const ring = parseZoneKeys(RING);

    const direct = await zoneSeen(b);
    expect(verifyZone(ring, direct.header, direct.sub, now())).toBe("unmanaged");

    const managed = await zoneSeen(b, viaProxy("10.1.2.3"));
    expect(verifyZone(ring, managed.header, managed.sub, now())).toBe("managed");
    expect(verifyZone(ring, managed.header, "someone-else", now())).toBeUndefined(); // cannot be replayed for another user

    const outside = await zoneSeen(b, viaProxy("10.9.9.9"));
    expect(verifyZone(ring, outside.header, outside.sub, now())).toBe("unmanaged");
  });

  it("forgery attempts from the browser all end in unmanaged: client-ip without the secret, wrong secret, forwarded headers, its own x-acl-zone", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    const ring = parseZoneKeys(RING);
    const attempts: Record<string, string>[] = [
      { "x-acl-client-ip": "10.1.2.3" },
      { "x-acl-proxy-secret": "wrong", "x-acl-client-ip": "10.1.2.3" },
      { "x-acl-proxy-secret": PROXY_SECRET.slice(0, -1), "x-acl-client-ip": "10.1.2.3" },
      { "x-forwarded-for": "10.1.2.3", "x-real-ip": "10.1.2.3", forwarded: "for=10.1.2.3" },
      { ...viaProxy("not-an-ip") },
      { ...viaProxy("10.1.2.3, 6.6.6.6") },
      { "x-acl-zone": "managed" },
      { "x-acl-zone": "v1.zone-1.1.managed.AAAA" },
    ];
    for (const a of attempts) {
      const z = await zoneSeen(b, a);
      expect(verifyZone(ring, z.header, z.sub, Math.floor(Date.now() / 1000)), JSON.stringify(a)).toBe("unmanaged");
    }
  });
});

describe("rate limits (T-22, T-27)", () => {
  it("login is limited per client address; a forged client address buys no new budget; a vouched one has its own", async () => {
    await stub?.stop();
    stub = undefined;
    await restart({ RATE_AUTH_PER_MINUTE: "5" });
    const hit = (h: Record<string, string> = {}) => fetch(`${WEB}/api/auth/login`, { redirect: "manual", headers: h });
    const codes: number[] = [];
    for (let i = 0; i < 7; i++) codes.push((await hit()).status);
    expect(codes).toEqual([303, 303, 303, 303, 303, 429, 429]);
    const blocked = await hit();
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
    expect(await blocked.json()).toEqual({ error: "rate_limited" }); // no detail
    expect((await hit({ "x-forwarded-for": "198.51.100.7", "x-acl-client-ip": "198.51.100.7" })).status).toBe(429); // header without the secret: same bucket
    expect((await hit({ "x-acl-proxy-secret": "wrong", "x-acl-client-ip": "198.51.100.8" })).status).toBe(429);
    expect((await hit(viaProxy("198.51.100.7"))).status).toBe(303); // the proxy vouches for a different client
    expect((await hit(viaProxy("198.51.100.7"))).status).toBe(303);
    // callback and logout share the budget; the callback refuses without touching the database or the identity provider
    expect((await fetch(`${WEB}/api/auth/callback?code=x&state=y`, { redirect: "manual" })).status).toBe(429);
    expect((await fetch(`${WEB}/api/auth/logout`, { method: "POST", redirect: "manual" })).status).toBe(429);
  });

  it("authenticated traffic is limited per user: one user's flood does not touch another", async () => {
    await restart({ RATE_USER_PER_MINUTE: "8" });
    const a = new Browser();
    const c = new Browser();
    await a.login("analyst-official");
    await c.login("reviewer");
    const codes: number[] = [];
    for (let i = 0; i < 10; i++) codes.push((await a.req("/api/auth/session")).status);
    expect(codes.slice(0, 8).every((x) => x === 200)).toBe(true);
    expect(codes.slice(8)).toEqual([429, 429]);
    expect((await a.req("/bff/me")).status).toBe(429); // the same budget covers the proxy
    expect((await c.req("/api/auth/session")).status).toBe(200);
    // state-changing routes are limited too, after the session check and before the CSRF check does any work
    const post = await a.req("/actions/case-files/create", { method: "POST", headers: { origin: WEB, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: "x" }) });
    expect(post.status).toBe(429);
  });
});
