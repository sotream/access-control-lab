import { describe, expect, it } from "vitest";
import { RateLimiter, clientIp, normalizeIp, parseNetworks, parseZoneKeys, signZone, verifyZone } from "./index.js";

const K1 = `k1:${Buffer.alloc(32, 1).toString("base64")}`;
const K2 = `k2:${Buffer.alloc(32, 2).toString("base64")}`;

describe("normalizeIp", () => {
  it("accepts IPs, unwraps IPv4-mapped IPv6, lowercases", () => {
    expect(normalizeIp("::ffff:10.0.0.1")).toBe("10.0.0.1");
    expect(normalizeIp(" FD00::1 ")).toBe("fd00::1");
    expect(normalizeIp("203.0.113.9")).toBe("203.0.113.9");
  });
  it.each(["", "abc", "1.2.3", "1.2.3.4.5", "999.1.1.1", "10.0.0.1, 10.0.0.2", "10.0.0.1:80", "::ffff:nonsense", undefined])("rejects %s", (v) => {
    expect(normalizeIp(v)).toBeUndefined();
  });
});

describe("parseNetworks", () => {
  it.each(["10.0.0.0/33", "fd00::/129", "10.0.0.0/x", "10.0.0.0/8/8", "nope", "10.0.0.0/"])("refuses %s", (e) => {
    expect(() => parseNetworks([e])).toThrow();
  });
  it("matches subnets and single addresses in both families", () => {
    const n = parseNetworks(["10.0.0.0/8", "192.0.2.7", "fd00::/8"]);
    expect([n.has("10.9.9.9"), n.has("192.0.2.7"), n.has("fd12::1"), n.has("::ffff:10.1.1.1")]).toEqual([true, true, true, true]); // BlockList itself understands the mapped form
    expect([n.has("11.0.0.1"), n.has("192.0.2.8"), n.has("fe80::1"), n.has(undefined), n.has("garbage")]).toEqual([false, false, false, false, false]);
  });
  it("an empty list trusts nothing", () => {
    expect(parseNetworks([]).has("127.0.0.1")).toBe(false);
  });
});

describe("clientIp", () => {
  const proxies = parseNetworks(["10.0.0.0/8"]);
  const none = parseNetworks([]);
  it("never believes X-Forwarded-For without a trusted peer", () => {
    expect(clientIp("203.0.113.5", "1.2.3.4", none)).toBe("203.0.113.5");
    expect(clientIp("203.0.113.5", "1.2.3.4", proxies)).toBe("203.0.113.5"); // peer is not a proxy
    expect(clientIp("::ffff:203.0.113.5", "1.2.3.4", proxies)).toBe("203.0.113.5");
  });
  it("takes the right-most address that is not a trusted proxy", () => {
    expect(clientIp("10.0.0.2", "198.51.100.1", proxies)).toBe("198.51.100.1");
    expect(clientIp("10.0.0.2", "6.6.6.6, 198.51.100.1, 10.0.0.9", proxies)).toBe("198.51.100.1"); // the client-chosen left part is ignored
    expect(clientIp("10.0.0.2", "198.51.100.1, 10.0.0.9, 10.0.0.3", proxies)).toBe("198.51.100.1");
  });
  it("falls back to the peer on garbage, an over-long chain, or an all-proxy chain", () => {
    expect(clientIp("10.0.0.2", "1.2.3.4, not-an-ip", proxies)).toBe("10.0.0.2");
    expect(clientIp("10.0.0.2", Array(25).fill("1.2.3.4").join(","), proxies)).toBe("10.0.0.2");
    expect(clientIp("10.0.0.2", "10.0.0.7, 10.0.0.8", proxies)).toBe("10.0.0.2");
    expect(clientIp("10.0.0.2", undefined, proxies)).toBe("10.0.0.2");
    expect(clientIp(undefined, "1.2.3.4", proxies)).toBeUndefined();
  });
});

describe("RateLimiter", () => {
  it("refuses from the limit on, with a Retry-After, and recovers after the window", () => {
    const r = new RateLimiter(3, 10_000);
    for (let i = 0; i < 3; i++) expect(r.hit("a", 1000).ok).toBe(true);
    expect(r.hit("a", 1000)).toEqual({ ok: false, retryAfterSeconds: 10 });
    expect(r.hit("a", 9500).retryAfterSeconds).toBe(2);
    expect(r.hit("b", 1000).ok).toBe(true); // keys are independent
    expect(r.hit("a", 11_000).ok).toBe(true);
  });
  it("blocked() reads without counting", () => {
    const r = new RateLimiter(2, 1000);
    expect(r.blocked("k", 0)).toBe(false);
    r.hit("k", 0);
    r.hit("k", 0);
    expect(r.blocked("k", 0)).toBe(true);
    expect(r.blocked("k", 1000)).toBe(false);
  });
  it("stays bounded under a key flood: expired keys go first, then the oldest", () => {
    const r = new RateLimiter(1, 1000, 50);
    for (let i = 0; i < 10_000; i++) r.hit(`ip-${i}`, 0);
    expect(r.size).toBeLessThanOrEqual(50);
    for (let i = 0; i < 100; i++) r.hit(`later-${i}`, 5000); // everything above has expired
    expect(r.size).toBeLessThanOrEqual(50);
  });
  it("refuses nonsense settings", () => {
    expect(() => new RateLimiter(0, 1000)).toThrow();
    expect(() => new RateLimiter(1, 0)).toThrow();
    expect(() => new RateLimiter(1, 1, 0)).toThrow();
    expect(() => new RateLimiter(Number.NaN, 1)).toThrow();
  });
});

describe("zone header", () => {
  const ring = parseZoneKeys(K1);
  const now = 1_800_000_000;
  it("round-trips for the subject it was made for", () => {
    expect(verifyZone(ring, signZone(ring, "managed", "u1", now), "u1", now)).toBe("managed");
    expect(verifyZone(ring, signZone(ring, "unmanaged", "u1", now), "u1", now + 30)).toBe("unmanaged");
  });
  it("rejects forgery, another subject, a flipped zone, staleness, the future, wrong key and garbage", () => {
    const good = signZone(ring, "unmanaged", "u1", now);
    const flipped = good.replace(".unmanaged.", ".managed.");
    const other = parseZoneKeys(`k1:${Buffer.alloc(32, 9).toString("base64")}`);
    const bad: [string | undefined, string, number][] = [
      [undefined, "u1", now],
      [good, "u2", now],
      [flipped, "u1", now],
      [good, "u1", now + 31],
      [signZone(ring, "managed", "u1", now + 60), "u1", now],
      [signZone(other, "managed", "u1", now), "u1", now],
      ["managed", "u1", now],
      ["v1.k1.1.managed", "u1", now],
      [`${good}.x`, "u1", now],
      [`v2${good.slice(2)}`, "u1", now],
      [good.replace(".k1.", ".k9."), "u1", now],
      [good.slice(0, -2) + "AA", "u1", now],
      [`v1.k1.${now}.managed.${"A".repeat(300)}`, "u1", now],
      [`v1.k1.abc.managed.AAAA`, "u1", now],
    ];
    for (const [h, sub, t] of bad) expect(verifyZone(ring, h, sub, t), String(h)).toBeUndefined();
  });
  it("rotation: old keys still verify, new ones sign", () => {
    const old = parseZoneKeys(K1);
    const both = parseZoneKeys(`${K2},${K1}`);
    const h = signZone(old, "managed", "u1", now);
    expect(verifyZone(both, h, "u1", now)).toBe("managed");
    expect(signZone(both, "managed", "u1", now).startsWith("v1.k2.")).toBe(true);
    expect(verifyZone(old, signZone(both, "managed", "u1", now), "u1", now)).toBeUndefined(); // k2 not yet known to the verifier
  });
  it("key rings are validated", () => {
    for (const bad of ["", "k1", "k1:AAAA", `k1:${Buffer.alloc(32).toString("base64")},k1:${Buffer.alloc(32).toString("base64")}`, `bad id:${Buffer.alloc(32).toString("base64")}`]) {
      expect(() => parseZoneKeys(bad), bad).toThrow();
    }
  });
});
