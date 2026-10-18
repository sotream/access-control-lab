import { beforeEach, describe, expect, it, vi } from "vitest";

const cfg = { managedCidrs: ["10.1.0.0/16"] as string[], trustedProxySecret: "p".repeat(40) as string | undefined };
vi.mock("./config", () => ({ config: () => cfg }));
vi.mock("next/headers", () => ({ headers: async () => { throw new Error("outside a request"); } }));

const { clientAddress, currentHeaders, zoneOf } = await import("./client");
const h = (o: Record<string, string>) => new Headers(o);
const SECRET = "p".repeat(40);

beforeEach(() => {
  cfg.managedCidrs = ["10.1.0.0/16"];
  cfg.trustedProxySecret = SECRET;
});

describe("client address and zone: nothing is believed without the proxy's secret", () => {
  it("forwarded headers alone (any spelling) change nothing", () => {
    for (const x of <Record<string, string>[]>[{ "x-acl-client-ip": "10.1.2.3" }, { "x-forwarded-for": "10.1.2.3" }, { "x-real-ip": "10.1.2.3" }, { forwarded: "for=10.1.2.3" }]) {
      expect(clientAddress(h(x))).toBe("direct");
      expect(zoneOf(h(x))).toBe("unmanaged");
    }
  });
  it("a wrong, shorter, longer or empty secret is refused", () => {
    for (const s of ["x", SECRET.slice(1), SECRET + "p", ""]) {
      const x = h({ "x-acl-proxy-secret": s, "x-acl-client-ip": "10.1.2.3" });
      expect(clientAddress(x)).toBe("direct");
      expect(zoneOf(x)).toBe("unmanaged");
    }
  });
  it("without a configured secret the contract is off, even if a header happens to match something", () => {
    cfg.trustedProxySecret = undefined;
    expect(clientAddress(h({ "x-acl-proxy-secret": "", "x-acl-client-ip": "10.1.2.3" }))).toBe("direct");
  });
  it("the right secret makes the proxy's address believable, and only a plain IP", () => {
    const ok = (ip: string) => h({ "x-acl-proxy-secret": SECRET, "x-acl-client-ip": ip });
    expect(clientAddress(ok("203.0.113.9"))).toBe("203.0.113.9");
    expect(clientAddress(ok("::ffff:203.0.113.9"))).toBe("203.0.113.9");
    for (const bad of ["", "not-an-ip", "10.1.2.3, 6.6.6.6", "10.1.2.3:80", "10.1.2.3/16"]) expect(clientAddress(ok(bad)), bad).toBe("direct");
    expect(clientAddress(h({ "x-acl-proxy-secret": SECRET }))).toBe("direct");
  });
  it("zone is managed only for a proxy-vouched address inside MANAGED_CIDRS", () => {
    const ok = (ip: string) => h({ "x-acl-proxy-secret": SECRET, "x-acl-client-ip": ip });
    expect(zoneOf(ok("10.1.2.3"))).toBe("managed");
    expect(zoneOf(ok("10.2.0.1"))).toBe("unmanaged");
    cfg.managedCidrs = [];
    expect(zoneOf(ok("10.1.2.3"))).toBe("unmanaged"); // nothing configured: nobody is managed
  });
  it("outside a request there are no headers", async () => {
    expect(await currentHeaders()).toBeUndefined();
  });
});
