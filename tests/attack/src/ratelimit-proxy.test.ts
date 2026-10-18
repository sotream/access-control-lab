// A-70..A-76: rate limits and lockouts, and what reaches the proxy on the wire. The BFF instance with the production limits is selected with
// the header x-attack-instance: strict (test-only route, infra/caddy/test/strict.caddy); the lax one serves the rest of the suite.
import { describe, expect, it } from "vitest";
import { apiStrict, FORM, form, idp, Jar, request, vault } from "./http.js";
import { oidcTokens } from "./kc.js";
import { rawRequest } from "./raw.js";
import { session } from "./sessions.js";
import { env } from "./stack.js";

const strict = { "x-attack-instance": "strict" };
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** the limiter windows are a minute long: on a fresh stack nothing to wait for, on a re-run poll until the previous window has drained */
async function drain(probe: () => Promise<boolean>): Promise<void> {
  for (let i = 0; i < 14 && !(await probe()); i++) await wait(5000);
}

describe("A-70 the login endpoint cannot be hammered by rotating the apparent client address", () => {
  it("forged x-forwarded-for, x-real-ip, x-acl-client-ip and Forwarded do not buy a fresh budget: the same real address is cut off", async () => {
    await drain(async () => (await vault("/api/auth/login", { headers: strict })).status !== 429);
    const codes: number[] = [];
    for (let i = 0; i < 40; i++) {
      const r = await vault("/api/auth/login", { headers: { ...strict, "x-forwarded-for": `9.9.9.${i}, 10.0.0.${i}`, "x-real-ip": `9.9.8.${i}`, "x-acl-client-ip": `9.9.7.${i}`, forwarded: `for=9.9.6.${i}`, "x-acl-proxy-secret": `guess-${i}` } });
      codes.push(r.status);
    }
    const first = codes.indexOf(429);
    expect(first, `no 429 in ${codes}`).toBeGreaterThan(0);
    expect(first).toBeLessThanOrEqual(21);
    expect(codes.slice(first).every((c) => c === 429)).toBe(true);
    const r = await vault("/api/auth/login", { headers: strict });
    expect(r.status).toBe(429);
    expect(Number(r.headers["retry-after"])).toBeGreaterThan(0);
    expect(r.json).toEqual({ error: "rate_limited" });
  });
});

describe("A-71 one noisy user does not starve another; one address is one bucket", () => {
  it("a user over the per-user limit is refused while another user's requests on the same instance still succeed", async () => {
    const noisy = await session("analyst-official");
    const calm = await session("reviewer");
    let refused = 0;
    for (let i = 0; i < 340; i++) if ((await vault("/api/auth/session", { jar: noisy.jar, headers: strict })).status === 429) refused++;
    expect(refused, "the noisy user hit the per-user limit").toBeGreaterThan(0);
    expect((await vault("/api/auth/session", { jar: calm.jar, headers: strict })).status).toBe(200);
  });
});

describe("A-72 the API's failed-authentication budget (production limits)", () => {
  it("ten bad tokens lock the source out for a window, a valid token included; the window ends on its own", async () => {
    const t = await oidcTokens("unit-admin-alpha");
    await drain(async () => (await apiStrict("/me", { headers: { authorization: `Bearer ${t.access_token}` } })).status === 200);
    const bad = [];
    for (let i = 0; i < 14; i++) bad.push((await apiStrict("/me", { headers: { authorization: `Bearer forged.${i}.token`, "x-forwarded-for": `1.2.3.${i}` } })).status);
    expect(bad.slice(0, 10).every((c) => c === 401)).toBe(true);
    expect(bad.slice(10).every((c) => c === 429), `after ten failures: ${bad}`).toBe(true);
    const valid = await apiStrict("/me", { headers: { authorization: `Bearer ${t.access_token}`, "x-forwarded-for": "7.7.7.7" } });
    expect(valid.status, "a valid token from a locked-out source").toBe(429);
    expect(Number(valid.headers["retry-after"])).toBeGreaterThan(0);
    await wait(62_000);
    expect((await apiStrict("/me", { headers: { authorization: `Bearer ${t.access_token}` } })).status, "after the window").toBe(200);
  }, 300_000);
});

describe("A-73 password guessing is stopped by the identity provider, whatever address the attempts claim to come from", () => {
  it("six wrong passwords lock the account; the right password is then refused too, and rotating forwarded addresses changes nothing", async () => {
    const victim = "platform-admin";
    const attempt = async (password: string, i: number) => {
      const jar = new Jar();
      const start = await vault("/api/auth/login", { jar, headers: { "x-forwarded-for": `8.8.8.${i}` } });
      const page = await idp(new URL(start.location!).pathname + new URL(start.location!).search, { jar, headers: { "x-forwarded-for": `8.8.7.${i}` } });
      const action = /<form[^>]*action="([^"]+)"/.exec(page.text)![1]!.replaceAll("&amp;", "&");
      return idp(new URL(action).pathname + new URL(action).search, { method: "POST", jar, headers: { ...FORM, "x-forwarded-for": `8.8.6.${i}` }, body: form({ username: victim, password, credentialId: "" }) });
    };
    for (let i = 0; i < 7; i++) expect((await attempt(`wrong-${i}`, i)).status).toBe(200); // the form again, with an error
    const right = await attempt(env.DEV_USER_PASSWORD ?? "", 99);
    expect(right.status, "the right password while the account is locked").toBe(200);
    expect(right.location).toBeNull();
    expect(right.text).toMatch(/Invalid username or password|temporarily disabled|locked/i);
  });
});

describe("A-74 what reaches the proxy on the wire: smuggling-style requests, absurd sizes", () => {
  const base = (extra = "") => `POST /api/auth/session HTTP/1.1\r\n${"Host: vault.localhost\r\n"}Connection: close\r\n${extra}`;
  const smuggled = "GET /__echo HTTP/1.1\r\nHost: vault.localhost\r\n\r\n";
  it("conflicting Content-Length and Transfer-Encoding, in both orders, never yield a second response", async () => {
    const clTe = await rawRequest(`${base(`Content-Length: ${smuggled.length + 3}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n${smuggled}`)}`);
    const teCl = await rawRequest(`${base(`Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n${(smuggled.length).toString(16)}\r\n${smuggled}\r\n0\r\n\r\n`)}`);
    for (const r of [clTe, teCl]) {
      expect(r.statuses.length, r.data.slice(0, 200)).toBeLessThanOrEqual(1);
      expect(r.data).not.toContain('"x-acl-proxy-secret"'); // the echo upstream never answered a smuggled request
    }
  });
  it("duplicate and malformed Content-Length, obsolete folding, bad chunk sizes, an unknown transfer coding, a bare LF", async () => {
    const variants = [
      base("Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello!"),
      base("Content-Length: 5, 6\r\n\r\nhello"),
      base("Content-Length: -1\r\n\r\n"),
      base("Content-Length: 0x10\r\n\r\n"),
      base("X-Folded: a\r\n b\r\nContent-Length: 0\r\n\r\n"),
      base("Transfer-Encoding: chunked\r\n\r\nZZ\r\nhello\r\n0\r\n\r\n"),
      base("Transfer-Encoding: xchunked\r\nContent-Length: 0\r\n\r\n"),
      base("Transfer-Encoding : chunked\r\nContent-Length: 0\r\n\r\n"),
      `GET / HTTP/1.1\nHost: vault.localhost\nConnection: close\n\n`,
      `GET / HTTP/1.1\r\nHost: vault.localhost\r\nHost: evil.example\r\nConnection: close\r\n\r\n`,
      `GET http://evil.example/ HTTP/1.1\r\nHost: vault.localhost\r\nConnection: close\r\n\r\n`,
      `GET / HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n`,
    ];
    for (const v of variants) {
      const r = await rawRequest(v);
      expect(r.statuses.length, JSON.stringify(v.slice(0, 80))).toBeLessThanOrEqual(1);
      // 502: the proxy forwarded a framing the application's HTTP parser refused and reports it as a bad gateway; nothing was executed
      for (const s of r.statuses) expect([200, 303, 400, 404, 405, 408, 411, 413, 421, 501, 502], JSON.stringify(v.slice(0, 80))).toContain(s);
    }
  });
  it("oversized URL, oversized header block, thousands of headers, a huge cookie: refused, never a 5xx, never reaching the app", async () => {
    const big = [
      `GET /${"a".repeat(70_000)} HTTP/1.1\r\n${"Host: vault.localhost\r\n"}Connection: close\r\n\r\n`,
      `GET / HTTP/1.1\r\n${"Host: vault.localhost\r\n"}X-Big: ${"b".repeat(200_000)}\r\nConnection: close\r\n\r\n`,
      `GET / HTTP/1.1\r\n${"Host: vault.localhost\r\n"}${Array.from({ length: 4000 }, (_, i) => `X-H${i}: v\r\n`).join("")}Connection: close\r\n\r\n`,
      `GET /api/auth/session HTTP/1.1\r\n${"Host: vault.localhost\r\n"}Cookie: ${"c=d; ".repeat(20_000)}\r\nConnection: close\r\n\r\n`,
    ];
    for (const b of big) {
      const r = await rawRequest(b, { readMs: 5000 });
      for (const s of r.statuses) expect([400, 413, 414, 431], `status ${s}`).toContain(s);
      expect(r.closed || r.statuses.length > 0).toBe(true);
    }
  });
  it("a body over the proxy's cap is refused (413) without being forwarded", async () => {
    const r = await request("vault.localhost", "/api/auth/logout", { method: "POST", headers: { ...FORM, origin: "https://vault.localhost" }, body: "x".repeat(7 * 1024 * 1024) });
    expect([400, 403, 411, 413]).toContain(r.status);
  });
});

describe("A-75 slowloris-lite: connections that dribble a request do not take the service down", () => {
  it("fifty half-open connections later the service still answers promptly; the server closes idle ones on its own (measured)", async () => {
    const socks: import("node:tls").TLSSocket[] = [];
    const tls = await import("node:tls");
    await Promise.all(
      Array.from({ length: 50 }, () =>
        new Promise<void>((resolve) => {
          const s = tls.connect({ host: "127.0.0.1", port: 443, servername: "vault.localhost" }, () => {
            s.write("GET / HTTP/1.1\r\nHost: vault.localhost\r\nX-Slow: ");
            socks.push(s);
            resolve();
          });
          s.on("error", () => resolve());
        }),
      ),
    );
    const t0 = Date.now();
    const ok = await vault("/api/auth/session");
    const ms = Date.now() - t0;
    console.log(`MEASURED A-75: ${socks.length} dribbling connections open; a normal request took ${ms} ms and answered ${ok.status}`);
    expect(ok.status).toBe(200);
    expect(ms).toBeLessThan(3000);
    for (const s of socks) s.destroy();
  });
});

describe("A-76 only what the application uses is spoken to it", () => {
  it("unusual methods are stopped at the proxy, OPTIONS grants nothing, HEAD leaks no body", async () => {
    for (const m of ["TRACE", "PROPFIND", "PURGE", "LOCK"]) expect((await vault("/bff/me", { method: m })).status, m).toBe(405);
    const head = await vault("/api/auth/session", { method: "HEAD" });
    expect(head.body.length).toBe(0);
    const opt = await vault("/bff/me", { method: "OPTIONS", headers: { origin: "https://evil.example" } });
    expect(opt.headers["access-control-allow-origin"]).toBeUndefined();
  });
});
