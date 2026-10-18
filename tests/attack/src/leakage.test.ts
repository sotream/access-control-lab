// A-80..A-86: what the system tells an attacker it did not have to: error bodies, banners, files, the difference between "hidden" and "not there".
import { describe, expect, it } from "vitest";
import { fixtures } from "./fixtures.js";
import { api, FORM, form, idp, vault } from "./http.js";
import { oidcTokens } from "./kc.js";
import { bff, session } from "./sessions.js";

const LEAK = /stack|node_modules|\bat \S+ \(|\.ts:\d+|\.js:\d+|Error:|ECONN|postgres|pg_|SELECT |relation "|syntax error|nestjs|express|\/app\/|\/usr\/|internal server/i;
const BANNERS = ["server", "x-powered-by", "via", "x-aspnet-version", "x-runtime", "x-nextjs-cache", "x-nextjs-prerender", "x-nextjs-stale-time"];

describe("A-80 errors tell nothing about the inside", () => {
  it("malformed, oversized and hostile requests to every layer get short generic bodies: no stack, no path, no SQL, no library name", async () => {
    const s = await session("analyst-official");
    const t = await oidcTokens("analyst-official");
    const bearer = { authorization: `Bearer ${t.access_token}` };
    const responses = await Promise.all([
      vault("/nope"),
      vault("/bff/case-files", { method: "POST", jar: s.jar, headers: { origin: "https://vault.localhost", "x-csrf-token": s.csrf, "content-type": "application/json" }, body: "{not json" }),
      vault("/bff/case-files", { method: "POST", jar: s.jar, headers: { origin: "https://vault.localhost", "x-csrf-token": s.csrf, "content-type": "application/json" }, body: "[" + "[".repeat(5000) }),
      vault("/bff/case-files", { method: "POST", jar: s.jar, headers: { origin: "https://vault.localhost", "x-csrf-token": s.csrf, "content-type": "text/xml" }, body: "<a/>" }),
      vault("/cases/%ff%fe", { jar: s.jar }),
      vault("/cases/..%2f..%2f", { jar: s.jar }),
      vault("/api/auth/callback?code=%00&state=%00"),
      vault("/actions/case-files/create", { method: "POST", jar: s.jar, headers: { ...FORM, origin: "https://vault.localhost" }, body: "%zz=%zz" }),
      api("/case-files", { method: "POST", headers: { ...bearer, "content-type": "application/json" }, body: "{not json" }),
      api("/case-files", { method: "POST", headers: { ...bearer, "content-type": "application/json" }, body: JSON.stringify({ title: 5, classification: {}, compartments: "A" }) }),
      api("/case-files/%00", { headers: bearer }),
      api("/case-files/'", { headers: bearer }),
      api("/nope", { headers: bearer }),
      api("/me", { method: "DELETE", headers: bearer }),
      api("/audit-log?limit=99999999999999999999&from=x", { headers: bearer }),
      idp("/realms/casefile/nope"),
      idp("/realms/master"),
    ]);
    for (const r of responses) {
      expect(r.text.length, `a long body: ${r.text.slice(0, 80)}`).toBeLessThan(40_000);
      if (r.headers["content-type"]?.toString().includes("html") && r.status === 200) continue; // a normal page
      expect(r.text.slice(0, 600), `${r.status} body`).not.toMatch(LEAK);
      expect(r.status, "never a server error").toBeLessThan(500);
    }
    // the API's error bodies share one shape
    for (const r of responses.slice(8, 15)) if (r.json) expect(Object.keys(r.json as object).every((k) => ["statusCode", "error", "message", "code"].includes(k)), JSON.stringify(r.json)).toBe(true);
  });
  it("no response of any kind carries a version banner or a framework header", async () => {
    const s = await session("analyst-official");
    for (const path of ["/", "/cases", "/nope", "/api/auth/session", "/bff/me", "/_next/static/chunks/nope.js", "/robots.txt", "/favicon.ico"]) {
      const r = await vault(path, { jar: s.jar });
      for (const h of BANNERS) expect(r.headers[h], `${path}: ${h}`).toBeUndefined();
    }
    const kc = await idp("/realms/casefile/.well-known/openid-configuration");
    expect(kc.headers.server, "identity provider banner").toBeUndefined();
  });
});

describe("A-81 files and endpoints that should not exist are not there", () => {
  it("configuration, source, source maps, build metadata, framework internals and debug endpoints answer 404 (or a login redirect), never content", async () => {
    const paths = ["/.env", "/.env.local", "/.git/config", "/.git/HEAD", "/package.json", "/pnpm-lock.yaml", "/next.config.ts", "/server.js", "/Dockerfile", "/docker-compose.yml", "/secrets-dev/prod-like/compose.env", "/_next/static/../../package.json", "/_next/static/chunks/main.js.map", "/_next/server/app/page.js", "/_next/BUILD_ID", "/.next/BUILD_ID", "/api/health", "/health", "/healthz", "/metrics", "/actuator/env", "/debug", "/graphql", "/swagger", "/openapi.json", "/docs", "/admin", "/phpinfo.php", "/wp-login.php", "/%2e%2e/%2e%2e/etc/passwd", "/..;/..;/etc/passwd", "/_next/image?url=%2Fetc%2Fpasswd&w=64&q=75"];
    for (const p of paths) {
      const r = await vault(p);
      expect([301, 302, 303, 307, 308, 400, 404, 405], p).toContain(r.status);
      expect(r.text.slice(0, 300), p).not.toMatch(/root:|BUILD_ID|"name": "@acl|POSTGRES_PASSWORD|sourceMappingURL/);
      if ([301, 302, 303, 307, 308].includes(r.status)) expect(r.location ?? "", p).toMatch(/^\/(?!\/)|^https:\/\/vault\.localhost\//);
    }
  });
  it("the image optimiser and the framework data routes cannot be turned into a fetch of an outside or internal URL (SSRF)", async () => {
    for (const url of ["http://api:3001/health", "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "https://evil.example/x.png", "file:///etc/passwd", "//evil.example/x.png", "http://keycloak:8080/", "gopher://x"]) {
      const r = await vault(`/_next/image?url=${encodeURIComponent(url)}&w=64&q=75`);
      expect([400, 404], url).toContain(r.status);
    }
    for (const p of ["/_next/data/x/index.json", "/_next/webpack-hmr", "/__nextjs_original-stack-frame?file=/etc/passwd", "/__nextjs_launch-editor?file=/etc/passwd"]) expect([400, 404, 405], p).toContain((await vault(p)).status);
  });
});

describe("A-82 hidden looks exactly like missing", () => {
  it("a file the user may not see and an id that does not exist give the same status, the same body and the same headers (modulo request-specific ones)", async () => {
    const f = fixtures();
    const s = await session("analyst-official");
    const gone = "00000000-0000-4000-8000-0000000000aa";
    const strip = (r: Awaited<ReturnType<typeof bff>>) => ({ status: r.status, body: r.text, type: r.headers["content-type"], length: r.headers["content-length"], cache: r.headers["cache-control"], csp: String(r.headers["content-security-policy"]).replace(/nonce-[^']+/g, "nonce-X") });
    const missing = strip(await bff(s, "GET", `/case-files/${gone}`));
    for (const hidden of [f.secAlphaA, f.secAlphaB, f.confAlphaA]) expect(strip(await bff(s, "GET", `/case-files/${hidden}`)), `hidden ${hidden}`).toEqual(missing);
    for (const path of ["attachments", "export"]) {
      const m = strip(await bff(s, "GET", `/case-files/${gone}/${path}`));
      for (const hidden of [f.secAlphaA, f.confAlphaA]) expect(strip(await bff(s, "GET", `/case-files/${hidden}/${path}`)), `${path} of ${hidden}`).toEqual(m);
    }
    const pageMissing = await vault(`/cases/${gone}`, { jar: s.jar });
    for (const hidden of [f.secAlphaA, f.confAlphaA]) {
      const p = await vault(`/cases/${hidden}`, { jar: s.jar });
      expect(p.status).toBe(pageMissing.status);
    }
    // writes behave the same: you cannot even learn that a file exists by trying to change it
    const write = async (id: string) => (await bff(s, "PATCH", `/case-files/${id}`, { title: "x", version: 1 })).status;
    const expected = await write(gone);
    for (const hidden of [f.secAlphaA, f.confAlphaA]) expect(await write(hidden), `PATCH ${hidden}`).toBe(expected);
  });
  it("and the time it takes does not tell them apart either (median of 40 interleaved requests each, tolerance 150 ms)", async () => {
    const f = fixtures();
    const s = await session("analyst-official");
    const gone = "00000000-0000-4000-8000-0000000000bb";
    const a: number[] = [];
    const b: number[] = [];
    for (let i = 0; i < 40; i++) {
      a.push((await bff(s, "GET", `/case-files/${f.secAlphaA}`)).ms);
      b.push((await bff(s, "GET", `/case-files/${gone}`)).ms);
    }
    const med = (x: number[]) => x.slice().sort((m, n) => m - n)[Math.floor(x.length / 2)]!;
    console.log(`MEASURED A-82: median hidden ${med(a)} ms, median missing ${med(b)} ms`);
    expect(Math.abs(med(a) - med(b))).toBeLessThan(150);
  });
});

describe("A-83 the login does not say which part was wrong", () => {
  it("an unknown user and a wrong password give the same answer", async () => {
    const attempt = async (u: string, p: string) => {
      const start = await vault("/api/auth/login");
      const page = await idp(new URL(start.location!).pathname + new URL(start.location!).search);
      const action = /<form[^>]*action="([^"]+)"/.exec(page.text)![1]!.replaceAll("&amp;", "&");
      const r = await idp(new URL(action).pathname + new URL(action).search, { method: "POST", headers: FORM, jar: undefined, body: form({ username: u, password: p, credentialId: "" }) });
      return r.text.match(/Invalid username or password|Invalid user|not found|does not exist|disabled/i)?.[0] ?? "";
    };
    expect(await attempt("no-such-user-xyz", "wrong-password-1")).toBe(await attempt("reviewer", "wrong-password-1"));
  });
});
