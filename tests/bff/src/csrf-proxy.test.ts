// CSRF on every state-changing route, and the API proxy: allow-list, header hygiene, SSRF, limits, step-up pass-through (T-05, T-07, T-12, T-13).
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Browser, adminDb, csrfOf, startApi, startStubApi, startWeb, WEB, type Seen, type WebServer } from "./harness.js";

let web: WebServer;
let api: Awaited<ReturnType<typeof startApi>> | undefined;
const admin = adminDb();
const ID = randomUUID();

beforeAll(async () => {
  api = await startApi();
  web = await startWeb();
});
afterAll(async () => {
  await web?.stop();
  await api?.stop();
  await admin.end();
});

const count = async () => (await admin.query("SELECT count(*)::int AS n FROM case_files")).rows[0].n as number;

type Variant = [string, (csrf: string, otherCsrf: string) => { headers: Record<string, string>; fields: Record<string, string>; query?: string }];
const variants: Variant[] = [
  ["no Origin header", (c) => ({ headers: { origin: "", "sec-fetch-site": "same-origin" }, fields: { csrf: c } })],
  ["Origin of another site", (c) => ({ headers: { origin: "https://evil.example", "sec-fetch-site": "cross-site" }, fields: { csrf: c } })],
  ["Origin null", (c) => ({ headers: { origin: "null" }, fields: { csrf: c } })],
  ["Origin of the same host on another port", (c) => ({ headers: { origin: "http://127.0.0.1:3001" }, fields: { csrf: c } })],
  ["same-origin Origin but sec-fetch-site none (typed URL / bookmark)", (c) => ({ headers: { origin: WEB, "sec-fetch-site": "none" }, fields: { csrf: c } })],
  ["correct Origin but no token", () => ({ headers: { origin: WEB }, fields: {} })],
  ["correct Origin, wrong token", () => ({ headers: { origin: WEB }, fields: { csrf: "x".repeat(43) } })],
  ["token of another user's session", (_c, o) => ({ headers: { origin: WEB }, fields: { csrf: o } })],
  ["correct Origin and token but cross-site fetch metadata", (c) => ({ headers: { origin: WEB, "sec-fetch-site": "cross-site" }, fields: { csrf: c } })],
  ["correct Origin and token but same-site (sibling) fetch metadata", (c) => ({ headers: { origin: WEB, "sec-fetch-site": "same-site" }, fields: { csrf: c } })],
  ["token only in the query string", (c) => ({ headers: { origin: WEB }, fields: {}, query: `?csrf=${c}` })],
];

describe("CSRF: every state-changing route refuses forged requests (T-05)", () => {
  async function pair() {
    const victim = new Browser();
    await victim.login("analyst-official");
    const csrf = csrfOf((await victim.req("/cases/new")).text);
    const other = new Browser();
    await other.login("reviewer");
    return { victim, csrf, otherCsrf: csrfOf((await other.req("/cases/new")).text) };
  }

  it.each(variants)("logout: %s", async (_n, make) => {
    const { victim, csrf, otherCsrf } = await pair();
    const v = make(csrf, otherCsrf);
    const r = await victim.req(`/api/auth/logout${v.query ?? ""}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...v.headers }, body: new URLSearchParams(v.fields) });
    expect(r.status).toBe(403);
    expect((await victim.req("/bff/me")).status).toBe(200); // still signed in
  });

  it.each(variants)("create case file (form action): %s", async (_n, make) => {
    const { victim, csrf, otherCsrf } = await pair();
    const before = await count();
    const v = make(csrf, otherCsrf);
    const r = await victim.req(`/actions/case-files/create${v.query ?? ""}`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", ...v.headers },
      body: new URLSearchParams({ title: "forged", body: "x", classification: "OFFICIAL", compartments: "", ...v.fields }),
    });
    expect(r.status).toBe(403);
    expect(await count()).toBe(before);
  });

  it.each(variants.filter(([n]) => !n.includes("query")))("proxy POST /bff/case-files (JSON): %s", async (_n, make) => {
    const { victim, csrf, otherCsrf } = await pair();
    const before = await count();
    const v = make(csrf, otherCsrf);
    const token = v.fields.csrf; // a JSON client sends it in a header
    const r = await victim.req("/bff/case-files", {
      method: "POST",
      headers: { "content-type": "application/json", ...(token ? { "x-csrf-token": token } : {}), ...v.headers },
      body: JSON.stringify({ title: "forged", classification: "OFFICIAL", compartments: [] }),
    });
    expect(r.status).toBe(403);
    expect(await count()).toBe(before);
  });

  it.each([
    ["submit", "/actions/case-files/" + ID + "/submit"],
    ["approve", "/actions/case-files/" + ID + "/approve"],
    ["delete", "/actions/case-files/" + ID + "/delete"],
    ["update", "/actions/case-files/" + ID + "/update"],
    ["break-glass", "/actions/case-files/" + ID + "/break-glass"],
  ])("%s action without token or with a foreign Origin is refused before anything is called", async (_n, path) => {
    const { victim } = await pair();
    const noToken = await victim.req(path, { method: "POST", headers: { origin: WEB, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ justification: "valid reason" }) });
    expect(noToken.status).toBe(403);
    const evil = await victim.req(path, { method: "POST", headers: { origin: "https://evil.example", "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: "x" }) });
    expect(evil.status).toBe(403);
  });

  it("a correct same-origin form post works (the control is not just a wall)", async () => {
    const { victim, csrf } = await pair();
    const r = await victim.post("/actions/case-files/create", { csrf, title: "legit", body: "b", classification: "OFFICIAL", compartments: "" });
    expect(r.status).toBe(303);
    expect(r.location).toMatch(/\/cases\/[0-9a-f-]{36}\?m=done$/);
    const j = await victim.postJson("/bff/case-files", { title: "legit-json", classification: "OFFICIAL", compartments: [] }, csrf);
    expect(j.status).toBe(201);
  });

  it("safe methods cannot change state: GET on action and logout routes is 405; no CORS grant to other origins", async () => {
    const { victim } = await pair();
    for (const p of ["/api/auth/logout", "/actions/case-files/create", `/actions/case-files/${ID}/approve`, `/actions/case-files/${ID}/delete`]) expect((await victim.req(p)).status, p).toBe(405);
    const pre = await victim.req("/bff/me", { method: "OPTIONS", headers: { origin: "https://evil.example", "access-control-request-method": "GET" } });
    expect(pre.headers.get("access-control-allow-origin")).toBeNull();
    const get = await victim.req("/bff/me", { headers: { origin: "https://evil.example" } });
    expect(get.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("the proxy refuses to act without a session", async () => {
    const anon = new Browser();
    expect((await anon.req("/bff/me")).status).toBe(401);
    expect((await anon.postJson("/bff/case-files", {}, "x")).status).toBe(401);
    expect((await anon.post("/actions/case-files/create", { csrf: "x" })).status).toBe(401);
  });
});

// ------------------------------------------------------------------------------------------------ stub upstream

describe("proxy behaviour against a recording upstream (T-12, T-13, T-27)", () => {
  let stub: Awaited<ReturnType<typeof startStubApi>>;
  let b: Browser;
  let csrf: string;
  let seen: Seen[];
  const mode = { stepUp: false, redirect: false, huge: false, slow: false, setCookie: false };
  const FILE = `/case-files/${ID}`;

  beforeAll(async () => {
    b = new Browser();
    await b.login("analyst-official");
    csrf = csrfOf((await b.req("/cases/new")).text);
    await api?.stop();
    api = undefined;
    stub = await startStubApi((s): { status: number; headers?: Record<string, string>; body?: string; delayMs?: number } => {
      if (mode.redirect) return { status: 302, headers: { location: "http://127.0.0.1:3998/stolen" } };
      if (mode.huge) return { status: 200, body: JSON.stringify({ blob: "x".repeat(3 * 1024 * 1024) }) };
      if (mode.slow) return { status: 200, delayMs: 12_000 };
      if (mode.stepUp) return { status: 403, headers: { "www-authenticate": 'Bearer realm="casefile-api", error="insufficient_user_authentication", acr_values="mfa"' }, body: JSON.stringify({ statusCode: 403, error: "Forbidden", code: "STEP_UP_REQUIRED" }) };
      const extra: Record<string, string> = mode.setCookie ? { "set-cookie": "evil=1; Path=/", "access-control-allow-origin": "*", "x-powered-by": "stub", "x-internal": "secret" } : {};
      if (s.url === "/me") return { status: 200, headers: extra, body: JSON.stringify({ sub: "stub", roles: ["analyst"], clearance: "OFFICIAL", unit: "alpha", compartments: [], acr: "pwd", amr: ["pwd"], authTime: 1 }) };
      if (s.url === FILE) return { status: 200, headers: extra, body: JSON.stringify({ id: ID, title: "T", body: "B", classification: "OFFICIAL", unit: "alpha", compartments: [], status: "draft", version: 1 }) };
      return { status: 200, headers: extra, body: "{}" };
    });
    seen = stub.seen;
  });
  afterAll(async () => {
    await stub?.stop();
  });
  const reset = () => {
    seen.length = 0;
    Object.assign(mode, { stepUp: false, redirect: false, huge: false, slow: false, setCookie: false });
  };

  it("the upstream request is built from scratch: only our Authorization; no cookie, no forwarded, no break-glass, no browser headers, no query", async () => {
    reset();
    const r = await b.req("/bff/me?x=1&access_token=evil", {
      headers: { authorization: "Bearer attacker", "x-forwarded-for": "10.9.9.9", "x-forwarded-host": "evil", "x-break-glass-justification": "sneaky", "x-user": "root", "x-clearance": "SECRET", forwarded: "for=evil", "x-request-id": "forged", referer: "https://evil.example/", origin: "https://evil.example" },
    });
    expect(r.status).toBe(200);
    expect(seen).toHaveLength(1);
    const h = seen[0]!.headers;
    expect(seen[0]!.url).toBe("/me"); // query string dropped
    expect(String(h.authorization)).toMatch(/^Bearer eyJ/);
    expect(h.authorization).not.toBe("Bearer attacker");
    for (const k of ["cookie", "x-forwarded-for", "x-forwarded-host", "forwarded", "x-break-glass-justification", "x-user", "x-clearance", "x-request-id", "referer", "origin", "x-csrf-token"]) expect(h[k], k).toBeUndefined();
    expect(h.host).toBe("127.0.0.1:3001");
  });

  it("the response is filtered: no Set-Cookie, no CORS grant, no internal headers; Cache-Control is no-store", async () => {
    reset();
    mode.setCookie = true;
    const r = await b.req("/bff/me");
    expect(r.status).toBe(200);
    for (const h of ["set-cookie", "access-control-allow-origin", "x-powered-by", "x-internal"]) expect(r.headers.get(h), h).toBeNull();
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.headers.get("content-type")).toBe("application/json");
  });

  it.each([
    ["GET", "/bff/health"],
    ["GET", "/bff/metrics"],
    ["GET", "/bff/me/extra"],
    ["POST", "/bff/me"],
    ["DELETE", "/bff/case-files"],
    ["PUT", `/bff${FILE}`],
    ["GET", `/bff${FILE}/`],
    ["GET", "/bff//evil.example/me"],
    ["GET", "/bff/http://127.0.0.1:1/me"],
    ["GET", "/bff/case-files/not-a-uuid"],
    ["GET", `/bff${FILE}%2fsubmit`],
    ["GET", "/bff/%2e%2e%2f%2e%2e%2fhealth"],
    ["GET", "/bff/@evil.example"],
    ["POST", `/bff${FILE}/export`],
    ["GET", `/bff${FILE}/approve`],
  ])("%s %s is not proxied (404, upstream untouched)", async (method, path) => {
    reset();
    const r = await b.req(path, { method, headers: { origin: WEB, "sec-fetch-site": "same-origin", "x-csrf-token": csrf, "content-type": "application/json" }, body: method === "GET" ? undefined : "{}" });
    // 308 is Next normalising a trailing or doubled slash back to a path on our own origin; either way nothing reaches the upstream
    expect([308, 404, 405]).toContain(r.status);
    if (r.status === 308) expect(new URL(r.location!, WEB).origin).toBe(WEB);
    expect(seen).toHaveLength(0);
  });

  it.each(["/bff/case-files/../me", "/bff/case-files/%2e%2e/me", "/bff/case-files/..%2fme", "/bff/%2e%2e/%2e%2e/health", "/bff/case-files/%2e%2e%2f%2e%2e%2fhealth", "/bff/me/..;/health"])("raw traversal %s: whatever the server makes of it, only allow-listed calls reach the upstream", async (path) => {
    reset();
    // a raw socket: fetch() would normalise the dot segments before sending
    const { Socket } = await import("node:net");
    await new Promise<void>((resolve, reject) => {
      const sock = new Socket();
      sock.connect(3000, "127.0.0.1", () => sock.write(`GET ${path} HTTP/1.1\r\nHost: 127.0.0.1:3000\r\nCookie: ${b.web.header()}\r\nConnection: close\r\n\r\n`));
      sock.on("data", () => undefined);
      sock.on("end", () => resolve());
      sock.on("error", reject);
    });
    const ALLOWED = /^\/(me|case-files(\/[0-9a-f-]{36}(\/(submit|approve|export))?)?)$/;
    for (const s of seen) expect(s.url, s.url).toMatch(ALLOWED);
    expect(seen.some((s) => s.url.includes("health"))).toBe(false);
  });

  it("only the allow-listed calls reach the upstream, with the right method and path", async () => {
    reset();
    const ok: [string, string, unknown?][] = [
      ["GET", "/bff/case-files"],
      ["GET", `/bff${FILE}`],
      ["POST", "/bff/case-files", { title: "t", classification: "OFFICIAL", compartments: [] }],
      ["PATCH", `/bff${FILE}`, { title: "n", version: 1 }],
      ["POST", `/bff${FILE}/submit`, {}],
      ["POST", `/bff${FILE}/approve`, {}],
      ["DELETE", `/bff${FILE}`],
      ["GET", `/bff${FILE}/export`],
    ];
    for (const [m, p, body] of ok) {
      const r = m === "GET" ? await b.req(p) : await b.req(p, { method: m, headers: { origin: WEB, "x-csrf-token": csrf, "content-type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
      expect(r.status, `${m} ${p}`).toBe(200);
    }
    expect(seen.map((s) => `${s.method} ${s.url}`)).toEqual(ok.map(([m, p]) => `${m} ${p.replace("/bff", "")}`));
  });

  it("request body rules: JSON only, size cap, valid JSON", async () => {
    reset();
    const h = { origin: WEB, "sec-fetch-site": "same-origin", "x-csrf-token": csrf };
    expect((await b.req("/bff/case-files", { method: "POST", headers: { ...h, "content-type": "text/plain" }, body: "{}" })).status).toBe(415);
    expect((await b.req("/bff/case-files", { method: "POST", headers: { ...h, "content-type": "application/x-www-form-urlencoded" }, body: "a=b" })).status).toBe(415);
    expect((await b.req("/bff/case-files", { method: "POST", headers: { ...h, "content-type": "application/json" }, body: "{not json" })).status).toBe(400);
    expect((await b.req("/bff/case-files", { method: "POST", headers: { ...h, "content-type": "application/json" }, body: JSON.stringify({ title: "x".repeat(70_000) }) })).status).toBe(413);
    expect(seen).toHaveLength(0);
  });

  it("a redirect from the upstream is never followed (the redirect target receives nothing)", async () => {
    reset();
    mode.redirect = true;
    const hits: string[] = [];
    const { createServer } = await import("node:http");
    const target = createServer((req, res) => (hits.push(`${req.method} ${req.url} auth=${req.headers.authorization ?? "-"}`), res.end("stolen")));
    await new Promise<void>((r) => target.listen(3998, "127.0.0.1", r));
    try {
      const r = await b.req("/bff/me");
      expect(r.status).toBe(502);
      expect(r.headers.get("location")).toBeNull();
      expect(r.text).not.toContain("stolen");
      expect(seen).toHaveLength(1);
      expect(hits).toEqual([]); // the bearer token never travelled to the redirect target
    } finally {
      await new Promise<void>((r) => target.close(() => r()));
    }
  });

  it("an oversized upstream response is cut off (502), not buffered without bound", async () => {
    reset();
    mode.huge = true;
    expect((await b.req("/bff/me")).status).toBe(502);
  });

  it("a slow upstream times out instead of hanging the request", async () => {
    reset();
    mode.slow = true;
    const started = Date.now();
    const r = await b.req("/bff/me");
    expect(r.status).toBe(502);
    expect(Date.now() - started).toBeLessThan(11_500);
  });

  it("the step-up challenge (RFC 9470) passes through the proxy and the pages offer re-authentication", async () => {
    reset();
    mode.stepUp = true;
    const r = await b.req(`/bff${FILE}`);
    expect(r.status).toBe(403);
    expect(r.headers.get("www-authenticate")).toContain('error="insufficient_user_authentication"');
    expect(r.headers.get("www-authenticate")).toContain('acr_values="mfa"');
    const page = await b.req(`/cases/${ID}`);
    expect(page.status).toBe(200);
    expect(page.text).toContain(`/api/auth/login?acr=mfa&amp;returnTo=${encodeURIComponent(`/cases/${ID}`)}`);
    expect(page.text).not.toContain("STEP_UP_REQUIRED"); // no raw API output in the page
  });

  it("break-glass: the justification header goes upstream only from the dedicated route", async () => {
    reset();
    const form = csrfOf((await b.req(`/cases/${ID}/break-glass`)).text);
    const posted = await b.post(`/actions/case-files/${ID}/break-glass`, { csrf: form, justification: "incident 4711 <b>x</b>" });
    expect(posted.status).toBe(303);
    expect(seen).toHaveLength(0); // the POST itself calls nothing upstream; the result page does the read
    const r = await b.req(posted.location!.replace(WEB, ""));
    expect(r.status).toBe(200);
    expect(seen).toHaveLength(1);
    expect(seen[0]!.url).toBe(FILE);
    expect(decodeURIComponent(String(seen[0]!.headers["x-break-glass-justification"]))).toBe("incident 4711 <b>x</b>"); // percent-encoded on the wire: a header is Latin-1, a justification may be in any script
    expect(r.text).not.toContain("<b>x</b>");
    expect(r.headers.get("cache-control")).toBe("no-store");

    reset();
    await b.post(`/actions/case-files/${ID}/submit`, { csrf: form }, { "x-break-glass-justification": "smuggled" });
    await b.req(`/bff${FILE}`, { headers: { "x-break-glass-justification": "smuggled" } });
    await b.post(`/actions/case-files/${ID}/update`, { csrf: form, title: "t", body: "b", version: "1" }, { "x-break-glass-justification": "smuggled" });
    expect(seen.length).toBeGreaterThanOrEqual(3);
    for (const s of seen) expect(s.headers["x-break-glass-justification"]).toBeUndefined();
  });

  it("the hand-over cookie opens the result page only for the case file it was made for, and the page does nothing without it", async () => {
    reset();
    const form = csrfOf((await b.req(`/cases/${ID}/break-glass`)).text);
    await b.post(`/actions/case-files/${ID}/break-glass`, { csrf: form, justification: "incident 4711 ok" });
    reset();
    const other = "1f1e2d3c-4b5a-4968-8776-655443322110";
    const wrongCase = await b.req(`/cases/${other}/break-glass/result`);
    expect([302, 303, 307]).toContain(wrongCase.status);
    expect(wrongCase.location).toMatch(/\/break-glass\?e=expired$/);
    expect(seen.filter((x) => x.url.includes("case-files"))).toHaveLength(0); // no upstream read without a matching justification
    const fresh = new Browser();
    await fresh.login("analyst-official");
    const noCookie = await fresh.req(`/cases/${ID}/break-glass/result`);
    expect(noCookie.location).toMatch(/\/break-glass\?e=expired$/);
    expect(seen.filter((x) => x.url.includes("case-files"))).toHaveLength(0);
  });

  it("a short or blank justification is refused before the upstream is called", async () => {
    reset();
    const form = csrfOf((await b.req(`/cases/${ID}/break-glass`)).text);
    for (const j of ["", "   ", "abcd"]) {
      const r = await b.post(`/actions/case-files/${ID}/break-glass`, { csrf: form, justification: j });
      expect(r.status).toBe(303);
      expect(r.location).toMatch(/\?e=short$/);
    }
    expect(seen).toHaveLength(0);
  });
});
