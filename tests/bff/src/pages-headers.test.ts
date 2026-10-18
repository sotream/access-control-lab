// The functional UI, stored XSS, security headers, and the Secure/__Host- configuration (T-07, T-12, T-31).
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PASSWORD, formAction, nextOtp, step } from "../../identity/src/kc.js";
import { adminPool, clearRows, insertRow } from "../../api-db/src/db.js";
import { Browser, csrfOf, startApi, startWeb, WEB, type Resp, type WebServer } from "./harness.js";

let web: WebServer;
let api: Awaited<ReturnType<typeof startApi>>;
const admin = adminPool();
const ids: Record<string, string> = {};
const XSS = `<script>alert(1)</script><img src=x onerror=alert(2)>"'><svg onload=alert(3)>`;

beforeAll(async () => {
  await clearRows(admin);
  const mk = async (k: string, r: Parameters<typeof insertRow>[1]) => (ids[k] = await insertRow(admin, { status: "approved", ...r }));
  await mk("official", { title: "Official file", body: "plain" });
  await mk("hostile", { title: XSS.slice(0, 100), body: XSS, classification: "CONFIDENTIAL", compartments: ["A"] });
  await mk("secret-a", { title: "Secret A", classification: "SECRET", compartments: ["A"] });
  api = await startApi();
  web = await startWeb();
});
afterAll(async () => {
  await web?.stop();
  await api?.stop();
  await clearRows(admin);
  await admin.end();
});

const scripts = (html: string) => [...html.matchAll(/<script\b[^>]*>/gi)].map((m) => m[0]);

describe("the functional pages (no design, plain HTML)", () => {
  it("unauthenticated visitors are sent to sign in and come back to the page they wanted", async () => {
    const r = await new Browser().req("/cases");
    expect(r.status).toBe(307);
    expect(r.location).toBe("/api/auth/login?returnTo=%2Fcases");
    expect((await new Browser().req("/")).text).toContain("/api/auth/login");
  });

  it("create, edit, submit, approve by someone else, delete a draft: the whole workflow through forms", async () => {
    const a = new Browser();
    await a.login("analyst-official", { returnTo: "/cases/new" });
    const create = await a.post("/actions/case-files/create", { csrf: csrfOf((await a.req("/cases/new")).text), title: "Workflow file", body: "first body", classification: "OFFICIAL", compartments: "" });
    expect(create.status).toBe(303);
    const detail = create.location!.replace(WEB, "").split("?")[0]!;
    const id = detail.split("/").pop()!;

    let page = await a.req(detail);
    expect(page.status).toBe(200);
    expect(page.text).toContain("Workflow file");
    expect(page.text).toContain("draft");
    const csrf = csrfOf(page.text);

    expect((await a.post(`/actions/case-files/${id}/update`, { csrf, title: "Workflow file v2", body: "second body", version: "1" })).location).toContain("m=done");
    expect((await a.post(`/actions/case-files/${id}/update`, { csrf, title: "stale", body: "x", version: "1" })).location).toContain("m=conflict"); // version is now 2
    page = await a.req(detail);
    expect(page.text).toContain("Workflow file v2");

    expect((await a.post(`/actions/case-files/${id}/approve`, { csrf })).location).toContain("m=forbidden"); // analyst cannot approve
    expect((await a.post(`/actions/case-files/${id}/submit`, { csrf })).location).toContain("m=done");

    const r = new Browser();
    await r.login("reviewer");
    const rpage = await r.req(detail);
    expect(rpage.status).toBe(200);
    expect((await r.post(`/actions/case-files/${id}/approve`, { csrf: csrfOf(rpage.text) })).location).toContain("m=done");
    expect((await r.req(detail)).text).toContain("approved");

    expect((await a.post(`/actions/case-files/${id}/delete`, { csrf })).location).toContain("m=forbidden"); // approved files cannot be deleted
    const mine = await a.post("/actions/case-files/create", { csrf, title: "to delete", body: "", classification: "OFFICIAL", compartments: "" });
    const delId = mine.location!.split("?")[0]!.split("/").pop()!;
    const del = await a.post(`/actions/case-files/${delId}/delete`, { csrf });
    expect(del.status).toBe(303);
    expect(del.location).toBe(`${WEB}/cases`);
    expect((await a.req(`/cases/${delId}`)).status).toBe(404);
  });

  it("the list and detail pages show only what the API lets this user see; hidden files are plain 404 pages", async () => {
    const a = new Browser();
    await a.login("analyst-official");
    const list = await a.req("/cases");
    expect(list.text).toContain("Official file");
    expect(list.text).not.toContain("Secret A");
    expect((await a.req(`/cases/${ids["secret-a"]}`)).status).toBe(404);
    expect((await a.req(`/cases/${randomUUID()}`)).status).toBe(404);
    expect((await a.req("/cases/not-a-uuid")).status).toBe(404);
  });

  it("a SECRET user with MFA reads a SECRET file; the same page for someone not cleared is 404", async () => {
    const s = new Browser();
    await s.login("analyst-secret-a");
    expect((await s.req("/session")).text).toContain("mfa");
    const page = await s.req(`/cases/${ids["secret-a"]}`);
    expect(page.status).toBe(200);
    expect(page.text).toContain("Secret A");
    const o = new Browser();
    await o.login("analyst-official");
    expect((await o.req(`/cases/${ids["secret-a"]}`)).status).toBe(404);
  });
});

describe("step-up through the identity provider", () => {
  it("asking for acr=mfa does not grant it on a password alone: Keycloak demands a second factor", async () => {
    const b = new Browser();
    const start = await b.req("/api/auth/login?acr=mfa&returnTo=%2Fsession");
    let r = await step(b.kc, start.location!);
    r = await step(b.kc, formAction(r.text)!, { username: "analyst-official", password: PASSWORD, credentialId: "" });
    expect(r.location ?? "").toContain("CONFIGURE_TOTP"); // enrolment, not a code for the app
    expect(b.cookie("casefile_session")).toBeUndefined();
  });

  it("a SECRET user who signs in with acr=mfa ends up with an MFA session", async () => {
    const b = new Browser();
    const { callback } = await b.login("analyst-secret-b", { acr: "mfa", returnTo: "/session" });
    expect(callback.status).toBe(303);
    expect((await b.req("/session")).text).toMatch(/mfa/);
    void nextOtp;
  });
});

describe("break-glass with real tokens", () => {
  it("a unit-admin of another unit reads a compartmented file through the dedicated form; output is escaped; an alert is logged", async () => {
    const b = new Browser();
    await b.login("unit-admin-beta");
    const direct = await b.req(`/cases/${ids["hostile"]}`);
    expect(direct.status).toBe(404);
    const form = await b.req(`/cases/${ids["hostile"]}/break-glass`);
    expect(form.status).toBe(200);
    const posted = await b.post(`/actions/case-files/${ids["hostile"]}/break-glass`, { csrf: csrfOf(form.text), justification: "incident 4711 " + XSS });
    expect(posted.status).toBe(303); // the audited read happens on the result page; the justification travels in a short-lived cookie, never in the URL
    expect(posted.location).not.toContain("incident");
    const r = await b.req(posted.location!.replace(WEB, ""));
    expect(r.status).toBe(200);
    expect(r.text).toContain("This access was recorded");
    expect(r.text).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(r.text).not.toMatch(/<script>alert/i);
    expect(r.text).not.toMatch(/<img[^>]*onerror/i);
    expect(api.logs.some((l) => l.includes("break_glass_alert") && l.includes("incident 4711"))).toBe(true);
    expect((await b.req(`/cases/${ids["hostile"]}`)).status).toBe(404); // nothing was opened for later
  });

  it("without a justification, and for a role without the grant, nothing is shown", async () => {
    const b = new Browser();
    await b.login("unit-admin-beta");
    const form = csrfOf((await b.req(`/cases/${ids["hostile"]}/break-glass`)).text);
    const blank = await b.post(`/actions/case-files/${ids["hostile"]}/break-glass`, { csrf: form, justification: "    " });
    expect(blank.status).toBe(303);
    expect(blank.location).toMatch(/\/break-glass\?e=short$/);
    const a = new Browser();
    await a.login("analyst-official");
    const posted = await a.post(`/actions/case-files/${ids["hostile"]}/break-glass`, { csrf: csrfOf((await a.req(`/cases/${ids["official"]}/break-glass`)).text), justification: "I would like to read this please" });
    const r = await a.req(posted.location!.replace(WEB, ""));
    expect(r.status).toBe(404);
    expect(r.text).not.toContain("alert(1)");
  });
});

describe("stored XSS renders inert (T-07)", () => {
  it("hostile title and body entered through the form come back escaped on the list, detail and edit form", async () => {
    const b = new Browser();
    await b.login("unit-admin-alpha");
    const created = await b.post("/actions/case-files/create", { csrf: csrfOf((await b.req("/cases/new")).text), title: XSS.slice(0, 100), body: XSS, classification: "OFFICIAL", compartments: "" });
    expect(created.status).toBe(303);
    const detailPath = created.location!.replace(WEB, "").split("?")[0]!;
    for (const path of [detailPath, "/cases"]) {
      const r = await b.req(path);
      expect(r.status).toBe(200);
      expect(r.text).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
      expect(r.text).not.toMatch(/<script>alert/i);
      expect(r.text).not.toMatch(/<img[^>]*onerror/i);
      expect(r.text).not.toMatch(/<svg[^>]*onload/i);
      // every script tag is ours: external with src or carrying the nonce
      for (const tag of scripts(r.text)) expect(tag, tag).toMatch(/\bsrc="\/_next\/|\bnonce="/);
    }
    // attribute context: the edit form's value attribute cannot be broken out of
    const detail = (await b.req(detailPath)).text;
    expect(detail).not.toMatch(/value="[^"]*"[^>]*onerror/i);
    expect(detail).not.toMatch(/"\s*onerror=/i);
  });

  it("the hostile file from the database is inert for a reader who may see it", async () => {
    const b = new Browser();
    await b.login("reviewer");
    const r = await b.req(`/cases/${ids["hostile"]}`);
    expect(r.status).toBe(200);
    expect(r.text).toContain("&lt;script&gt;");
    expect(r.text).not.toMatch(/<script>alert/i);
  });
});

// ---------------------------------------------------------------------------------------------- headers

const REQUIRED: Record<string, RegExp> = {
  "x-content-type-options": /^nosniff$/,
  "x-frame-options": /^DENY$/,
  "referrer-policy": /^same-origin$/,
  "cross-origin-opener-policy": /^same-origin$/,
  "cross-origin-resource-policy": /^same-origin$/,
  "cache-control": /no-store/, // Next adds its own, stricter value on 404 pages: it still contains no-store
  "permissions-policy": /camera=\(\).*microphone=\(\).*geolocation=\(\)/,
};

function checkHeaders(r: Resp, label: string, { hsts }: { hsts: boolean }) {
  for (const [h, re] of Object.entries(REQUIRED)) expect(r.headers.get(h) ?? "", `${label}: ${h}`).toMatch(re);
  const csp = r.headers.get("content-security-policy") ?? "";
  expect(csp, label).toMatch(/default-src 'none'/);
  expect(csp, label).toMatch(/script-src 'self' 'nonce-[A-Za-z0-9+/=]{20,}' 'strict-dynamic'/);
  expect(csp, label).toMatch(/style-src 'self' 'nonce-[A-Za-z0-9+/=]{20,}'/);
  expect(csp, label).toMatch(/frame-ancestors 'none'/);
  expect(csp, label).toMatch(/base-uri 'none'/);
  expect(csp, label).toMatch(/object-src 'none'/);
  expect(csp, label).toMatch(/form-action 'self'/);
  expect(csp, label).not.toContain("unsafe-inline");
  expect(csp, label).not.toContain("unsafe-eval");
  expect(csp, label).not.toMatch(/https?:\/\/(?!127\.0\.0\.1)/); // no third-party origin anywhere
  expect(r.headers.get("x-powered-by"), label).toBeNull();
  if (hsts) {
    expect(r.headers.get("strict-transport-security") ?? "", label).toMatch(/max-age=31536000; includeSubDomains/);
    expect(csp, label).toContain("upgrade-insecure-requests");
  } else expect(r.headers.get("strict-transport-security"), label).toBeNull();
}

describe("security headers (T-07, T-31)", () => {
  it("every kind of response carries them: pages, route handlers, JSON, redirects, errors", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    const csrf = csrfOf((await b.req("/cases/new")).text);
    const responses: [string, Resp][] = [
      ["home", await b.req("/")],
      ["cases", await b.req("/cases")],
      ["session page", await b.req("/session")],
      ["detail", await b.req(`/cases/${ids["official"]}`)],
      ["404 page", await b.req("/cases/not-a-uuid")],
      ["unknown route", await b.req("/nope")],
      ["api session", await b.req("/api/auth/session")],
      ["bff json", await b.req("/bff/me")],
      ["bff refused", await b.req("/bff/health")],
      ["login redirect", await new Browser().req("/api/auth/login")],
      ["protected redirect", await new Browser().req("/cases")],
      ["csrf refusal", await b.req("/api/auth/logout", { method: "POST", headers: { origin: "https://evil.example" } })],
      ["action redirect", await b.post("/actions/case-files/create", { csrf, title: "h", body: "", classification: "OFFICIAL", compartments: "" })],
      ["405", await b.req("/api/auth/logout")],
    ];
    for (const [label, r] of responses) checkHeaders(r, label, { hsts: false });
  });

  it("the nonce is fresh per request and the page's own scripts carry it", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    const a = await b.req("/cases");
    const c = await b.req("/cases");
    const n = (r: Resp) => /'nonce-([^']+)'/.exec(r.headers.get("content-security-policy")!)![1]!;
    expect(n(a)).not.toBe(n(c));
    const tags = scripts(a.text);
    expect(tags.length).toBeGreaterThan(0);
    for (const t of tags) expect(t).toContain(`nonce="${n(a)}"`);
    expect(a.text).not.toMatch(/<script(?![^>]*\bnonce=)(?![^>]*\bsrc=)[^>]*>/i); // no inline script without a nonce
    expect(a.text).not.toMatch(/\son[a-z]+="/i); // no inline event handlers
  });

  it("no third-party resources: every link, script, stylesheet and form target is same-origin", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    for (const p of ["/", "/cases", "/cases/new", "/session", `/cases/${ids["official"]}`]) {
      const r = await b.req(p);
      for (const m of r.text.matchAll(/\b(?:src|href|action)="([^"]+)"/g)) {
        const u = m[1]!;
        expect(u.startsWith("/") || u.startsWith("#") || u.startsWith(WEB), `${p}: ${u}`).toBe(true);
      }
    }
    const css = [...(await b.req("/")).text.matchAll(/href="([^"]+\.css)"/g)].map((m) => m[1]!);
    expect(css).toEqual(["/ui.css"]); // the one self-served, build-time stylesheet
    for (const u of css) {
      const text = await (await fetch(`${WEB}${u}`)).text();
      expect(text).not.toMatch(/@import|url\(\s*["']?(?:https?:)?\/\//i);
      for (const m of text.matchAll(/url\(\s*["']?([^"')]+)/g)) expect(m[1]!.startsWith("/fonts/") || m[1]!.startsWith("data:"), `css url ${m[1]}`).toBe(true); // fonts are ours
    }
    const js = [...(await b.req("/cases")).text.matchAll(/<script[^>]*\bsrc="([^"]+)"/g)].map((m) => m[1]!);
    for (const u of js) expect(u.startsWith("/"), `script ${u}`).toBe(true);
  });

  it("static assets are served with nosniff and are not reachable cross-origin by script (CORP same-origin applies to pages)", async () => {
    const r = await b2().req("/");
    const asset = /src="(\/_next\/static\/[^"]+\.js)"/.exec(r.text)![1]!;
    const a = await fetch(`${WEB}${asset}`);
    expect(a.headers.get("x-content-type-options")).toBe("nosniff");
    expect(a.headers.get("content-type")).toMatch(/javascript/);
  });
});
const b2 = () => new Browser();

describe("Secure cookies and HSTS when configured (https deployment)", () => {
  it("__Host- cookie names, Secure, HttpOnly, Lax, Path=/, no Domain; HSTS and upgrade-insecure-requests on every response", async () => {
    await web.stop();
    web = await startWeb({ COOKIE_SECURE: "true", HSTS_ENABLED: "true" });
    const b = new Browser();
    const start = await b.req("/api/auth/login");
    const pre = start.setCookies.find((c) => c.startsWith("__Host-casefile_pre=") && !c.includes("=;"))!;
    expect(pre).toBeDefined();
    for (const c of [pre]) {
      const a = c.split(";").slice(1).map((x) => x.trim().toLowerCase());
      expect(a).toEqual(expect.arrayContaining(["httponly", "secure", "samesite=lax", "path=/"]));
      expect(a.some((x) => x.startsWith("domain"))).toBe(false);
    }
    const { callback } = await b.login("analyst-official");
    const session = callback.setCookies.find((c) => c.startsWith("__Host-casefile_session=") && !c.includes("=;"))!;
    expect(session).toBeDefined();
    const a = session.split(";").slice(1).map((x) => x.trim().toLowerCase());
    expect(a).toEqual(expect.arrayContaining(["httponly", "secure", "samesite=lax", "path=/"]));
    expect(a.some((x) => x.startsWith("domain"))).toBe(false);
    checkHeaders(await b.req("/cases"), "hsts cases", { hsts: true });
    checkHeaders(await b.req("/bff/me"), "hsts bff", { hsts: true });
    checkHeaders(await b.req("/nope"), "hsts 404", { hsts: true });
    expect((await b.req("/bff/me")).status).toBe(200);
  });

  it("the server refuses to run with insecure cookies on an https origin or without a key ring", async () => {
    await web.stop();
    await expect(startWeb({ WEB_ORIGIN: "https://vault.example", KEYCLOAK_ISSUER: "https://id.example/realms/casefile", API_BASE_URL: "https://api.example", COOKIE_SECURE: "false" })).rejects.toThrow();
    web = await startWeb(); // back to the default for afterAll
  });
});
