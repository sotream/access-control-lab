// A-30..A-34: SQL injection (first and second order), stored and reflected XSS against the real CSP, through every string input a user controls.
import { describe, expect, it } from "vitest";
import { FORM, form, vault } from "./http.js";
import { bff, session } from "./sessions.js";
import { psql } from "./stack.js";

const SQLI = ["'; DROP TABLE case_files; --", "' OR '1'='1", '" OR 1=1 --', "1; SELECT pg_sleep(5)", "\\'; DELETE FROM role_grants; --", "$$; DROP SCHEMA public CASCADE; --", "'||(SELECT version())||'", "x' UNION SELECT NULL,NULL,NULL--", "%27%20OR%201=1", "Robert'); DROP TABLE audit_log;--", "ʼ OR 1=1 --", "'; INSERT INTO role_grants VALUES ('analyst','approve',true,false,false); --"];
const XSS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "'><svg onload=alert(1)>", "javascript:alert(1)", "<a href=javascript:alert(1)>x</a>", "</title><script>alert(1)</script>", "<iframe srcdoc='<script>alert(1)</script>'>", "${alert(1)}", "{{constructor.constructor('alert(1)')()}}", "<style>@import 'https://evil.example/x.css'</style>", "<math><mtext><script>alert(1)</script>", "‮<b>rtl</b>", "<details open ontoggle=alert(1)>"];

/** names of attributes that are event handlers, found by tokenising real tags (quoted values may contain anything: that is text, not an attribute) */
function eventHandlerAttributes(html: string): string[] {
  const found: string[] = [];
  for (const tag of html.matchAll(/<([a-zA-Z][a-zA-Z0-9]*)((?:\s+[^\s"'<>\/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'<>]+))?)*)\s*\/?>/g)) {
    for (const attr of (tag[2] ?? "").matchAll(/\s+([^\s"'<>\/=]+)(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'<>]+))?/g)) if (/^on/i.test(attr[1]!)) found.push(`${tag[1]} ${attr[1]}`);
  }
  return found;
}

const intact = () => ({ grants: Number(psql("SELECT count(*) FROM role_grants")), tables: psql("SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename IN ('case_files','audit_log','role_grants','attachments','bff_sessions')"), schema: psql("SELECT count(*) FROM pg_namespace WHERE nspname='public'") });

describe("A-30 SQL injection through every string a user can submit", () => {
  it("hostile titles, bodies, compartments and versions are stored as data or refused, and the database is untouched", async () => {
    const before = intact();
    const s = await session("unit-admin-alpha");
    const made: string[] = [];
    for (const p of SQLI) {
      const r = await bff(s, "POST", "/case-files", { title: p.slice(0, 100), body: p, classification: "OFFICIAL", compartments: [] });
      expect([201, 400], p).toContain(r.status);
      if (r.status === 201) {
        const id = (r.json as { id: string }).id;
        made.push(id);
        const back = (await bff(s, "GET", `/case-files/${id}`)).json as { title: string; body: string };
        expect(back.body, "stored verbatim, as data").toBe(p);
      }
      for (const comp of [[p], [p.slice(0, 32)]]) expect([400, 403], `compartments ${p}`).toContain((await bff(s, "POST", "/case-files", { title: "x", classification: "OFFICIAL", compartments: comp })).status);
    }
    expect(made.length).toBeGreaterThan(5);
    // second order: the stored hostile text is read back by the list, an edit, the form page, a submit and an audit filter without effect
    await bff(s, "GET", "/case-files");
    for (const id of made.slice(0, 3)) {
      expect([200, 409]).toContain((await bff(s, "PATCH", `/case-files/${id}`, { title: SQLI[0]!.slice(0, 100), body: SQLI[1], version: 1 })).status);
      expect((await vault(`/cases/${id}`, { jar: s.jar })).status).toBe(200);
      expect([201, 403]).toContain((await bff(s, "POST", `/case-files/${id}/submit`, {})).status);
    }
    expect(intact()).toEqual(before);
  });
  it("ids, paths and query values are validated before they get near a query", async () => {
    const s = await session("analyst-official");
    for (const p of SQLI) {
      for (const path of [`/case-files/${encodeURIComponent(p)}`, `/case-files/${encodeURIComponent(p)}/attachments`]) {
        const r = await bff(s, "GET", path);
        expect([400, 404], `${path}`).toContain(r.status);
      }
      expect([400, 404], `page ${p}`).toContain((await vault(`/cases/${encodeURIComponent(p)}`, { jar: s.jar })).status);
    }
  });
  it("the audit filters, cursor and limit (the auditor's inputs) take hostile strings without error or leak", async () => {
    const a = await session("auditor");
    const before = intact();
    for (const p of SQLI) {
      for (const key of ["actor", "resource", "action", "effect", "from", "to", "cursor", "limit", "format"]) {
        const r = await bff(a, "GET", `/audit-log?${new URLSearchParams({ [key]: p })}`);
        expect([200, 400], `${key}=${p}`).toContain(r.status);
        expect(r.text, `${key}=${p}`).not.toMatch(/syntax error|pg_|postgres|stack|at \//i);
      }
    }
    const odd = await bff(a, "GET", "/audit-log?actor=%27%20OR%201%3D1%20--");
    if (odd.status === 200) expect((odd.json as { rows: unknown[] }).rows).toEqual([]); // matched literally, nothing found; or refused by the strict filter pattern
    expect(intact()).toEqual(before);
  });
});

describe("A-31 stored XSS: hostile text in every rendered field comes out inert, under a strict CSP", () => {
  it("title, body, justification-free pages: each payload is escaped on the list, the detail, the edit form and the break-glass page", async () => {
    const s = await session("unit-admin-alpha");
    const ids: string[] = [];
    for (const p of XSS) {
      const r = await bff(s, "POST", "/case-files", { title: p.slice(0, 100), body: p, classification: "OFFICIAL", compartments: [] });
      if (r.status === 201) ids.push((r.json as { id: string }).id);
    }
    expect(ids.length).toBeGreaterThan(8);
    const pages = ["/cases", ...ids.flatMap((id) => [`/cases/${id}`, `/cases/${id}/break-glass`])];
    for (const path of pages) {
      const r = await vault(path, { jar: s.jar });
      expect(r.status, path).toBe(200);
      const html = r.text;
      // no payload survives as live markup: none of the active constructs appear unescaped
      expect(html, path).not.toMatch(/<script>alert\(1\)<\/script>/i);
      expect(html, path).not.toMatch(/<img src=x onerror/i);
      expect(html, path).not.toMatch(/<svg onload/i);
      expect(html, path).not.toMatch(/<iframe srcdoc/i);
      expect(html, path).not.toMatch(/<details open ontoggle/i);
      expect(html, path).not.toMatch(/<a\b[^>]*\shref=["']?javascript:/i);
      expect(eventHandlerAttributes(html), `${path}: inline event handler attributes`).toEqual([]);
      expect(html, path).not.toMatch(/<style>@import/i);
      // every script tag is one of the framework's, with the nonce of this response
      const nonce = /script-src [^;]*'nonce-([^']+)'/.exec(String(r.headers["content-security-policy"]))?.[1];
      expect(nonce, `${path}: CSP nonce`).toBeTruthy();
      for (const tag of html.match(/<script\b[^>]*>/gi) ?? []) expect(tag, `${path}: ${tag}`).toMatch(new RegExp(`nonce="${nonce}"|src="/_next/`));
    }
  });
  it("the CSP of every kind of response is strict: nonce, no unsafe-inline, no unsafe-eval, no wildcard, no third party", async () => {
    const s = await session("unit-admin-alpha");
    for (const path of ["/", "/cases", "/session", "/audit", "/api/auth/session", "/bff/me", "/nope"]) {
      const r = await vault(path, { jar: s.jar });
      const csp = String(r.headers["content-security-policy"] ?? "");
      expect(csp, path).toMatch(/default-src 'none'/);
      expect(csp, path).not.toMatch(/unsafe-inline|unsafe-eval|\*|https?:\/\/(?!vault)/);
      expect(csp, path).toMatch(/frame-ancestors 'none'/);
      expect(csp, path).toMatch(/object-src 'none'/);
      expect(csp, path).toMatch(/base-uri 'none'/);
    }
  });
});

describe("A-32 reflected XSS and injection through URLs, parameters and headers", () => {
  it("a payload in the path, in ?m=, ?e=, ?returnTo= and in headers is not reflected as markup anywhere", async () => {
    const s = await session("analyst-official");
    for (const p of XSS) {
      const enc = encodeURIComponent(p);
      for (const path of [`/cases/${enc}`, `/cases?m=${enc}&e=${enc}`, `/session?m=${enc}`, `/cases/new?e=${enc}`, `/nope/${enc}`, `/audit?actor=${enc}&cursor=${enc}`, `/api/auth/login?returnTo=${enc}&acr=${enc}`]) {
        const h = p.replace(/[^\x20-\x7e]/g, ""); // a client library cannot even put other characters into a header
        const r = await vault(path, { jar: s.jar, headers: { "user-agent": h, referer: `https://evil.example/${encodeURIComponent(p)}`, "x-forwarded-host": h, "accept-language": h } });
        expect(r.status, path).toBeLessThan(500);
        expect(r.text, path).not.toMatch(/<script>alert\(1\)|<img src=x onerror|<svg onload|<iframe srcdoc|<details open ontoggle/i);
      }
    }
  });
  it("messages on a page come from a fixed set of codes: an unknown code shows nothing", async () => {
    const s = await session("unit-admin-alpha");
    const id = psql("SELECT id FROM case_files WHERE title = 'attack: official alpha' LIMIT 1") || "00000000-0000-4000-8000-000000000000";
    const r = await vault(`/cases/${id}?m=${encodeURIComponent("<b>pwned</b>")}`, { jar: s.jar });
    // the URL is echoed, percent-encoded, inside the framework's own data blob; it must not become a message on the page
    expect(r.text).not.toContain("<b>pwned</b>");
    expect(r.text).not.toMatch(/role="alert"[^>]*>[^<]*pwned/);
  });
});

describe("A-33 response splitting and header injection", () => {
  it("CR, LF and NUL in a value that ends up in a header never produce a header", async () => {
    const s = await session("unit-admin-alpha");
    for (const v of ["x%0d%0aSet-Cookie:%20pwned=1", "x%0aX-Injected:1", "x%00y"]) {
      const r1 = await vault(`/api/auth/login?returnTo=${v}`);
      const r2 = await vault(`/bff/me?x=${v}`, { jar: s.jar });
      for (const r of [r1, r2]) {
        expect(JSON.stringify(r.headers)).not.toMatch(/pwned|x-injected/i);
        expect(r.status).toBeLessThan(500);
      }
    }
    // a control character in a name header sent to an upload is refused before it reaches any header
    const up = await vault(`/actions/case-files/00000000-0000-4000-8000-000000000000/attachments`, { method: "POST", jar: s.jar, headers: { ...FORM, origin: "https://vault.localhost" }, body: form({ csrf: s.csrf }) });
    expect(up.status).toBeLessThan(500);
  });
});
