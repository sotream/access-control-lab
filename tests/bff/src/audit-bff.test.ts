// Authentication events from the BFF in the audit chain, fail-closed sign-in, and the auditor's page (T-06, T-24, T-26).
import { rowFromDb, verifyChain, type AuditRow } from "@acl/audit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminPool, auditKeys, auditPool, resetAudit, insertRow, clearRows } from "../../api-db/src/db.js";
import { CLIENT_ID, CLIENT_SECRET, OIDC, step } from "../../identity/src/kc.js";
import { Browser, csrfOf, forceExpire, sessionRow, startApi, startWeb, WEB, type WebServer } from "./harness.js";

let web: WebServer;
let api: Awaited<ReturnType<typeof startApi>>;
const admin = adminPool();
const aud = auditPool();
const ring = auditKeys();

beforeAll(async () => {
  api = await startApi();
  web = await startWeb();
});
afterAll(async () => {
  await web?.stop();
  await api?.stop();
  await resetAudit(admin);
  await admin.query("GRANT INSERT ON audit_log TO casefile_web");
  await clearRows(admin);
  await admin.end();
  await aud.end();
});

const rows = async (): Promise<AuditRow[]> => (await aud.query("SELECT * FROM audit_log ORDER BY id")).rows.map(rowFromDb);
const bff = async () => (await rows()).filter((r) => r.source === "bff");
const subOf = async (b: Browser) => (JSON.parse((await b.req("/api/auth/session")).text) as { sub: string }).sub;

describe("sign-in, step-up, sign-out and session kills are in the chain (T-06, T-24)", () => {
  it("a successful sign-in: one allow row with the real subject and nothing else about the request", async () => {
    await resetAudit(admin);
    const b = new Browser();
    await b.login("analyst-official", { returnTo: "/cases" });
    const [row] = await bff();
    expect(row).toMatchObject({ action: "auth.login", effect: "allow", reasonCode: "LOGIN_OK", source: "bff", resourceType: "session", resourceId: null, obligations: ["audit"], actorRoles: [] });
    expect(row!.actorSub).toBe(await subOf(b));
    expect(row!.details).toEqual({ event: "login", acr: "pwd" });
    expect(row!.requestId).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("step-up (acr=mfa) is recorded as such, with the achieved level", async () => {
    await resetAudit(admin);
    const b = new Browser();
    await b.login("analyst-secret-a", { acr: "mfa" });
    const row = (await bff()).find((r) => r.action === "auth.stepup")!;
    expect(row).toMatchObject({ effect: "allow", reasonCode: "LOGIN_OK" });
    expect(row.details).toEqual({ event: "login", acr: "mfa" });
  });

  it("refused callbacks are recorded as anonymous denials with a coarse reason, never with the parameters", async () => {
    await resetAudit(admin);
    const start = new Browser();
    const l = await start.req("/api/auth/login");
    const kc = await step(start.kc, l.location!);
    const done = await step(start.kc, /<form[^>]*action="([^"]+)"/.exec(kc.text)![1]!.replaceAll("&amp;", "&"), { username: "analyst-official", password: process.env.DEV_USER_PASSWORD!, credentialId: "" });
    const url = new URL(done.location!);
    const attempts: [string, Browser, string][] = [
      ["no pre-auth cookie", new Browser(), done.location!.slice(WEB.length)],
    ];
    const bad = new URL(url);
    bad.searchParams.set("state", "CANARY_STATE_7731");
    attempts.push(["state mismatch", start, bad.pathname + bad.search]);
    const err = new URL(url);
    err.searchParams.delete("code");
    err.searchParams.set("error", "access_denied");
    attempts.push(["identity provider error", (() => { const b = new Browser(); b.setCookie("casefile_pre", start.cookie("casefile_pre")!); return b; })(), err.pathname + err.search]);
    for (const [, b, path] of attempts) expect((await b.req(path)).status).toBe(400);
    const got = (await bff()).filter((r) => r.action === "auth.login_failed");
    expect(got.map((r) => r.reasonCode).sort()).toEqual(["CALLBACK_REJECTED", "IDP_ERROR", "NO_PREAUTH"]);
    for (const r of got) expect(r).toMatchObject({ effect: "deny", actorSub: "anonymous", details: {} });
    expect(JSON.stringify(got)).not.toContain("CANARY_STATE_7731");
  });

  it("sign-out is recorded", async () => {
    await resetAudit(admin);
    const b = new Browser();
    await b.login("analyst-official");
    const sub = await subOf(b);
    await b.post("/api/auth/logout", { csrf: csrfOf((await b.req("/")).text) });
    const row = (await bff()).find((r) => r.action === "auth.logout")!;
    expect(row).toMatchObject({ effect: "allow", reasonCode: "LOGOUT", actorSub: sub });
  });

  it("a session killed by a refused refresh (replayed refresh token) is recorded as a denial for that user", async () => {
    await resetAudit(admin);
    const b = new Browser();
    await b.login("analyst-official");
    const sid = b.cookie("casefile_session")!;
    const sub = await subOf(b);
    const r0 = (await sessionRow(sid))!.tokens.refreshToken;
    await forceExpire(sid);
    expect((await b.req("/bff/me")).status).toBe(200);
    const replay = await fetch(`${OIDC}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: r0, client_id: CLIENT_ID, client_secret: CLIENT_SECRET }) });
    expect(replay.status).toBe(400);
    await forceExpire(sid);
    expect((await b.req("/bff/me")).status).toBe(401);
    await new Promise((r) => setTimeout(r, 300)); // the audit write is fire-and-forget on purpose
    const killed = (await bff()).find((r) => r.action === "auth.session_killed")!;
    expect(killed).toMatchObject({ effect: "deny", reasonCode: "REFRESH_REFUSED", actorSub: sub });
  });

  it("a refused CSRF check is recorded with the reason and the session's subject", async () => {
    await resetAudit(admin);
    const b = new Browser();
    await b.login("analyst-official");
    const sub = await subOf(b);
    await b.req("/api/auth/logout", { method: "POST", headers: { origin: "https://evil.example", "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: "x" }) });
    await b.post("/api/auth/logout", { csrf: "wrong" });
    const denied = (await bff()).filter((r) => r.action === "auth.csrf_denied");
    expect(denied.map((r) => r.reasonCode)).toEqual(["ORIGIN_MISMATCH", "TOKEN_MISMATCH"]);
    for (const r of denied) expect(r).toMatchObject({ effect: "deny", actorSub: sub });
  });

  it("no cookie, token, state, nonce, code or URL ever reaches an audit row", async () => {
    await resetAudit(admin);
    const b = new Browser();
    const { callbackUrl } = await b.login("analyst-secret-b", { acr: "mfa", returnTo: "/cases?CANARY_RETURN_8842=1" });
    const sid = b.cookie("casefile_session")!;
    const tokens = (await sessionRow(sid))!.tokens;
    await b.post("/api/auth/logout", { csrf: csrfOf((await b.req("/")).text) });
    const dump = JSON.stringify((await aud.query("SELECT * FROM audit_log")).rows);
    const u = new URL(callbackUrl);
    for (const secret of [sid, tokens.accessToken, tokens.refreshToken, tokens.idToken, u.searchParams.get("state")!, u.searchParams.get("code")!, "CANARY_RETURN_8842", "http://", WEB]) expect(dump, secret.slice(0, 20)).not.toContain(secret);
    expect(dump).not.toMatch(/eyJ[A-Za-z0-9_-]{8,}\./);
  });
});

describe("fail closed for sign-in, never for sign-out (T-24)", () => {
  async function withBffAuditBroken<T>(fn: () => Promise<T>): Promise<T> {
    await admin.query("REVOKE INSERT ON audit_log FROM casefile_web");
    try {
      return await fn();
    } finally {
      await admin.query("GRANT INSERT ON audit_log TO casefile_web");
    }
  }

  it("when the audit write fails, the sign-in does not happen: 503, no session cookie, no session row", async () => {
    await resetAudit(admin);
    const b = new Browser();
    const before = (await admin.query("SELECT count(*)::int AS n FROM bff_sessions")).rows[0].n;
    const attempt = await withBffAuditBroken(() => b.login("analyst-official"));
    expect(attempt.callback.status).toBe(503); // instead of the usual 303 with a session cookie
    expect(attempt.callback.setCookies.some((c) => c.startsWith("casefile_session=") && !c.startsWith("casefile_session=;"))).toBe(false);
    expect(b.cookie("casefile_session")).toBeUndefined();
    expect((await admin.query("SELECT count(*)::int AS n FROM bff_sessions")).rows[0].n).toBe(before);
    // and it recovers by itself
    const ok = new Browser();
    await ok.login("analyst-official");
    expect(ok.cookie("casefile_session")).toBeDefined();
  });

  it("signing out still works when the audit write fails: a security-reducing action is never blocked by the log", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    const csrf = csrfOf((await b.req("/")).text);
    const out = await withBffAuditBroken(() => b.post("/api/auth/logout", { csrf }));
    expect(out.status).toBe(303);
    expect((await b.req("/bff/me")).status).toBe(401);
  });
});

describe("the auditor's page and export through the BFF (T-24, T-12)", () => {
  const XSS = `<script>alert(1)</script>`;
  beforeAll(async () => {
    await resetAudit(admin);
    await clearRows(admin);
    await insertRow(admin, { title: "x" });
    const w = new Browser();
    await w.login("analyst-official");
    for (let i = 0; i < 60; i++) await w.req("/bff/case-files"); // a policy route: every call is an audited decision
  });

  it("an auditor sees the log, the analyst is told it is not for them", async () => {
    const a = new Browser();
    await a.login("auditor");
    const page = await a.req("/audit");
    expect(page.status).toBe(200);
    expect(page.text).toContain("auth.login");
    expect(page.text).toContain("Audit log");
    const analyst = new Browser();
    await analyst.login("analyst-official");
    const denied = await analyst.req("/audit");
    expect(denied.text).toContain("Only auditors");
    expect(denied.text).not.toContain("auth.login");
    expect((await new Browser().req("/audit")).status).toBe(307);
  });

  it("pagination links carry an opaque cursor; filters narrow; malformed filters are not reflected", async () => {
    const a = new Browser();
    await a.login("auditor");
    const page = await a.req("/audit?action=auth.login");
    expect(page.text).toContain("auth.login");
    const link = /href="(\/audit\?[^"]*cursor=[^"]+)"/.exec((await a.req("/audit")).text);
    // 50 rows per page: more than one page exists
    expect(link).not.toBeNull();
    const second = await a.req(link![1]!.replaceAll("&amp;", "&"));
    expect(second.status).toBe(200);
    const evil = await a.req(`/audit?actor=${encodeURIComponent(`"><script>alert(1)</script>`)}`);
    expect(evil.text).toContain("not available");
    expect(evil.text).not.toContain("auth.login");
    expect(evil.text).not.toMatch(/<script>alert/i);
    const forged = await a.req("/audit?cursor=audit-1.5.00000000000000000000000000000000");
    expect(forged.text).not.toContain("auth.login"); // refused by the API, no rows
    const unknown = await a.req("/audit?password=x&effect=deny");
    expect(unknown.status).toBe(200); // unknown parameters are simply not forwarded
  });

  it("export: NDJSON and CSV downloads with a proof; the export is a row of its own; CSRF is required", async () => {
    const a = new Browser();
    await a.login("auditor");
    const csrf = csrfOf((await a.req("/audit")).text);
    const nd = await a.post("/actions/audit/export", { csrf, format: "ndjson" });
    expect(nd.status).toBe(200);
    expect(nd.headers.get("content-type")).toContain("application/x-ndjson");
    expect(nd.headers.get("content-disposition")).toContain("attachment");
    expect(nd.headers.get("x-content-type-options")).toBe("nosniff");
    expect(JSON.parse(Buffer.from(nd.headers.get("x-audit-proof")!, "base64").toString()).chain).toBe("acl-audit/v1");
    const lines = nd.text.trim().split("\n");
    expect(JSON.parse(lines.at(-1)!).proof.rows).toBe(lines.length - 1);
    const csv = await a.post("/actions/audit/export", { csrf, format: "csv" });
    expect(csv.headers.get("content-type")).toContain("text/csv");
    expect(csv.text.split("\r\n")[0]).toContain("id,ts,actor_sub");
    expect((await rows()).filter((r) => r.action === "audit.export")).toHaveLength(2);
    // forged export requests are refused and produce no export row
    const count = (await rows()).filter((r) => r.action === "audit.export").length;
    expect((await a.req("/actions/audit/export", { method: "POST", headers: { origin: "https://evil.example", "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf, format: "csv" }) })).status).toBe(403);
    expect((await a.post("/actions/audit/export", { format: "csv" })).status).toBe(403);
    expect((await rows()).filter((r) => r.action === "audit.export")).toHaveLength(count);
    const analyst = new Browser();
    await analyst.login("analyst-official");
    expect((await analyst.post("/actions/audit/export", { csrf: csrfOf((await analyst.req("/cases/new")).text), format: "csv" })).status).toBe(403);
  });

  it("the verification page reports a sound chain", async () => {
    const a = new Browser();
    await a.login("auditor");
    const r = await a.req("/audit/verify");
    expect(r.text).toContain("The chain verifies");
  });

  it("the whole mixed chain (API decisions and BFF events written by two processes) verifies end to end", async () => {
    const all = await rows();
    expect(all.some((r) => r.source === "bff")).toBe(true);
    expect(all.some((r) => r.source === "api")).toBe(true);
    const head = (await aud.query("SELECT last_id::int AS id, last_hash FROM audit_head")).rows[0];
    expect(await verifyChain(all, ring, { head: { lastId: head.id, lastHash: head.last_hash } })).toMatchObject({ ok: true });
    void XSS;
  });
});
