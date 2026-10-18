// The audit trail end to end with real Keycloak tokens: what is recorded, fail closed, the auditor's endpoints, exports, verification (T-24..T-26).
import { parseZoneKeys, signZone } from "@acl/netguard";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { verifyChain, rowFromDb, type AuditRow } from "@acl/audit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../../../apps/api/src/app.js";
import { loadConfig } from "../../../apps/api/src/config.js";
import { JsonLogger } from "../../../apps/api/src/http/logger.js";
import { decode, login, REALM_URL, type Tokens } from "../../identity/src/kc.js";
import { SEED } from "../../identity/src/seed.js";
import { adminPool, appUrl, auditKeys, auditPool, auditUrl, clearRows, insertRow, resetAudit } from "./db.js";

type User = keyof typeof SEED;
const run = promisify(execFile);
const admin = adminPool();
const aud = auditPool();
const ring = auditKeys();
const tokens = new Map<string, Tokens>();
const ids: Record<string, string> = {};
const logs: string[] = [];
let url = "";
let close: () => Promise<void>;

/** what the BFF would send: the managed zone, signed for the token's subject (the API accepts a zone from nobody else) */
const zoneHeader = (accessToken: string) => ({ "x-acl-zone": signZone(parseZoneKeys(process.env.ZONE_SIGNING_KEYS!), "managed", JSON.parse(Buffer.from(accessToken.split(".")[1]!, "base64url").toString()).sub as string, Math.floor(Date.now() / 1000)) });

async function call(user: User, method: string, path: string, body?: unknown, headers: Record<string, string> = {}, base = url) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { authorization: `Bearer ${tokens.get(user)!.access_token}`, ...zoneHeader(tokens.get(user)!.access_token), ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json: Record<string, unknown> & unknown[] = {} as never;
  try {
    json = JSON.parse(text);
  } catch {
    /* not json */
  }
  return { status: res.status, body: json, text, headers: res.headers };
}
const sub = (u: User) => decode(tokens.get(u)!.access_token).claims.sub as string;
const dbRows = async (): Promise<AuditRow[]> => (await aud.query("SELECT * FROM audit_log ORDER BY id")).rows.map(rowFromDb);

async function start(env: Record<string, string> = {}) {
  const cfg = loadConfig({ KEYCLOAK_ISSUER: REALM_URL, DATABASE_URL: appUrl(), AUDIT_HMAC_KEYS: process.env.AUDIT_HMAC_KEYS!, ZONE_SIGNING_KEYS: process.env.ZONE_SIGNING_KEYS!, THROTTLE_LIMIT: "100000", AUTH_FAIL_LIMIT: "10000", AUDIT_CHECKPOINT_SECONDS: "0", ...env });
  const app = await createApp(cfg, { logger: new JsonLogger((l) => logs.push(l)), clock: () => Date.UTC(2026, 9, 17, 12, 0, 0) });
  await app.listen(0, "127.0.0.1");
  return { app, base: `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}` };
}

beforeAll(async () => {
  await clearRows(admin);
  await resetAudit(admin);
  const mk = async (k: string, r: Parameters<typeof insertRow>[1]) => (ids[k] = await insertRow(admin, { title: k, status: "approved", ...r }));
  await mk("official", {});
  await mk("secret-a", { classification: "SECRET", compartments: ["A"] });
  await mk("conf-a", { classification: "CONFIDENTIAL", compartments: ["A"] });
  await mk("official-comp-a", { compartments: ["A"] });
  const s = await start();
  url = s.base;
  close = () => s.app.close();
  for (const u of Object.keys(SEED)) tokens.set(u, await login(u));
}, 300_000);
afterAll(async () => {
  await close?.();
  await clearRows(admin);
  await resetAudit(admin);
  await admin.end();
  await aud.end();
});

describe("every policy decision is audited, with the real reason (T-24)", () => {
  it("allow, hidden-as-404, not found, create and role-only decisions each leave a row correlated by request id", async () => {
    await resetAudit(admin);
    const reqs: [string, Awaited<ReturnType<typeof call>>][] = [
      ["read ok", await call("analyst-official", "GET", `/case-files/${ids["official"]}`)],
      ["read hidden by clearance", await call("analyst-official", "GET", `/case-files/${ids["secret-a"]}`)],
      ["read hidden by compartment", await call("analyst-official", "GET", `/case-files/${ids["official-comp-a"]}`)],
      ["read missing", await call("analyst-official", "GET", `/case-files/00000000-0000-4000-8000-0000000000aa`)],
      ["create", await call("analyst-official", "POST", "/case-files", { title: "t", classification: "OFFICIAL", compartments: [] })],
      ["create above clearance", await call("analyst-official", "POST", "/case-files", { title: "t", classification: "SECRET", compartments: [] })],
      ["list", await call("analyst-official", "GET", "/case-files")],
      ["auditor listing case files (role)", await call("auditor", "GET", "/case-files")],
    ];
    const statuses = reqs.map(([, r]) => r.status);
    expect(statuses).toEqual([200, 404, 404, 404, 201, 403, 200, 403]);
    const rows = await dbRows();
    expect(rows).toHaveLength(8);
    const byReq = new Map(rows.map((r) => [r.requestId, r]));
    const expected: [number, string, string, string, string | null][] = [
      [0, "allow", "ALLOWED", "read", ids["official"]!],
      [1, "deny", "CLEARANCE_TOO_LOW", "read", ids["secret-a"]!], // the client saw 404; the log has the truth
      [2, "deny", "COMPARTMENT_MISSING", "read", ids["official-comp-a"]!],
      [3, "deny", "RESOURCE_NOT_FOUND", "read", "00000000-0000-4000-8000-0000000000aa"], // the id the client asked for is recorded (probing is visible)
      [4, "allow", "ALLOWED", "create", null],
      [5, "deny", "CLEARANCE_TOO_LOW", "create", null],
      [6, "allow", "ALLOWED", "read", null],
      [7, "deny", "ROLE_NOT_PERMITTED", "read", null],
    ];
    for (const [i, effect, reason, action, resourceId] of expected) {
      const r = byReq.get(reqs[i]![1].headers.get("x-request-id")!);
      expect(r, reqs[i]![0]).toBeDefined();
      expect(r).toMatchObject({ effect, reasonCode: reason, action, resourceId, resourceType: "case_file", source: "api" });
    }
    expect(byReq.get(reqs[0]![1].headers.get("x-request-id")!)).toMatchObject({ actorSub: sub("analyst-official"), actorRoles: ["analyst"], obligations: ["audit"] });
    expect(byReq.get(reqs[7]![1].headers.get("x-request-id")!)).toMatchObject({ actorSub: sub("auditor"), actorRoles: ["auditor"] });
    expect((await verifyChain(rows, ring)).ok).toBe(true);
  });

  it("unauthenticated and malformed requests leave no row (no identity to record) and no 500", async () => {
    await resetAudit(admin);
    for (const h of [{} as Record<string, string>, { authorization: "Bearer x.y.z" }, { authorization: "Basic abc" }]) {
      const r = await fetch(`${url}/case-files/${ids["official"]}`, { headers: h });
      expect(r.status).toBe(401);
    }
    expect(await dbRows()).toHaveLength(0);
  });

  it("an authoritative refusal inside the transaction (state changed after the guard) is audited too", async () => {
    await resetAudit(admin);
    const made = await call("unit-admin-alpha", "POST", "/case-files", { title: "case", classification: "OFFICIAL", compartments: [] });
    const id = made.body.id as string;
    await call("unit-admin-alpha", "POST", `/case-files/${id}/submit`);
    const self = await call("unit-admin-alpha", "POST", `/case-files/${id}/approve`);
    expect(self.status).toBe(403);
    const rows = (await dbRows()).filter((r) => r.action === "approve");
    expect(rows.length).toBeGreaterThanOrEqual(1);
    expect(rows.at(-1)).toMatchObject({ effect: "deny", reasonCode: "SEPARATION_OF_DUTIES" });
    expect(rows.at(-1)!.requestId).toBe(self.headers.get("x-request-id"));
  });

  it("break-glass: the justification is stored sanitised, an alert marker is set, the real subject is the actor", async () => {
    await resetAudit(admin);
    const shy = String.fromCodePoint(0xad); // headers cannot carry bidi controls over fetch; the unit tests cover those
    const r = await call("unit-admin-beta", "GET", `/case-files/${ids["conf-a"]}`, undefined, { "x-break-glass-justification": `incident 4711 ${shy}evil\t=cmd` });
    expect(r.status).toBe(200);
    const row = (await dbRows()).find((x) => x.reasonCode === "ALLOWED_BREAK_GLASS")!;
    expect(row).toMatchObject({ effect: "allow", action: "read", actorSub: sub("unit-admin-beta"), resourceId: ids["conf-a"], obligations: ["audit", "alert"] });
    expect(row.details).toMatchObject({ alert: true, justification: "incident 4711 evil =cmd" });
    expect(JSON.stringify(row.details)).not.toContain(shy);
    expect(row.requestId).toBe(r.headers.get("x-request-id"));
    // a refused break-glass attempt is recorded as well, with the attempted justification
    const refused = await call("analyst-official", "GET", `/case-files/${ids["conf-a"]}`, undefined, { "x-break-glass-justification": "I would like to read this" });
    expect(refused.status).toBe(404);
    const denyRow = (await dbRows()).find((x) => x.requestId === refused.headers.get("x-request-id"))!;
    expect(denyRow).toMatchObject({ effect: "deny", actorSub: sub("analyst-official") });
  });

  it("rows never contain tokens, claims, cookies, query strings, request bodies or headers (canary scan)", async () => {
    await resetAudit(admin);
    const canaries = ["CANARY_QUERY_5521", "CANARY_HEADER_5522", "CANARY_COOKIE_5523", "CANARY_BODY_5524", "CANARY_UA_5525"];
    const pathId = "CANARY_PATHID_5526"; // an id-shaped value in the path IS recorded (as resource_id, so probing is visible); nothing else of the request is
    const t = tokens.get("analyst-official")!;
    await call("analyst-official", "GET", `/case-files/${ids["official"]}?token=${canaries[0]}&access_token=${t.access_token}`, undefined, { "x-canary": canaries[1]!, cookie: `session=${canaries[2]}`, "user-agent": canaries[4]!, "x-forwarded-for": "10.9.8.7" });
    await call("analyst-official", "POST", "/case-files", { title: canaries[3], body: canaries[3], classification: "OFFICIAL", compartments: [] }, { "x-canary": canaries[1]! });
    await call("analyst-official", "GET", `/case-files/${pathId}`);
    const dump = JSON.stringify((await aud.query("SELECT * FROM audit_log")).rows);
    for (const c of canaries) expect(dump, c).not.toContain(c);
    const probed = (await dbRows()).find((r) => r.resourceId === pathId)!;
    expect(probed).toMatchObject({ effect: "deny", reasonCode: "RESOURCE_NOT_FOUND" });
    expect(dump.split(pathId).length - 1).toBe(1); // exactly once, in resource_id
    for (const secret of [t.access_token, t.access_token.split(".")[2]!, t.refresh_token, t.id_token]) expect(dump).not.toContain(secret);
    expect(dump).not.toMatch(/eyJ[A-Za-z0-9_-]{8,}\./);
    for (const claim of ["realm_access", '"clearance"', '"compartments"', "preferred_username", "email", "10.9.8.7", "127.0.0.1"]) expect(dump, claim).not.toContain(claim);
    expect(logs.join("\n")).not.toContain(t.access_token);
  });
});

describe("fail closed: no audit, no action (T-24)", () => {
  async function withAuditBroken<T>(fn: () => Promise<T>): Promise<T> {
    await admin.query("REVOKE INSERT ON audit_log FROM casefile_app");
    try {
      return await fn();
    } finally {
      await admin.query("GRANT INSERT ON audit_log TO casefile_app");
    }
  }

  it("when the audit table cannot be written, allowed decisions become 503 and nothing happens", async () => {
    await resetAudit(admin);
    const before = (await admin.query("SELECT count(*)::int AS n FROM case_files")).rows[0].n;
    const results = await withAuditBroken(async () => ({
      read: await call("analyst-official", "GET", `/case-files/${ids["official"]}`),
      list: await call("analyst-official", "GET", "/case-files"),
      create: await call("analyst-official", "POST", "/case-files", { title: "must not exist", classification: "OFFICIAL", compartments: [] }),
      auditor: await call("auditor", "GET", "/audit-log"),
    }));
    expect(results.read.status).toBe(503);
    expect(results.list.status).toBe(503);
    expect(results.create.status).toBe(503);
    expect(results.auditor.status).toBe(503);
    expect(results.read.body).toEqual({ statusCode: 503, error: "Service Unavailable" });
    expect((await admin.query("SELECT count(*)::int AS n FROM case_files")).rows[0].n).toBe(before);
    expect((await admin.query("SELECT 1 FROM case_files WHERE title = 'must not exist'")).rows).toHaveLength(0);
    expect(logs.some((l) => l.includes("audit_write_failed"))).toBe(true);
    // and it recovers by itself
    expect((await call("analyst-official", "GET", `/case-files/${ids["official"]}`)).status).toBe(200);
    expect((await dbRows()).length).toBe(1);
  });

  it("refusals are still refusals when the audit write fails (a deny does not become a 503, and nothing leaks)", async () => {
    const r = await withAuditBroken(async () => ({
      hidden: await call("analyst-official", "GET", `/case-files/${ids["secret-a"]}`),
      role: await call("auditor", "GET", "/case-files"),
    }));
    expect(r.hidden.status).toBe(404);
    expect(r.role.status).toBe(403);
  });

  it("an audit export fails closed too: no audit row for the export, no data", async () => {
    const r = await withAuditBroken(async () => call("auditor", "GET", "/audit-log/export"));
    expect(r.status).toBe(503);
    expect(r.text).not.toContain("actor_sub");
  });
});

describe("the auditor's endpoints (T-24, T-12)", () => {
  async function seedRows(n: number) {
    await resetAudit(admin);
    for (let i = 0; i < n; i++) await call(i % 2 ? "analyst-official" : "reviewer", "GET", `/case-files/${ids["official"]}`);
  }

  it("only the auditor role reads the log; everyone else is refused and sees nothing", async () => {
    await seedRows(3);
    for (const u of ["analyst-official", "analyst-secret-a", "reviewer", "unit-admin-alpha", "unit-admin-beta", "platform-admin"] as User[]) {
      for (const p of ["/audit-log", "/audit-log/export", "/audit-log/checkpoints", "/audit-log/verify"]) {
        const r = await call(u, "GET", p);
        expect(r.status, `${u} ${p}`).toBe(403);
        expect(r.text).not.toContain("actor_sub");
      }
    }
    expect((await call("auditor", "GET", "/audit-log")).status).toBe(200);
    expect((await fetch(`${url}/audit-log`)).status).toBe(401);
  });

  it("the auditor reads the log but not the case files; reading the log is itself audited", async () => {
    await seedRows(2);
    const r = await call("auditor", "GET", "/audit-log");
    expect(r.status).toBe(200);
    expect((r.body.rows as { action: string }[]).length).toBe(3); // the two seeded reads and this very request: reading the log is audited before it is served
    expect((await call("auditor", "GET", `/case-files/${ids["official"]}`)).status).toBe(404);
    expect((await call("auditor", "GET", "/case-files")).status).toBe(403);
    const mine = (await dbRows()).filter((x) => x.actorSub === sub("auditor") && x.action === "readAudit");
    expect(mine.length).toBeGreaterThanOrEqual(1);
    expect(mine[0]).toMatchObject({ effect: "allow", resourceType: "case_file" });
  });

  it("filters: time range, actor, resource, action, effect; unknown or malformed parameters are 400", async () => {
    await seedRows(6);
    await call("analyst-official", "GET", `/case-files/${ids["secret-a"]}`);
    const all = (await call("auditor", "GET", "/audit-log?limit=500")).body.rows as { actor_sub: string; effect: string; action: string; resource_id: string | null; ts: string }[];
    expect(all.length).toBe(8); // six reads, one hidden read, and the auditor's own request
    const f = async (q: string) => ((await call("auditor", "GET", `/audit-log?${q}`)).body.rows as typeof all) ?? [];
    expect((await f("effect=deny")).every((r) => r.effect === "deny")).toBe(true);
    expect((await f("effect=deny")).length).toBe(1);
    expect((await f(`actor=${sub("reviewer")}`)).every((r) => r.actor_sub === sub("reviewer"))).toBe(true);
    expect((await f(`resource=${ids["secret-a"]}`)).length).toBe(1);
    expect((await f("action=read")).length).toBe(7);
    expect((await f("action=delete")).length).toBe(0);
    expect((await f(`from=${new Date(Date.now() + 3600_000).toISOString()}`)).length).toBe(0);
    expect((await f(`to=${new Date(Date.now() - 3600_000 * 24).toISOString()}`)).length).toBe(0);
    for (const bad of ["effect=maybe", "limit=0", "limit=501", "limit=abc", "from=yesterday", "actor=a%20b", "actor='%20OR%201=1", "format=xml", "password=x", "resource=../etc", "action=1x"]) {
      expect((await call("auditor", "GET", `/audit-log?${bad}`)).status, bad).toBe(400);
    }
  });

  it("pagination: stable cursors survive new rows arriving; tampered, foreign and truncated cursors are refused", async () => {
    await seedRows(25);
    const first = (await call("auditor", "GET", "/audit-log?limit=10")).body as unknown as { rows: { id: number }[]; nextCursor: string };
    expect(first.rows.map((r) => r.id)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    await call("analyst-official", "GET", `/case-files/${ids["official"]}`); // new rows arrive between pages
    const second = (await call("auditor", "GET", `/audit-log?limit=10&cursor=${first.nextCursor}`)).body as unknown as { rows: { id: number }[]; nextCursor: string };
    expect(second.rows.map((r) => r.id)).toEqual([11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
    const seen = new Set<number>();
    let cursor: string | null = first.nextCursor;
    for (const r of first.rows) seen.add(r.id);
    while (cursor) {
      const page = (await call("auditor", "GET", `/audit-log?limit=10&cursor=${cursor}`)).body as unknown as { rows: { id: number }[]; nextCursor: string | null };
      for (const r of page.rows) expect(seen.has(r.id)).toBe(false); // no duplicates
      for (const r of page.rows) seen.add(r.id);
      cursor = page.nextCursor;
    }
    expect(seen.size).toBeGreaterThanOrEqual(25);
    const c = first.nextCursor;
    for (const bad of [c.replace(/\.10\./, ".1."), c.slice(0, -2), `${c}x`, "x.1.00000000000000000000000000000000", "..", "1", `${c}&cursor=${c}`]) {
      const r = await call("auditor", "GET", `/audit-log?limit=10&cursor=${bad}`);
      expect(r.status, bad).toBe(400);
    }
    expect((await call("auditor", "GET", `/audit-log?limit=10&effect=deny&cursor=${c}`)).status).toBe(400); // bound to the filters it was issued for
  });

  it("export (NDJSON): rows, a proof trailer that verifies offline, and the export itself is audited", async () => {
    await seedRows(9);
    const r = await call("auditor", "GET", "/audit-log/export?format=ndjson");
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toContain("application/x-ndjson");
    expect(r.headers.get("content-disposition")).toContain("attachment");
    expect(r.headers.get("x-content-type-options")).toBe("nosniff");
    const lines = r.text.trim().split("\n").map((l) => JSON.parse(l));
    const proof = lines.at(-1).proof;
    const rows = lines.slice(0, -1);
    expect(rows).toHaveLength(10); // nine seeded reads plus the auditor's own request
    expect(proof).toMatchObject({ chain: "acl-audit/v1", algorithm: "HMAC-SHA256", rows: 10, firstId: 1, lastId: 10, truncated: false });
    expect(proof.firstPrevHash).toBe("4c28ebab5bc198ff48266a7625eaaeddd4f860656eaa34dd2f89b8579441a465");
    expect(proof.lastHash).toBe(rows[9].hash);
    expect(proof.checkpoint).not.toBeNull();
    // offline verification with nothing but the key ring
    const parsed: AuditRow[] = rows.map((w) => ({ id: w.id, ts: new Date(w.ts), actorSub: w.actor_sub, actorRoles: w.actor_roles, action: w.action, resourceType: w.resource_type, resourceId: w.resource_id, effect: w.effect, reasonCode: w.reason_code, obligations: w.obligations, requestId: w.request_id, source: w.source, details: w.details, prevHash: Buffer.from(w.prev_hash, "hex"), keyId: w.key_id, hash: Buffer.from(w.hash, "hex") }));
    expect((await verifyChain(parsed, ring)).ok).toBe(true);
    // the header carries the same proof
    expect(JSON.parse(Buffer.from(r.headers.get("x-audit-proof")!, "base64").toString()).lastId).toBe(10);
    // the export is a row of its own
    const exportRow = (await dbRows()).find((x) => x.action === "audit.export")!;
    expect(exportRow).toMatchObject({ effect: "allow", reasonCode: "EXPORTED", resourceType: "audit_log", actorSub: sub("auditor") });
    expect(exportRow.details).toMatchObject({ format: "ndjson", count: 10, from_id: 1, to_id: 10 });
  });

  it("export: filters apply and are recorded; a tampered row in an export file would not verify", async () => {
    await seedRows(6);
    await call("analyst-official", "GET", `/case-files/${ids["secret-a"]}`);
    const r = await call("auditor", "GET", "/audit-log/export?format=ndjson&effect=deny");
    const lines = r.text.trim().split("\n").map((l) => JSON.parse(l));
    expect(lines).toHaveLength(2); // one deny + trailer
    const exportRow = (await dbRows()).find((x) => x.action === "audit.export")!;
    expect(exportRow.details).toMatchObject({ filters: { effect: "deny" }, count: 1 });
    const w = lines[0];
    const edited: AuditRow = { id: w.id, ts: new Date(w.ts), actorSub: w.actor_sub, actorRoles: w.actor_roles, action: w.action, resourceType: w.resource_type, resourceId: w.resource_id, effect: "allow", reasonCode: w.reason_code, obligations: w.obligations, requestId: w.request_id, source: w.source, details: w.details, prevHash: Buffer.from(w.prev_hash, "hex"), keyId: w.key_id, hash: Buffer.from(w.hash, "hex") };
    expect((await verifyChain([edited], ring, { startAfter: { id: w.id - 1, hash: edited.prevHash } })).firstBad?.code).toBe("HASH");
  });

  it("export (CSV): header, one line per row, formula-looking cells neutralised, proof in a header", async () => {
    await seedRows(3);
    // rows whose text fields start with characters a spreadsheet treats as formulas (allowed by the column patterns)
    const c = await admin.connect();
    try {
      await c.query("BEGIN");
      const { appendAudit } = await import("@acl/audit");
      for (const sub of ["-SUM-A1", "-cmd", "-1-1"]) {
        await appendAudit(c, { actorSub: sub, actorRoles: [], action: "read", resourceType: "case_file", resourceId: "-evil-id", effect: "deny", reasonCode: "X", obligations: [], requestId: "-reqreqreq1", source: "api", details: {} }, ring);
      }
      await c.query("COMMIT");
    } finally {
      c.release();
    }
    const r = await call("auditor", "GET", "/audit-log/export?format=csv");
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toContain("text/csv");
    const lines = r.text.trim().split("\r\n");
    expect(lines[0]).toBe("id,ts,actor_sub,actor_roles,action,resource_type,resource_id,effect,reason_code,obligations,request_id,source,details,prev_hash,key_id,hash");
    expect(lines.length).toBe(1 + 3 + 3 + 1); // header, three seeded reads, three crafted rows, the auditor's own request
    const body = lines.slice(1).join("\n");
    expect(body).toContain(",'-SUM-A1,");
    expect(body).toContain(",'-cmd,");
    expect(body).toContain(",'-evil-id,");
    expect(body).toContain(",'-reqreqreq1,");
    for (const l of lines.slice(1)) for (const cell of l.split(",")) expect(cell, cell).not.toMatch(/^[=+\-@]/); // no cell starts with a formula character
    const proof = JSON.parse(Buffer.from(r.headers.get("x-audit-proof")!, "base64").toString());
    expect(proof.rows).toBe(7);
  });

  it("export is bounded: a big chain is cut at the cap and continues with a cursor", async () => {
    await resetAudit(admin);
    const c = await admin.connect();
    try {
      const { appendAudit } = await import("@acl/audit");
      await c.query("BEGIN");
      for (let i = 0; i < 2100; i++) await appendAudit(c, { actorSub: "bulk", actorRoles: [], action: "read", resourceType: "case_file", resourceId: null, effect: "allow", reasonCode: "ALLOWED", obligations: ["audit"], requestId: `req-${String(i).padStart(8, "0")}`, source: "api", details: {} }, ring);
      await c.query("COMMIT");
    } finally {
      c.release();
    }
    const first = await call("auditor", "GET", "/audit-log/export?format=ndjson");
    const lines = first.text.trim().split("\n").map((l) => JSON.parse(l));
    const trailer = lines.at(-1);
    expect(lines.length - 1).toBe(2000);
    expect(trailer.proof.truncated).toBe(true);
    expect(trailer.nextCursor).toMatch(/^audit-1\.2000\./);
    const second = await call("auditor", "GET", `/audit-log/export?format=ndjson&cursor=${trailer.nextCursor}`);
    const l2 = second.text.trim().split("\n").map((l) => JSON.parse(l));
    expect(l2[0].id).toBe(2001);
    expect(l2.at(-1).proof.firstPrevHash).toBe(lines[1999].hash); // the second part chains onto the first
  }, 120_000);

  it("the checkpoint list and the in-API verification", async () => {
    await seedRows(4);
    await call("auditor", "GET", "/audit-log/export"); // an export writes a checkpoint
    const cps = (await call("auditor", "GET", "/audit-log/checkpoints")).body as unknown as { last_id: number; mac: string }[];
    expect(cps.length).toBeGreaterThanOrEqual(1);
    expect(cps[0]!.mac).toMatch(/^[0-9a-f]{64}$/);
    const v = (await call("auditor", "GET", "/audit-log/verify")).body;
    expect(v).toMatchObject({ ok: true, issues: [] });
  });
});

describe("verification CLI against a tampered database (T-26)", () => {
  const dist = new URL("../../../apps/api/dist/audit/", import.meta.url).pathname;
  const env = () => ({ ...process.env, AUDIT_DATABASE_URL: auditUrl(), AUDIT_HMAC_KEYS: process.env.AUDIT_HMAC_KEYS! });
  const verify = async (...args: string[]) => {
    try {
      const r = await run(process.execPath, [`${dist}verify-cli.js`, ...args], { env: env() });
      return { code: 0, out: r.stdout, err: r.stderr };
    } catch (e) {
      const x = e as { code: number; stdout: string; stderr: string };
      return { code: x.code, out: x.stdout, err: x.stderr };
    }
  };
  const checkpoint = (...args: string[]) => run(process.execPath, [`${dist}checkpoint-cli.js`, ...args], { env: env() });
  const sudo = async (statements: string[]) => {
    const c = await admin.connect();
    try {
      await c.query("BEGIN");
      await c.query("SET LOCAL session_replication_role = replica"); // the documented break procedure
      for (const s of statements) await c.query(s);
      await c.query("COMMIT");
    } finally {
      c.release();
    }
  };
  async function freshChain(n = 14) {
    await resetAudit(admin);
    for (let i = 0; i < n; i++) await call(i % 3 ? "analyst-official" : "reviewer", "GET", `/case-files/${i % 5 === 0 ? ids["secret-a"] : ids["official"]}`);
  }

  it("a healthy chain: exit 0, ranges and checkpoints verify", async () => {
    await freshChain();
    await checkpoint();
    const full = await verify();
    expect(full.code).toBe(0);
    expect(JSON.parse(full.out)).toMatchObject({ ok: true, checked: 14, lastId: 14, firstBad: null });
    expect((await verify("--from", "5", "--to", "9")).code).toBe(0);
    const head = (await aud.query("SELECT encode(hash, 'hex') AS h FROM audit_log WHERE id = 6")).rows[0].h as string;
    expect((await verify("--from", "7", "--prev-hash", head)).code).toBe(0);
    expect((await verify("--from", "7", "--prev-hash", "00".repeat(32))).code).toBe(1); // wrong anchor for the range
  });

  it("an edited row: exit 1, reported at that row", async () => {
    await freshChain();
    await sudo(["UPDATE audit_log SET effect = 'allow', reason_code = 'ALLOWED' WHERE id = 6"]);
    const r = await verify();
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out).firstBad).toMatchObject({ id: 6, code: "HASH" });
    expect(r.err).toContain("AUDIT CHAIN BROKEN at row 6");
    expect((await verify("--from", "8")).code).toBe(0); // rows after the damage verify on their own, which is how the damage is bounded
  });

  it("an edited row re-hashed with plain SHA-256 (what a DB-only attacker can do) is still caught", async () => {
    await freshChain();
    await sudo(["UPDATE audit_log SET effect = 'allow', hash = sha256(convert_to('forged', 'UTF8')) WHERE id = 7"]);
    const r = await verify();
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out).issues.some((i: { id: number; code: string }) => i.id === 7 && i.code === "HASH")).toBe(true);
  });

  it("a deleted middle row: gap", async () => {
    await freshChain();
    await sudo(["DELETE FROM audit_log WHERE id = 5"]);
    const r = await verify();
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out).firstBad).toMatchObject({ id: 6, code: "GAP" });
  });

  it("deleted tail rows: the head disagrees; and with the head rewritten too, a checkpoint still catches it", async () => {
    await freshChain();
    await checkpoint();
    await sudo(["DELETE FROM audit_log WHERE id > 9"]);
    let r = await verify();
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out).issues.map((i: { code: string }) => i.code)).toEqual(expect.arrayContaining(["HEAD_MISMATCH", "TAIL_TRUNCATED"]));
    await sudo(["UPDATE audit_head SET last_id = 9, last_hash = (SELECT hash FROM audit_log WHERE id = 9)"]); // attacker fixes the head
    r = await verify();
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out).issues.map((i: { code: string }) => i.code)).toContain("TAIL_TRUNCATED");
  });

  it("tail deleted AND checkpoints deleted AND head rewritten: only an external checkpoint copy detects it", async () => {
    await freshChain();
    const file = join(mkdtempSync(join(tmpdir(), "cp-")), "checkpoints.ndjson");
    await checkpoint("--out", file);
    expect(readFileSync(file, "utf8").trim().split("\n")).toHaveLength(1);
    await sudo(["DELETE FROM audit_log WHERE id > 9", "DELETE FROM audit_checkpoints", "UPDATE audit_head SET last_id = 9, last_hash = (SELECT hash FROM audit_log WHERE id = 9)"]);
    expect((await verify()).code).toBe(0); // inside the database everything is consistent: this is what no in-database control can prevent
    const r = await verify("--checkpoint-file", file);
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out).issues.map((i: { code: string }) => i.code)).toContain("TAIL_TRUNCATED");
  });

  it("a forged checkpoint, a forged row and a row signed with another key are rejected", async () => {
    await freshChain(8);
    await sudo(["INSERT INTO audit_checkpoints (ts, last_id, last_hash, key_id, mac) VALUES (now(), 8, (SELECT hash FROM audit_log WHERE id = 8), 'audit-1', decode(repeat('ab', 32), 'hex'))"]);
    let r = await verify();
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out).issues.some((i: { code: string }) => i.code === "CHECKPOINT_MAC")).toBe(true);

    await freshChain(8);
    const forgedKey = Buffer.alloc(32, 99).toString("base64");
    const { parseAuditKeys, buildRow } = await import("@acl/audit");
    const evilRing = parseAuditKeys(`audit-1:${forgedKey}`);
    const h = (await aud.query("SELECT last_id, last_hash FROM audit_head")).rows[0];
    const row = buildRow({ actorSub: "mallory", actorRoles: [], action: "read", resourceType: "case_file", resourceId: null, effect: "allow", reasonCode: "ALLOWED", obligations: [], requestId: "req-0000ffff", source: "api", details: {} }, { lastId: Number(h.last_id), lastHash: h.last_hash }, evilRing, new Date());
    const c = await admin.connect();
    await c.query("INSERT INTO audit_log (id, ts, actor_sub, actor_roles, action, resource_type, resource_id, effect, reason_code, obligations, request_id, source, details, prev_hash, key_id, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)", [row.id, row.ts, row.actorSub, row.actorRoles, row.action, row.resourceType, row.resourceId, row.effect, row.reasonCode, row.obligations, row.requestId, row.source, JSON.stringify(row.details), row.prevHash, row.keyId, row.hash]);
    c.release();
    r = await verify();
    expect(r.code).toBe(1);
    expect(JSON.parse(r.out).firstBad).toMatchObject({ id: 9, code: "HASH" }); // a valid-looking row appended by a DB-only attacker
  });

  it("usage and configuration errors exit 2, never 0", async () => {
    expect((await verify("--bogus")).code).toBe(2);
    const r = await run(process.execPath, [`${dist}verify-cli.js`], { env: { ...process.env, AUDIT_HMAC_KEYS: "" } }).then(() => 0, (e) => (e as { code: number }).code);
    expect(r).toBe(2);
    const f = join(mkdtempSync(join(tmpdir(), "cp-")), "x");
    writeFileSync(f, "not json\n");
    expect((await verify("--checkpoint-file", f)).code).toBe(2);
  });

  it("the checkpoint CLI appends to the chosen file and the API role can write its own", async () => {
    await freshChain(3);
    const file = join(mkdtempSync(join(tmpdir(), "cp-")), "c.ndjson");
    await checkpoint("--out", file);
    await checkpoint("--out", file);
    expect(readFileSync(file, "utf8").trim().split("\n")).toHaveLength(2);
    expect((await verify("--checkpoint-file", file)).code).toBe(0);
  });
});
