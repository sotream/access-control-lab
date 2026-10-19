// A-50..A-53: an attacker who got hold of an application database credential, or who can only use the application, tries to rewrite or hide what the audit trail says.
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { api, FORM, form } from "./http.js";
import { oidcTokens } from "./kc.js";
import { bff, session } from "./sessions.js";
import { COMPOSE, ROOT, env, psqlAs, secret } from "./stack.js";
import { vault } from "./http.js";
// the reader and the predicate live next to the exporter they check (a test helper of packages/audit, not part of its API)
import { isRawFormula, parseCsv } from "../../../packages/audit/src/csv-parse.js";

const appPw = () => /casefile_app:([^@]+)@/.exec(secret("database_url_api"))![1]!;
const webPw = () => /casefile_web:([^@]+)@/.exec(secret("database_url_web"))![1]!;
const auditPw = () => env.CASEFILE_AUDIT_PASSWORD ?? "";

const STATEMENTS = [
  "UPDATE audit_log SET effect = 'allow'",
  "UPDATE audit_log SET actor_sub = 'nobody' WHERE id = 1",
  "DELETE FROM audit_log",
  "DELETE FROM audit_log WHERE id = (SELECT max(id) FROM audit_log)",
  "TRUNCATE audit_log",
  "TRUNCATE audit_log, audit_head, audit_checkpoints",
  "UPDATE audit_head SET last_id = 0",
  "DELETE FROM audit_checkpoints",
  "UPDATE audit_checkpoints SET last_id = 0",
  "INSERT INTO audit_log (id, ts, actor_sub, actor_roles, action, resource_type, effect, reason_code, obligations, request_id, source, details, prev_hash, key_id, hash) VALUES (999999, now(), 'x', '{}', 'read', 'case_file', 'allow', 'ALLOWED', '{}', 'forged-0001', 'api', '{}', decode(repeat('00',32),'hex'), 'k', decode(repeat('00',32),'hex'))",
  "ALTER TABLE audit_log DISABLE TRIGGER ALL",
  "DROP TRIGGER audit_log_no_update ON audit_log",
  "DROP TABLE audit_log",
  "ALTER TABLE audit_log DISABLE ROW LEVEL SECURITY",
  "DROP POLICY audit_log_insert_api ON audit_log",
  "CREATE POLICY pwn ON audit_log FOR ALL USING (true)",
  "GRANT ALL ON audit_log TO casefile_app",
  "SET session_replication_role = replica",
  "CREATE OR REPLACE FUNCTION audit_reject_change() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
  "ALTER FUNCTION audit_chain_guard() OWNER TO casefile_app",
  "COPY (SELECT 1) TO PROGRAM 'id'",
  "CREATE TABLE audit_evil (x int)",
  "SELECT set_config('app.ctx','v1',false), set_config('app.roles','auditor',false); UPDATE audit_log SET effect='allow'",
];

describe("A-50 a stolen application credential cannot rewrite, delete or disable the audit trail", () => {
  it.each([
    ["the API's database role", "casefile_app", appPw],
    ["the BFF's database role", "casefile_web", webPw],
    ["the verifier's read-only role", "casefile_audit", auditPw],
  ])("%s: every statement is refused", (_n, user, pw) => {
    for (const stmt of STATEMENTS) {
      const r = psqlAs(user, pw(), stmt);
      // refused, or accepted as a no-op that changes nothing (a GRANT by a role that owns nothing only warns)
      expect(!r.ok || /no privileges were granted/.test(r.out), `${user}: ${stmt.slice(0, 60)} -> ${r.out.slice(0, 120)}`).toBe(true);
    }
  });
  it("the table owner and the superuser are stopped by the triggers too (no statement edits or removes a row)", () => {
    for (const stmt of ["UPDATE audit_log SET effect = 'allow'", "DELETE FROM audit_log", "UPDATE audit_head SET last_id = 0"]) {
      const r = psqlAs("postgres", env.POSTGRES_PASSWORD ?? "", stmt);
      expect(r.ok, `superuser: ${stmt}`).toBe(false);
    }
  });
});

describe("A-51 through the application there is no way to change or hide the trail", () => {
  it("no route accepts a write to the audit endpoints, for the auditor or anyone else, through the BFF or on the API itself", async () => {
    const a = await session("auditor");
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      for (const path of ["/audit-log", "/audit-log/export", "/audit-log/checkpoints", "/audit-log/verify", "/audit-log/1", "/audit-log/checkpoints/1"]) {
        const r = await bff(a, method, path, { effect: "allow", id: 1 });
        expect([403, 404, 405], `${method} ${path}`).toContain(r.status);
      }
    }
    const t = await oidcTokens("auditor");
    const bearer = { authorization: `Bearer ${t.access_token}`, "content-type": "application/json" };
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      for (const path of ["/audit-log", "/audit-log/export", "/audit-log/1", "/audit-log/checkpoints", "/audit-log/verify"]) {
        const r = await api(path, { method, headers: bearer, body: JSON.stringify({ effect: "allow" }) });
        expect([400, 403, 404, 405], `API ${method} ${path}`).toContain(r.status);
      }
    }
    expect((await api("/audit-log", { headers: bearer })).status, "reading is what the auditor may do").toBe(200);
  });
  it("an export is a row of its own: reading the trail leaves a trace, and the CSV cannot carry a formula", async () => {
    const a = await session("auditor");
    const before = (await bff(a, "GET", "/audit-log?action=audit.export")).json as { rows: unknown[] };
    const csv = await vault("/actions/audit/export", { method: "POST", jar: a.jar, headers: { ...FORM, origin: "https://vault.localhost", "sec-fetch-site": "same-origin" }, body: form({ csrf: a.csrf, format: "csv" }) });
    expect(csv.status).toBe(200);
    // parsed as CSV (quoted cells can hold commas and line breaks); a cell is safe when the exporter neutralised it with a leading apostrophe or it never looked like a formula
    const rows = parseCsv(csv.text).slice(1);
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) for (const cell of row) expect(isRawFormula(cell), `cell ${JSON.stringify(cell)} is a raw formula`).toBe(false);
    const after = (await bff(a, "GET", "/audit-log?action=audit.export")).json as { rows: unknown[] };
    expect(after.rows.length).toBeGreaterThan(before.rows.length);
  });
  it("a failed attempt is itself recorded: CSRF refusals and rejected uploads leave rows", async () => {
    const s = await session("unit-admin-alpha");
    await vault("/actions/case-files/create", { method: "POST", jar: s.jar, headers: { ...FORM, origin: "https://evil.example" }, body: form({ csrf: s.csrf, title: "x", classification: "OFFICIAL" }) });
    const a = await session("auditor");
    const rows = ((await bff(a, "GET", "/audit-log?action=auth.csrf_denied&limit=50")).json as { rows: { actor_sub: string }[] }).rows;
    expect(rows.some((r) => r.actor_sub === s.sub)).toBe(true);
  });
});

describe("A-53 the databases of the application and of the identity provider are walled off from each other", () => {
  it("the identity provider's role cannot enter the application database, and the application roles cannot enter the identity provider's", () => {
    const kc = env.KEYCLOAK_DB_PASSWORD ?? "";
    expect(psqlAs("keycloak", kc, "SELECT 1", "acl").ok, "keycloak role into acl").toBe(false);
    expect(psqlAs("keycloak", kc, "SELECT count(*) FROM case_files", "acl").ok).toBe(false);
    for (const [user, pw] of [["casefile_app", appPw()], ["casefile_web", webPw()], ["casefile_audit", auditPw()]] as const) {
      expect(psqlAs(user, pw, "SELECT 1", "keycloak").ok, `${user} into the keycloak database`).toBe(false);
    }
    expect(psqlAs("keycloak", kc, "SELECT 1", "keycloak").ok, "the identity provider's own role works (the check is not vacuous)").toBe(true);
    expect(psqlAs("casefile_app", appPw(), "SELECT 1", "acl").ok, "and so does the application's").toBe(true);
  });
});

describe("A-52 after all of the above the chain still verifies", () => {
  it("the verifier CLI, run with the audit role and the key ring, finds no gap, fork, wrong key or altered row", () => {
    const keys = secret("audit_hmac_keys");
    const url = `postgres://casefile_audit:${auditPw()}@postgres:5432/acl`;
    const r = spawnSync("docker", [...COMPOSE, "exec", "-T", "-e", `AUDIT_DATABASE_URL=${url}`, "-e", `AUDIT_HMAC_KEYS=${keys}`, "api", "/nodejs/bin/node", "dist/audit/verify-cli.js"], { cwd: ROOT, encoding: "utf8" });
    expect(r.status, `${r.stdout}${r.stderr}`).toBe(0);
    expect(JSON.parse(r.stdout.trim().split("\n").at(-1)!)).toMatchObject({ ok: true });
  });
});
