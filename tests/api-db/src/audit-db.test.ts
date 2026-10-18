// The audit tables as the database enforces them: who may do what, append-only, linear chain, serialised writers (T-24, T-26).
import { randomUUID } from "node:crypto";
import { evaluate } from "@acl/policy";
import { GENESIS_HASH_HEX, DETAIL_KEYS, appendAudit, buildRow, verifyChain, rowFromDb, type AuditEntry, type AuditRow } from "@acl/audit";
import pg from "pg";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { MFA_ENV, adminPool, appPool, appUrl, auditKeys, auditPool, auditUrl, ctxOf, envOf, migratorUrl, probe, resetAudit, subjectOf, webDbUrl, webPool } from "./db.js";

const admin = adminPool();
const app = appPool(6);
const web = webPool();
const aud = auditPool();
const ring = auditKeys();
afterAll(async () => {
  await resetAudit(admin);
  await admin.end();
  await app.end();
  await web.end();
  await aud.end();
});
beforeEach(() => resetAudit(admin));

const entry = (over: Partial<AuditEntry> = {}): AuditEntry => ({
  actorSub: "user-1",
  actorRoles: ["analyst"],
  action: "read",
  resourceType: "case_file",
  resourceId: "0f1e2d3c-4b5a-4968-8776-655443322110",
  effect: "allow",
  reasonCode: "ALLOWED",
  obligations: ["audit"],
  requestId: "req-00000001",
  source: "api",
  details: { rule_ids: ["rbac.role-grants-action"] },
  ...over,
});

/** one row through the real writer path (lock, head, insert) on a given pool */
async function append(pool: pg.Pool, e: AuditEntry): Promise<AuditRow> {
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const row = await appendAudit(c, e, ring);
    await c.query("COMMIT");
    return row;
  } catch (err) {
    await c.query("ROLLBACK").catch(() => undefined);
    throw err;
  } finally {
    c.release();
  }
}
const code = (p: Promise<unknown>) => p.then(() => "ok", (e) => (e as { code?: string }).code ?? "error");
const rows = async () => (await admin.query("SELECT * FROM audit_log ORDER BY id")).rows.map(rowFromDb);
const head = async () => (await admin.query("SELECT last_id::int AS id, last_hash FROM audit_head")).rows[0] as { id: number; last_hash: Buffer };
const sql1 = async (url: string, text: string, params: unknown[] = []) => {
  const c = new pg.Client({ connectionString: url });
  await c.connect();
  try {
    return await c.query(text, params).then((r) => ({ ok: true as const, r }), (e) => ({ ok: false as const, code: (e as { code?: string }).code ?? "error", message: String((e as Error).message) }));
  } finally {
    await c.end();
  }
};

describe("who can do what", () => {
  it("the API and the BFF can append (each only with its own source); nobody else can", async () => {
    await append(app, entry());
    await append(web, entry({ source: "bff", requestId: "req-00000002", action: "auth.login", resourceType: "session", resourceId: null, actorRoles: [], reasonCode: "LOGIN_OK", details: { event: "login" } }));
    expect((await rows()).map((r) => [r.id, r.source])).toEqual([[1, "api"], [2, "bff"]]);
    // wrong source for the role: refused by the row policy
    expect(await code(append(app, entry({ source: "bff", requestId: "req-00000003" })))).toBe("42501");
    expect(await code(append(web, entry({ source: "api", requestId: "req-00000004" })))).toBe("42501");
    // the verifier role writes checkpoints only
    expect(await code(append(aud, entry({ requestId: "req-00000005" })))).toBe("42501");
    expect((await rows()).length).toBe(2);
  });

  it("append-only for every role: no UPDATE, DELETE or TRUNCATE for the writers, the verifier, the owner or even a superuser", async () => {
    await append(app, entry());
    await aud.query("INSERT INTO audit_checkpoints (ts, last_id, last_hash, key_id, mac) VALUES (now(), 1, $1, 'audit-1', $1)", [Buffer.alloc(32, 1)]); // rows must exist for row-level triggers to fire
    const targets: [string, string][] = [
      ["casefile_app", appUrl()],
      ["casefile_web", webDbUrl()],
      ["casefile_audit", auditUrl()],
      ["owner (migrator)", migratorUrl()],
      ["superuser", process.env.ADMIN_DATABASE_URL!.replace(/\/[^/]+$/, `/${new URL(appUrl()).pathname.slice(1)}`)],
    ];
    for (const [who, url] of targets) {
      for (const statement of ["UPDATE audit_log SET effect = 'allow'", "DELETE FROM audit_log", "TRUNCATE audit_log", "UPDATE audit_checkpoints SET key_id = 'x'", "DELETE FROM audit_checkpoints", "TRUNCATE audit_checkpoints", "TRUNCATE audit_head", "DELETE FROM audit_head", "UPDATE audit_head SET last_id = 0"]) {
        const r = await sql1(url, statement);
        if (r.ok) {
          // the only way a statement may "succeed": row security hides every row from this role, so it touched nothing
          expect(who, `${who}: ${statement}`).toBe("owner (migrator)");
          expect(r.r.rowCount ?? 0, `${who}: ${statement}`).toBe(0);
        } else expect(r.code, `${who}: ${statement}`).toBe("42501");
      }
    }
    expect((await rows()).length).toBe(1);
    expect((await rows())[0]!.effect).toBe("allow");
  });

  it("the writers cannot alter or drop the tables, triggers or policies, nor switch triggers off", async () => {
    for (const url of [appUrl(), webDbUrl(), auditUrl()]) {
      for (const statement of ["ALTER TABLE audit_log DISABLE TRIGGER audit_chain", "ALTER TABLE audit_log DISABLE TRIGGER USER", "DROP TRIGGER audit_log_no_update ON audit_log", "ALTER TABLE audit_log DISABLE ROW LEVEL SECURITY", "ALTER TABLE audit_log NO FORCE ROW LEVEL SECURITY", "DROP TABLE audit_log", "DROP POLICY audit_log_select_auditor ON audit_log", "ALTER TABLE audit_log ADD COLUMN x int", "CREATE OR REPLACE FUNCTION audit_chain_guard() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END'", "SET session_replication_role = replica", "GRANT UPDATE ON audit_log TO PUBLIC"]) {
        const r = await sql1(url, statement);
        // GRANT by a non-owner is a warning, not an error: check the effect below
        if (statement.startsWith("GRANT")) continue;
        expect(r.ok, `${url.split("@")[0]}: ${statement}`).toBe(false);
      }
    }
    const acl = await admin.query("SELECT a.grantee::regrole::text AS g, a.privilege_type AS p FROM pg_class c, aclexplode(c.relacl) a WHERE c.relname = 'audit_log'");
    const by = (g: string) => acl.rows.filter((r) => r.g === g).map((r) => r.p).sort();
    expect(by("-")).toEqual([]); // PUBLIC
    expect(by("casefile_app")).toEqual(["INSERT", "SELECT"]);
    expect(by("casefile_web")).toEqual(["INSERT"]);
    expect(by("casefile_audit")).toEqual(["SELECT"]);
  });

  it("reading: the web role cannot read the log; the API role reads nothing without an auditor context; the verifier reads everything", async () => {
    await append(app, entry());
    expect((await sql1(webDbUrl(), "SELECT * FROM audit_log")).ok).toBe(false);
    const bare = await sql1(appUrl(), "SELECT * FROM audit_log");
    expect(bare.ok && bare.r.rows).toEqual([]);
    const analyst = await probe(app, ctxOf(subjectOf({ roles: ["analyst"] }), envOf(), "readAudit"), async (tx) => (await tx.query("SELECT id FROM audit_log" as never)).rows);
    expect(analyst).toEqual([]);
    for (const roles of [["reviewer"], ["unit-admin"], ["platform-admin"], ["ghost"]]) {
      const r = await probe(app, ctxOf(subjectOf({ roles }), envOf(), "readAudit"), async (tx) => (await tx.query("SELECT id FROM audit_log" as never)).rows);
      expect(r, roles.join()).toEqual([]);
    }
    const auditor = await probe(app, ctxOf(subjectOf({ roles: ["auditor"] }), envOf(), "readAudit"), async (tx) => (await tx.query("SELECT id FROM audit_log" as never)).rows);
    expect(auditor).toHaveLength(1);
    expect((await aud.query("SELECT id FROM audit_log")).rows).toHaveLength(1);
  });

  it("even the owner sees nothing and writes nothing without a policy (FORCE row level security)", async () => {
    await append(app, entry());
    const sel = await sql1(migratorUrl(), "SELECT * FROM audit_log");
    expect(sel.ok && sel.r.rows).toEqual([]);
    const ins = await sql1(migratorUrl(), "INSERT INTO audit_log (id, ts, actor_sub, actor_roles, action, resource_type, effect, reason_code, obligations, request_id, source, details, prev_hash, key_id, hash) VALUES (2, now(), 'x', '{}', 'a', 'b', 'allow', 'X', '{}', 'req-00000009', 'api', '{}', $1, 'k', $1)", [Buffer.alloc(32)]);
    expect(ins.ok).toBe(false);
  });

  it("checkpoints: the API and the verifier insert; only auditors read through the API role", async () => {
    const cp = [new Date(), 0, Buffer.from(GENESIS_HASH_HEX, "hex"), "audit-1", Buffer.alloc(32, 1)];
    const insert = "INSERT INTO audit_checkpoints (ts, last_id, last_hash, key_id, mac) VALUES ($1, $2, $3, $4, $5)";
    expect((await sql1(appUrl(), insert, cp)).ok).toBe(true);
    expect((await sql1(auditUrl(), insert, cp)).ok).toBe(true);
    expect((await sql1(webDbUrl(), insert, cp)).ok).toBe(false);
    expect((await sql1(webDbUrl(), "SELECT * FROM audit_checkpoints")).ok).toBe(false);
    const bare = await sql1(appUrl(), "SELECT * FROM audit_checkpoints");
    expect(bare.ok && bare.r.rows).toEqual([]);
    expect((await aud.query("SELECT * FROM audit_checkpoints")).rows).toHaveLength(2);
  });

  it("the head is readable by the writers but changes only through an insert (not directly, by nobody)", async () => {
    for (const url of [appUrl(), webDbUrl(), auditUrl()]) expect((await sql1(url, "SELECT last_id FROM audit_head")).ok).toBe(true);
    const direct = await sql1(process.env.ADMIN_DATABASE_URL!.replace(/\/[^/]+$/, `/${new URL(appUrl()).pathname.slice(1)}`), "UPDATE audit_head SET last_id = 99");
    expect(direct.ok).toBe(false);
  });
});

describe("the chain is linear: the database refuses forks and gaps from any role (T-26)", () => {
  async function rawInsert(pool: pg.Pool, over: Partial<{ id: number; prev: Buffer }>) {
    const h = await head();
    const row = buildRow(entry({ requestId: "req-0000000a" }), { lastId: over.id !== undefined ? over.id - 1 : h.id, lastHash: over.prev ?? h.last_hash }, ring, new Date());
    return code(pool.query("INSERT INTO audit_log (id, ts, actor_sub, actor_roles, action, resource_type, resource_id, effect, reason_code, obligations, request_id, source, details, prev_hash, key_id, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)", [row.id, row.ts, row.actorSub, row.actorRoles, row.action, row.resourceType, row.resourceId, row.effect, row.reasonCode, row.obligations, row.requestId, row.source, JSON.stringify(row.details), row.prevHash, row.keyId, row.hash]));
  }

  it("a row that skips an id, repeats an id or attaches to the wrong hash is refused even though the signature may be fine", async () => {
    await append(app, entry());
    expect(await rawInsert(app, { id: 5 })).toBe("23514"); // gap
    expect(await rawInsert(app, { id: 1 })).toMatch(/23514|23505/); // duplicate / fork
    expect(await rawInsert(app, { prev: Buffer.alloc(32, 9) })).toBe("23514"); // wrong previous hash
    expect(await rawInsert(app, {})).toBe("ok"); // the honest next row passes
    expect((await rows()).map((r) => r.id)).toEqual([1, 2]);
  });

  it("the head moves with every insert and the chain verifies end to end", async () => {
    for (let i = 0; i < 12; i++) await append(i % 2 ? app : web, entry({ requestId: `req-${String(i).padStart(8, "0")}`, source: i % 2 ? "api" : "bff" }));
    const all = await rows();
    const h = await head();
    expect(h.id).toBe(12);
    expect(h.last_hash).toEqual(all[11]!.hash);
    expect((await verifyChain(all, ring, { head: { lastId: h.id, lastHash: h.last_hash } })).ok).toBe(true);
  });

  it("a rolled back write leaves no gap: the next row reuses the id", async () => {
    await append(app, entry());
    const c = await app.connect();
    await c.query("BEGIN");
    await appendAudit(c, entry({ requestId: "req-0000000b" }), ring);
    await c.query("ROLLBACK");
    c.release();
    const next = await append(app, entry({ requestId: "req-0000000c" }));
    expect(next.id).toBe(2);
    expect((await verifyChain(await rows(), ring)).ok).toBe(true);
  });

  it("concurrent writers from API and BFF connections produce ONE linear verifiable chain: no forks, no gaps", async () => {
    const N = 60;
    const results = await Promise.allSettled(Array.from({ length: N }, (_, i) => append(i % 3 === 0 ? web : app, entry({ requestId: `req-${String(i).padStart(8, "0")}`, source: i % 3 === 0 ? "bff" : "api" }))));
    expect(results.every((r) => r.status === "fulfilled")).toBe(true);
    const all = await rows();
    expect(all.map((r) => r.id)).toEqual(Array.from({ length: N }, (_, i) => i + 1));
    const h = await head();
    expect(await verifyChain(all, ring, { head: { lastId: h.id, lastHash: h.last_hash } })).toMatchObject({ ok: true, checked: N, lastId: N });
    expect(new Set(all.map((r) => r.requestId)).size).toBe(N); // every writer landed exactly once
  });

  it("concurrent writers mixed with failures and rollbacks still leave a gap-free chain", async () => {
    const jobs = Array.from({ length: 40 }, async (_, i) => {
      const c = await app.connect();
      try {
        await c.query("BEGIN");
        await appendAudit(c, entry({ requestId: `req-${String(i).padStart(8, "0")}` }), ring);
        if (i % 4 === 0) throw new Error("business transaction failed");
        await c.query("COMMIT");
      } catch {
        await c.query("ROLLBACK").catch(() => undefined);
      } finally {
        c.release();
      }
    });
    await Promise.all(jobs);
    const all = await rows();
    expect(all).toHaveLength(30);
    expect((await verifyChain(all, ring)).ok).toBe(true);
  });

  it("a writer that forgets the chain lock cannot corrupt the chain: it fails and the chain stays valid", async () => {
    await append(app, entry());
    const make = async () => {
      const c = await app.connect();
      await c.query("BEGIN");
      const h = (await c.query("SELECT last_id, last_hash FROM audit_head WHERE singleton")).rows[0];
      return { c, row: buildRow(entry({ requestId: "req-0000000d" }), { lastId: Number(h.last_id), lastHash: h.last_hash }, ring, new Date()) };
    };
    const [a, b] = await Promise.all([make(), make()]); // both read the same head without locking
    const ins = (x: Awaited<ReturnType<typeof make>>) => x.c.query("INSERT INTO audit_log (id, ts, actor_sub, actor_roles, action, resource_type, resource_id, effect, reason_code, obligations, request_id, source, details, prev_hash, key_id, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)", [x.row.id, x.row.ts, x.row.actorSub, x.row.actorRoles, x.row.action, x.row.resourceType, x.row.resourceId, x.row.effect, x.row.reasonCode, x.row.obligations, x.row.requestId, x.row.source, JSON.stringify(x.row.details), x.row.prevHash, x.row.keyId, x.row.hash]);
    await ins(a);
    const second = ins(b).then(() => "ok", (e) => (e as { code?: string }).code);
    await a.c.query("COMMIT");
    expect(await second).toMatch(/23514|23505/);
    await b.c.query("ROLLBACK");
    a.c.release();
    b.c.release();
    expect((await verifyChain(await rows(), ring)).ok).toBe(true);
    expect(await rows()).toHaveLength(2);
  });
});

describe("hostile or malformed rows are refused by the table itself (T-14, T-24)", () => {
  const bad: [string, Partial<AuditEntry>][] = [
    ["actor with a quote", { actorSub: "a'b" }],
    ["details with a token key", { details: { access_token: "x" } as never }],
    ["details with nested claims", { details: { claims: { sub: "x" } } as never }],
    ["lower-case reason", { reasonCode: "allowed" }],
    ["request id with a space", { requestId: "req 0000001" }],
    ["resource type with upper case", { resourceType: "Case" }],
  ];
  it.each(bad)("%s", async (_n, over) => {
    // go around the application-side validation: build a valid row, then break one column in the INSERT
    const h = await head();
    const good = buildRow(entry(), { lastId: h.id, lastHash: h.last_hash }, ring, new Date());
    const row = { ...good, ...over } as AuditRow;
    const c = await code(app.query("INSERT INTO audit_log (id, ts, actor_sub, actor_roles, action, resource_type, resource_id, effect, reason_code, obligations, request_id, source, details, prev_hash, key_id, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)", [row.id, row.ts, row.actorSub, row.actorRoles, row.action, row.resourceType, row.resourceId, row.effect, row.reasonCode, row.obligations, row.requestId, row.source, JSON.stringify(row.details), row.prevHash, row.keyId, row.hash]));
    expect(c).toBe("23514");
    expect(await rows()).toHaveLength(0);
  });

  it("the database key whitelist equals the library's (drift)", async () => {
    const src = (await admin.query("SELECT prosrc FROM pg_proc WHERE proname = 'audit_details_ok'")).rows[0].prosrc as string;
    const inList = /NOT IN \(([^)]*)\)/.exec(src)![1]!.split(",").map((s) => s.trim().replace(/'/g, "")).sort();
    expect(inList).toEqual([...DETAIL_KEYS].sort());
  });

  it("the genesis hash in the database equals the library's", async () => {
    expect((await admin.query("SELECT encode(last_hash, 'hex') AS h FROM audit_head")).rows[0].h).toBe(GENESIS_HASH_HEX);
  });
});

describe("the SECURITY DEFINER functions: exactly two, each pinned and narrow", () => {
  it("audit_chain_guard (trigger, owned by the migrator) and audit_read_denial_reason (owned by the NOLOGIN lookup role); search_path pinned", async () => {
    const r = await admin.query("SELECT proname, pg_get_userbyid(proowner) AS owner, proconfig::text AS cfg, prorettype::regtype::text AS ret FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND prosecdef ORDER BY proname");
    expect(r.rows).toEqual([
      { proname: "audit_chain_guard", owner: "casefile_migrator", cfg: '{"search_path=pg_catalog, public"}', ret: "trigger" },
      { proname: "audit_read_denial_reason", owner: "casefile_lookup", cfg: '{"search_path=pg_catalog, public"}', ret: "text" },
    ]);
  });

  it("the lookup role cannot log in and can see three columns of case_files and the role matrix, nothing else", async () => {
    const role = (await admin.query("SELECT rolcanlogin, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'casefile_lookup'")).rows[0];
    expect(role).toEqual({ rolcanlogin: false, rolsuper: false, rolbypassrls: false });
    const cols = await admin.query("SELECT table_name, column_name, privilege_type FROM information_schema.column_privileges WHERE grantee = 'casefile_lookup' ORDER BY table_name, column_name, privilege_type");
    expect(cols.rows.filter((r) => r.table_name === "case_files").map((r) => `${r.column_name}:${r.privilege_type}`)).toEqual(["classification:SELECT", "compartments:SELECT", "id:SELECT"]);
    const tables = await admin.query("SELECT table_name, privilege_type FROM information_schema.role_table_grants WHERE grantee = 'casefile_lookup' AND table_schema = 'public' ORDER BY 1, 2");
    expect(tables.rows.every((r) => ["case_files", "role_grants"].includes(r.table_name) && r.privilege_type === "SELECT")).toBe(true);
    const schema = await admin.query("SELECT has_schema_privilege('casefile_lookup', 'public', 'CREATE') AS c");
    expect(schema.rows[0].c).toBe(false); // the temporary CREATE used to hand over the function was revoked again
  });

  it("only the API role may call the denial-reason function; the web and verifier roles and PUBLIC may not", async () => {
    expect((await sql1(webDbUrl(), "SELECT audit_read_denial_reason(gen_random_uuid())")).ok).toBe(false);
    expect((await sql1(auditUrl(), "SELECT audit_read_denial_reason(gen_random_uuid())")).ok).toBe(false);
    const bare = await sql1(appUrl(), "SELECT audit_read_denial_reason(gen_random_uuid()) AS r");
    expect(bare.ok && bare.r.rows[0].r).toBe("INVALID_INPUT"); // no request context: no answer about any file
  });

  it("it returns only reason codes and agrees with packages/policy on a grid (parity)", async () => {
    await admin.query("TRUNCATE case_files");
    const files: { id: string; classification: string; compartments: string[] }[] = [];
    for (const classification of ["OFFICIAL", "CONFIDENTIAL", "SECRET"])
      for (const compartments of [[], ["A"], ["A", "B"]]) {
        const id = randomUUID();
        await admin.query("INSERT INTO case_files (id, title, classification, unit, compartments, status, author_id, submitted_by_id) VALUES ($1, 't', $2::classification, 'alpha', $3::text[], 'approved', 'a', 's')", [id, classification, compartments]);
        files.push({ id, classification, compartments });
      }
    const codes = new Set<string>();
    for (const roles of [["analyst"], ["reviewer"], ["unit-admin"], ["auditor"], ["platform-admin"], ["ghost"], []])
      for (const clearance of ["OFFICIAL", "CONFIDENTIAL", "SECRET"])
        for (const compartments of [[], ["A"], ["B"], ["A", "B"]])
          for (const mfa of [false, true]) {
            const s = subjectOf({ roles, clearance, compartments });
            const e = envOf(mfa ? { ...MFA_ENV } : {});
            await probe(app, ctxOf(s, e, "read"), async (tx) => {
              for (const f of files) {
                const got = (await tx.query<{ r: string }>("SELECT audit_read_denial_reason($1) AS r" as never, [f.id])).rows[0]!.r;
                const d = evaluate(s, "read", { id: f.id, classification: f.classification, ownerUnit: "alpha", compartments: f.compartments, status: "approved", authorId: "a", submittedById: "s" }, e);
                codes.add(got);
                expect(got, `${roles}/${clearance}/${compartments}/${mfa}/${f.classification}${f.compartments}`).toBe(d.effect === "allow" ? "ALLOWED" : d.reason);
              }
              expect((await tx.query<{ r: string }>("SELECT audit_read_denial_reason($1) AS r" as never, [randomUUID()])).rows[0]!.r).toBe("RESOURCE_NOT_FOUND");
            });
          }
    expect([...codes].sort()).toEqual(["ALLOWED", "CLEARANCE_TOO_LOW", "COMPARTMENT_MISSING", "ROLE_NOT_PERMITTED", "STEP_UP_REQUIRED"]);
    await admin.query("TRUNCATE case_files");
  });

  it("nobody can call it directly", async () => {
    const r = await sql1(appUrl(), "SELECT audit_chain_guard()");
    expect(r.ok).toBe(false);
  });
});

describe("the break procedure (superuser) works but cannot be hidden", () => {
  it("with triggers disabled a row can be edited; the verifier then reports exactly that row", async () => {
    for (let i = 0; i < 8; i++) await append(app, entry({ requestId: `req-${String(i).padStart(8, "0")}` }));
    const c = await admin.connect();
    await c.query("BEGIN");
    await c.query("SET LOCAL session_replication_role = replica");
    await c.query("UPDATE audit_log SET effect = 'deny', reason_code = 'CLEARANCE_TOO_LOW' WHERE id = 4");
    await c.query("COMMIT");
    c.release();
    const h = await head();
    const res = await verifyChain(await rows(), ring, { head: { lastId: h.id, lastHash: h.last_hash } });
    expect(res.ok).toBe(false);
    expect(res.firstBad).toMatchObject({ id: 4, code: "HASH" });
  });
});
