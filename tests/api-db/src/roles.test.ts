// The application role is powerless by construction (T-14, T-15, T-18).
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminPool, appPool, appUrl, clearRows, ctxOf, envOf, insertRow, MFA_ENV, migratorUrl, probe, subjectOf, TEST_DB } from "./db.js";

const admin = adminPool();
const app = appPool();
afterAll(async () => {
  await admin.end();
  await app.end();
});

const fails = async (sql: string) => {
  const c = new pg.Client({ connectionString: appUrl() });
  await c.connect();
  try {
    await c.query(sql);
    return undefined;
  } catch (e) {
    return (e as { code?: string }).code;
  } finally {
    await c.end();
  }
};

describe("role attributes", () => {
  it("casefile_app: login only, no superuser, no BYPASSRLS, no createdb/createrole/replication, bounded connections", async () => {
    const r = (await admin.query("SELECT * FROM pg_roles WHERE rolname = 'casefile_app'")).rows[0];
    expect(r).toMatchObject({ rolsuper: false, rolbypassrls: false, rolcreatedb: false, rolcreaterole: false, rolreplication: false, rolcanlogin: true });
    expect(r.rolconnlimit).toBeGreaterThan(0);
  });

  it("casefile_migrator is not a superuser and has no BYPASSRLS either", async () => {
    const r = (await admin.query("SELECT * FROM pg_roles WHERE rolname = 'casefile_migrator'")).rows[0];
    expect(r).toMatchObject({ rolsuper: false, rolbypassrls: false, rolcreatedb: false, rolcreaterole: false });
  });

  it("the app role owns nothing and is a member of no other role", async () => {
    const owned = await admin.query("SELECT relname FROM pg_class WHERE relowner = (SELECT oid FROM pg_roles WHERE rolname = 'casefile_app') AND relnamespace = 'public'::regnamespace");
    expect(owned.rows).toEqual([]);
    const member = await admin.query("SELECT 1 FROM pg_auth_members WHERE member = (SELECT oid FROM pg_roles WHERE rolname = 'casefile_app')");
    expect(member.rows).toEqual([]);
    const fn = await admin.query("SELECT proname FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proowner = (SELECT oid FROM pg_roles WHERE rolname = 'casefile_app')");
    expect(fn.rows).toEqual([]);
  });

  it("tables, policies and functions belong to the migrator; RLS is enabled AND forced", async () => {
    const t = (await admin.query("SELECT tableowner FROM pg_tables WHERE schemaname = 'public' AND tablename IN ('case_files','role_grants')")).rows;
    expect(t.map((x) => x.tableowner)).toEqual(["casefile_migrator", "casefile_migrator"]);
    const c = (await admin.query("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'case_files'")).rows[0];
    expect(c).toEqual({ relrowsecurity: true, relforcerowsecurity: true });
  });

  it("exactly two SECURITY DEFINER functions exist, both documented in the migrations (audit chain guard, audit denial reason)", async () => {
    const r = await admin.query("SELECT proname FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND prosecdef ORDER BY proname");
    expect(r.rows.map((x) => x.proname)).toEqual(["audit_chain_guard", "audit_read_denial_reason"]);
  });

  it("every function pins its search_path", async () => {
    const r = await admin.query("SELECT proname FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND (proconfig IS NULL OR NOT proconfig::text ~ 'search_path=')");
    expect(r.rows).toEqual([]);
  });

  it("role-level guard rails: statement, lock and idle-in-transaction timeouts, applied to a fresh connection", async () => {
    const c = new pg.Client({ connectionString: appUrl() });
    await c.connect();
    const r = (await c.query("SELECT current_setting('statement_timeout') s, current_setting('lock_timeout') l, current_setting('idle_in_transaction_session_timeout') i")).rows[0];
    await c.end();
    expect(r).toEqual({ s: "5s", l: "3s", i: "15s" });
  });
});

describe("what the app role cannot do (T-15, T-18)", () => {
  it.each([
    ["ALTER TABLE case_files DISABLE ROW LEVEL SECURITY"],
    ["ALTER TABLE case_files NO FORCE ROW LEVEL SECURITY"],
    ["ALTER TABLE case_files ADD COLUMN x int"],
    ["ALTER TABLE case_files OWNER TO casefile_app"],
    ["DROP TABLE case_files"],
    ["DROP POLICY case_files_select ON case_files"],
    ["CREATE POLICY p ON case_files FOR ALL USING (true)"],
    ["ALTER TABLE case_files DISABLE TRIGGER case_files_guard"],
    ["DROP TRIGGER case_files_guard ON case_files"],
    ["TRUNCATE case_files"],
    ["CREATE TABLE public.evil (x int)"],
    ["CREATE FUNCTION public.evil() RETURNS int LANGUAGE sql AS 'select 1'"],
    ["CREATE OR REPLACE FUNCTION public.app_ctx_ok() RETURNS boolean LANGUAGE sql AS 'select true'"],
    ["DROP FUNCTION public.app_ctx_ok()"],
    ["INSERT INTO role_grants (role, action) VALUES ('analyst','approve')"],
    ["UPDATE role_grants SET cross_unit = true"],
    ["DELETE FROM role_grants"],
    ["ALTER ROLE casefile_app BYPASSRLS"],
    ["ALTER ROLE casefile_app SUPERUSER"],
    ["CREATE ROLE evil SUPERUSER"],
    ["SET ROLE casefile_migrator"],
    ["SET ROLE postgres"],
    ["SET session_replication_role = replica"],
    ["CREATE SCHEMA evil"],
    ["COPY case_files TO '/tmp/x'"],
    ["SELECT * FROM schema_migrations"],
  ])("%s is refused", async (statement) => {
    const code = await fails(statement);
    expect(code, statement).toBeDefined();
    expect(["42501", "0LP01", "25006"]).toContain(code); // insufficient_privilege (and its relatives); never "succeeded"
  });

  it("GRANT by the app role is a no-op (warning only): PUBLIC still has nothing, and the app role has no grant option", async () => {
    await fails("GRANT ALL ON case_files TO PUBLIC");
    await fails("GRANT ALL ON case_files TO casefile_migrator");
    const acl = await admin.query("SELECT a.grantee::regrole::text AS grantee, a.privilege_type, a.is_grantable FROM pg_class c, aclexplode(c.relacl) a WHERE c.relname = 'case_files'");
    const publicGrants = acl.rows.filter((r) => r.grantee === "-");
    expect(publicGrants).toEqual([]);
    expect(acl.rows.filter((r) => r.grantee === "casefile_app" && r.is_grantable)).toEqual([]);
    const privs = acl.rows.filter((r) => r.grantee === "casefile_app").map((r) => r.privilege_type).sort();
    expect(privs).toEqual(["DELETE", "SELECT"]); // INSERT/UPDATE are column-level
  });

  it("UPDATE is limited to title, body, status: classification, unit, compartments, author, version are not writable", async () => {
    await clearRows(admin);
    const id = await insertRow(admin, { authorId: "u1" });
    const ctx = ctxOf(subjectOf({ id: "u1" }), envOf());
    for (const col of ["classification = 'SECRET'", "unit = 'beta'", "compartments = '{A}'", "author_id = 'x'", "version = 99", "submitted_by_id = 'x'", "id = gen_random_uuid()", "created_at = now()"]) {
      const code = await probe(app, ctx, async (tx) => {
        try {
          // static test statements: nothing user-controlled
          await tx.query(`UPDATE case_files SET ${col} WHERE id = $1` as never, [id]);
          return "ok";
        } catch (e) {
          return (e as { code?: string }).code;
        }
      });
      expect(code, col).toBe("42501");
    }
  });

  it("INSERT cannot set version, submitted_by_id, id, timestamps", async () => {
    const ctx = ctxOf(subjectOf({ id: "u1" }), envOf());
    for (const col of ["version", "submitted_by_id", "id", "created_at", "updated_at"]) {
      const val = col === "id" ? "gen_random_uuid()" : col === "version" ? "5" : col === "submitted_by_id" ? "'x'" : "now()";
      const code = await probe(app, ctx, async (tx) => {
        try {
          await tx.query(`INSERT INTO case_files (title, classification, unit, author_id, ${col}) VALUES ('t','OFFICIAL','alpha','u1', ${val})` as never);
          return "ok";
        } catch (e) {
          return (e as { code?: string }).code;
        }
      });
      expect(code, col).toBe("42501");
    }
  });

  it("row_security = off makes a query that RLS would filter fail instead of bypassing it", async () => {
    await clearRows(admin);
    await insertRow(admin, { classification: "SECRET" });
    const c = new pg.Client({ connectionString: appUrl() });
    await c.connect();
    await c.query("SET row_security = off");
    const code = await c.query("SELECT * FROM case_files").then(() => "ok", (e) => (e as { code?: string }).code);
    await c.end();
    expect(code).toBe("42501");
  });
});

describe("no context, no rows (fail closed)", () => {
  beforeAll(async () => {
    await clearRows(admin);
    await insertRow(admin, { classification: "OFFICIAL" });
  });

  it("a bare connection of the app role reads nothing and writes nothing", async () => {
    const c = new pg.Client({ connectionString: appUrl() });
    await c.connect();
    expect((await c.query("SELECT * FROM case_files")).rows).toEqual([]);
    await expect(c.query("INSERT INTO case_files (title, classification, unit, author_id) VALUES ('t','OFFICIAL','alpha','u1')")).rejects.toMatchObject({ code: "42501" });
    expect((await c.query("DELETE FROM case_files")).rowCount).toBe(0);
    expect((await c.query("UPDATE case_files SET title = 'x'")).rowCount).toBe(0);
    await c.end();
  });

  it.each([
    ["marker only", { "app.ctx": "v1" }],
    ["everything but the marker", { "app.sub": "u1", "app.unit": "alpha", "app.clearance": "SECRET", "app.roles": "analyst", "app.compartments": "", "app.acr": "mfa", "app.amr": "pwd,otp" }],
    ["unknown clearance", { "app.ctx": "v1", "app.sub": "u1", "app.unit": "alpha", "app.clearance": "TOPSECRET", "app.roles": "analyst" }],
    ["lower-case clearance", { "app.ctx": "v1", "app.sub": "u1", "app.unit": "alpha", "app.clearance": "official", "app.roles": "analyst" }],
    ["empty sub", { "app.ctx": "v1", "app.sub": "", "app.unit": "alpha", "app.clearance": "OFFICIAL", "app.roles": "analyst" }],
    ["no roles", { "app.ctx": "v1", "app.sub": "u1", "app.unit": "alpha", "app.clearance": "SECRET", "app.roles": "" }],
    ["unknown role", { "app.ctx": "v1", "app.sub": "u1", "app.unit": "alpha", "app.clearance": "SECRET", "app.roles": "superuser,constructor" }],
    ["wrong marker version", { "app.ctx": "v2", "app.sub": "u1", "app.unit": "alpha", "app.clearance": "OFFICIAL", "app.roles": "analyst" }],
  ])("partial or malformed context (%s) sees no rows", async (_n, settings) => {
    const c = new pg.Client({ connectionString: appUrl() });
    await c.connect();
    await c.query("BEGIN");
    for (const [k, v] of Object.entries(settings)) await c.query("SELECT set_config($1, $2, true)", [k, v]);
    const rows = (await c.query("SELECT * FROM case_files")).rows;
    await c.query("ROLLBACK");
    await c.end();
    expect(rows).toEqual([]);
  });

  it("the migrator (table owner) is bound by RLS too (FORCE): no rows without a context", async () => {
    const c = new pg.Client({ connectionString: migratorUrl() });
    await c.connect();
    expect((await c.query("SELECT * FROM case_files")).rows).toEqual([]);
    await c.end();
  });

  it("with a proper context the same connection pool sees the row", async () => {
    const rows = await probe(app, ctxOf(subjectOf(), envOf()), async (tx) => (await tx.query("SELECT id FROM case_files" as never)).rows);
    expect(rows).toHaveLength(1);
  });

  it("sanity: the test database is the test database", () => {
    expect(TEST_DB.endsWith("_test")).toBe(true);
    void MFA_ENV;
  });
});
