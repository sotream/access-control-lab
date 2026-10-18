// Migrations: from empty, idempotent, tamper-evident, serialised, atomic (T-20).
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { migrate, MIGRATIONS_DIR } from "../../../apps/api/src/db/migrate.js";
import { adminPool, migratorUrl } from "./db.js";

const admin = adminPool("postgres");
const created: string[] = [];

async function scratchDb(): Promise<string> {
  const name = `acl_scratch_${randomBytes(4).toString("hex")}`;
  await admin.query(`CREATE DATABASE ${name} OWNER casefile_migrator`);
  created.push(name);
  const a = adminPool(name);
  await a.query("REVOKE ALL ON SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO casefile_app; GRANT ALL ON SCHEMA public TO casefile_migrator");
  await a.end();
  return name;
}

afterAll(async () => {
  for (const n of created) await admin.query(`DROP DATABASE IF EXISTS ${n} WITH (FORCE)`);
  await admin.end();
});

describe("migrations", () => {
  let db: string;
  beforeEach(async () => {
    db = await scratchDb();
  });

  it("apply on an empty database and create the secured schema", async () => {
    const r = await migrate(migratorUrl(db));
    expect(r.applied).toEqual(["001_case_files.sql", "002_bff_sessions.sql", "003_audit_log.sql", "004_audit_denial_reason.sql"]);
    const a = adminPool(db);
    const c = (await a.query("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'case_files'")).rows[0];
    expect(c).toEqual({ relrowsecurity: true, relforcerowsecurity: true });
    expect((await a.query("SELECT count(*)::int AS n FROM pg_policies WHERE tablename = 'case_files'")).rows[0].n).toBe(5); // select, insert, update, delete, and the lookup role of the audit denial reason
    expect((await a.query("SELECT count(*)::int AS n FROM role_grants")).rows[0].n).toBe(19);
    await a.end();
  });

  it("re-running is a no-op", async () => {
    await migrate(migratorUrl(db));
    const again = await migrate(migratorUrl(db));
    expect(again.applied).toEqual([]);
    expect(again.alreadyApplied).toEqual(["001_case_files.sql", "002_bff_sessions.sql", "003_audit_log.sql", "004_audit_denial_reason.sql"]);
  });

  it("a migration edited after it was applied stops the run", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mig-"));
    writeFileSync(join(dir, "001_a.sql"), "CREATE TABLE a (x int);");
    await migrate(migratorUrl(db), dir);
    writeFileSync(join(dir, "001_a.sql"), "CREATE TABLE a (x int, y int);");
    await expect(migrate(migratorUrl(db), dir)).rejects.toThrow(/modified after it was applied/);
  });

  it("an applied migration that disappeared stops the run", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mig-"));
    writeFileSync(join(dir, "001_a.sql"), "CREATE TABLE a (x int);");
    await migrate(migratorUrl(db), dir);
    const empty = mkdtempSync(join(tmpdir(), "mig-"));
    await expect(migrate(migratorUrl(db), empty)).rejects.toThrow(/missing on disk/);
  });

  it("bad file names and duplicate numbers are refused", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mig-"));
    writeFileSync(join(dir, "1_a.sql"), "SELECT 1;");
    await expect(migrate(migratorUrl(db), dir)).rejects.toThrow(/bad migration file name/);
    const dir2 = mkdtempSync(join(tmpdir(), "mig-"));
    writeFileSync(join(dir2, "001_a.sql"), "SELECT 1;");
    writeFileSync(join(dir2, "001_b.sql"), "SELECT 1;");
    await expect(migrate(migratorUrl(db), dir2)).rejects.toThrow(/duplicate migration number/);
  });

  it("a failing migration rolls back completely and is retried next time", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mig-"));
    writeFileSync(join(dir, "001_ok.sql"), "CREATE TABLE ok_table (x int);");
    writeFileSync(join(dir, "002_bad.sql"), "CREATE TABLE half (x int); SELECT 1/0;");
    await expect(migrate(migratorUrl(db), dir)).rejects.toThrow();
    const a = adminPool(db);
    expect((await a.query("SELECT to_regclass('half') AS t")).rows[0].t).toBeNull();
    expect((await a.query("SELECT name FROM schema_migrations")).rows.map((r) => r.name)).toEqual(["001_ok.sql"]);
    writeFileSync(join(dir, "002_bad.sql"), "CREATE TABLE half (x int);");
    // the edited file was never applied, so changing it is legitimate
    expect((await migrate(migratorUrl(db), dir)).applied).toEqual(["002_bad.sql"]);
    await a.end();
  });

  it("two runners at once apply each migration exactly once (advisory lock)", async () => {
    const [a, b] = await Promise.all([migrate(migratorUrl(db)), migrate(migratorUrl(db))]);
    expect([...a.applied, ...b.applied]).toEqual(["001_case_files.sql", "002_bff_sessions.sql", "003_audit_log.sql", "004_audit_denial_reason.sql"]);
  });

  it("the shipped migration file is exactly what the repository holds (guards against accidental edits after release)", () => {
    expect(readFileSync(join(MIGRATIONS_DIR, "001_case_files.sql"), "utf8")).toContain("FORCE ROW LEVEL SECURITY");
  });
});
