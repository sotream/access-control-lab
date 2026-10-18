// Database helpers for the data-layer tests. Everything runs against the `<POSTGRES_DB>_test` database of the compose Postgres.
import { randomUUID } from "node:crypto";
import { GENESIS_HASH_HEX, parseAuditKeys } from "@acl/audit";
import pg from "pg";
import type { Environment, Subject } from "@acl/policy";
import { toDbContext, withContext, type DbContext, type Tx } from "../../../apps/api/src/db/context.js";
import { createPool } from "../../../apps/api/src/db/pool.js";

try {
  process.loadEnvFile(new URL("../../../.env", import.meta.url));
} catch {
  // variables may come from the environment (CI copies .env.example to .env)
}

const need = (n: string) => {
  const v = process.env[n];
  if (!v) throw new Error(`missing env ${n} (copy .env.example to .env)`);
  return v;
};

/** same server and credentials, test database */
export function withDb(url: string, db: string): string {
  const u = new URL(url);
  u.pathname = `/${db}`;
  return u.toString();
}

const devDb = () => new URL(need("DATABASE_URL")).pathname.slice(1);
// overridable so the suite can be pointed at a deliberately broken scratch database (mutation checks)
export const TEST_DB = process.env.TEST_DB_NAME ?? `${devDb()}_test`;
export const adminUrl = (db = TEST_DB) => withDb(need("ADMIN_DATABASE_URL"), db);
export const migratorUrl = (db = TEST_DB) => withDb(need("MIGRATOR_DATABASE_URL"), db);
export const appUrl = (db = TEST_DB) => withDb(need("DATABASE_URL"), db);

export const auditUrl = (db = TEST_DB) => withDb(need("AUDIT_DATABASE_URL"), db);
export const webDbUrl = (db = TEST_DB) => withDb(need("WEB_DATABASE_URL"), db);
export const auditKeys = () => parseAuditKeys(need("AUDIT_HMAC_KEYS"));
export const auditPool = (db = TEST_DB) => new pg.Pool({ connectionString: auditUrl(db), max: 2 });
export const webPool = (db = TEST_DB) => new pg.Pool({ connectionString: webDbUrl(db), max: 4 });

/**
 * Empties the audit tables and rewinds the head, as a SUPERUSER with triggers disabled for the transaction (the documented break procedure).
 * Test databases only: this is exactly the operation the production roles can never perform.
 */
export async function resetAudit(admin: pg.Pool): Promise<void> {
  const c = await admin.connect();
  try {
    await c.query("BEGIN");
    await c.query("SET LOCAL session_replication_role = replica");
    await c.query("TRUNCATE audit_log, audit_checkpoints");
    await c.query("UPDATE audit_head SET last_id = 0, last_hash = decode($1, 'hex')", [GENESIS_HASH_HEX]);
    await c.query("COMMIT");
  } catch (e) {
    await c.query("ROLLBACK").catch(() => undefined);
    throw e;
  } finally {
    c.release();
  }
}

export const adminPool = (db = TEST_DB) => new pg.Pool({ connectionString: adminUrl(db), max: 4 });
export const migratorPool = (db = TEST_DB) => new pg.Pool({ connectionString: migratorUrl(db), max: 2 });
export const appPool = (max = 5, db = TEST_DB) => createPool({ connectionString: appUrl(db), max });

export interface Row {
  id?: string;
  title?: string;
  body?: string;
  classification?: string;
  unit?: string;
  compartments?: string[];
  status?: string;
  authorId?: string;
  submittedById?: string | null;
  version?: number;
}

/** Inserts as the superuser (bypasses RLS) so tests can create any state, including ones the app could never reach. */
export async function insertRow(admin: pg.Pool, r: Row): Promise<string> {
  const id = r.id ?? randomUUID();
  const status = r.status ?? "draft";
  await admin.query(
    "INSERT INTO case_files (id, title, body, classification, unit, compartments, status, author_id, submitted_by_id, version) VALUES ($1,$2,$3,$4::classification,$5,$6::text[],$7::case_status,$8,$9,$10)",
    [
      id,
      r.title ?? "t",
      r.body ?? "",
      r.classification ?? "OFFICIAL",
      r.unit ?? "alpha",
      r.compartments ?? [],
      status,
      r.authorId ?? "author-1",
      r.submittedById !== undefined ? r.submittedById : status === "draft" ? null : "submitter-1",
      r.version ?? 1,
    ],
  );
  return id;
}

export const clearRows = (admin: pg.Pool) => admin.query("TRUNCATE attachments, case_files");

export const MFA_ENV = { acr: "mfa", amr: ["pwd", "otp"] } as const;
export const NOON = Date.UTC(2026, 9, 17, 12, 0, 0) / 1000;

export const envOf = (o: Partial<Environment> = {}): Environment => ({ acr: "pwd", amr: ["pwd"], now: NOON, networkZone: "managed", ...o });
export const subjectOf = (o: Partial<Subject> = {}): Subject => ({ id: "u1", roles: ["analyst"], clearance: "OFFICIAL", unit: "alpha", compartments: [], ...o });

class Rollback<T> extends Error {
  constructor(readonly value: T) {
    super("rollback");
  }
}

/** Runs `fn` with the request context set, then always rolls back: for probing what the database allows without changing state. */
export async function probe<T>(pool: pg.Pool, ctx: DbContext, fn: (tx: Tx) => Promise<T>): Promise<T> {
  try {
    return await withContext(pool, ctx, async (tx) => {
      throw new Rollback(await fn(tx));
    });
  } catch (e) {
    if (e instanceof Rollback) return e.value as T;
    throw e;
  }
}

export const ctxOf = (s: Subject, e: Environment, action = "none"): DbContext => toDbContext(s, e, action);
export { withContext, toDbContext };

/** Map with bounded concurrency; results keep input order. */
export async function pmap<T, R>(items: readonly T[], concurrency: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i] as T);
      }
    }),
  );
  return out;
}
