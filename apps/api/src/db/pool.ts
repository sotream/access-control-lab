import pg from "pg";
import { sql } from "./sql.js";

export interface PoolOptions {
  connectionString: string;
  max: number;
}

export function createPool(o: PoolOptions): pg.Pool {
  const pool = new pg.Pool({
    connectionString: o.connectionString,
    max: o.max,
    connectionTimeoutMillis: 5_000, // fail instead of queueing forever when the pool is exhausted
    idleTimeoutMillis: 30_000,
    application_name: "casefile-api",
    // statement_timeout, lock_timeout and idle_in_transaction_session_timeout come from ALTER ROLE casefile_app (init script)
  });
  pool.on("error", () => undefined); // an idle client error must not crash the process; the next checkout reconnects
  return pool;
}

/**
 * Refuse to run as a role that would make row-level security meaningless: superuser, BYPASSRLS, or owner of the tables.
 * Called at startup; a misconfigured DATABASE_URL stops the API instead of silently disabling the database layer.
 */
export async function assertSafeRole(pool: pg.Pool): Promise<void> {
  const r = await pool.query<{ rolname: string; rolsuper: boolean; rolbypassrls: boolean; owns: number }>(
    sql`SELECT r.rolname, r.rolsuper, r.rolbypassrls,
        (SELECT count(*)::int FROM pg_class c WHERE c.relowner = r.oid AND c.relnamespace = 'public'::regnamespace) AS owns
        FROM pg_roles r WHERE r.rolname = current_user`,
  );
  const row = r.rows[0];
  if (!row) throw new Error("cannot read the current role");
  if (row.rolsuper || row.rolbypassrls || row.owns > 0) {
    throw new Error(`database role ${row.rolname} is unsafe for the API (superuser, BYPASSRLS or table owner)`);
  }
}
