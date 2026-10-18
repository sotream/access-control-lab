import type { Environment, Subject } from "@acl/policy";
import type pg from "pg";
import type { Sql } from "./sql.js";
import { sql } from "./sql.js";

/** What Postgres row-level security sees. Set per transaction, never per connection. */
export interface DbContext {
  sub: string;
  roles: readonly string[];
  clearance: string;
  unit: string;
  compartments: readonly string[];
  acr: string;
  amr: readonly string[];
  /** only for read requests, only with a non-blank justification (checked here, and again by the policy) */
  breakGlass?: { justification: string };
}

/** A transaction handle that only accepts `sql` tagged text: no way to pass a built string. */
export interface Tx {
  query<R extends pg.QueryResultRow = pg.QueryResultRow>(text: Sql, params?: readonly unknown[]): Promise<pg.QueryResult<R>>;
}

export function toDbContext(subject: Subject, env: Environment, action: string): DbContext {
  const j = env.breakGlass?.justification.trim() ?? "";
  return {
    sub: subject.id,
    roles: subject.roles,
    clearance: subject.clearance,
    unit: subject.unit,
    compartments: subject.compartments,
    acr: env.acr,
    amr: env.amr,
    ...(action === "read" && j !== "" ? { breakGlass: { justification: j } } : {}),
  };
}

// list members travel comma separated, so a member must not contain a comma; control characters never belong in a setting
const bad = (v: string) => /[\u0000-\u001f\u007f]/.test(v) || v.length > 600;
function list(name: string, items: readonly string[]): string {
  for (const i of items) if (bad(i) || i.includes(",")) throw new Error(`context ${name} has an unsafe member`);
  return items.join(",");
}
function scalar(name: string, v: string): string {
  if (bad(v)) throw new Error(`context ${name} is unsafe`);
  return v;
}

const SET_CONTEXT = sql`SELECT set_config('app.sub', $1, true), set_config('app.roles', $2, true), set_config('app.clearance', $3, true),
  set_config('app.unit', $4, true), set_config('app.compartments', $5, true), set_config('app.acr', $6, true),
  set_config('app.amr', $7, true), set_config('app.break_glass', $8, true), set_config('app.bg_justification', $9, true),
  set_config('app.ctx', 'v1', true)`;

/**
 * Runs `fn` in ONE transaction whose first statement sets the request context transaction-locally (is_local = true).
 * The settings vanish at COMMIT/ROLLBACK, so a pooled connection can never carry them into another request.
 */
export async function withContext<T>(pool: pg.Pool, ctx: DbContext, fn: (tx: Tx) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    try {
      await client.query(SET_CONTEXT, [
        scalar("sub", ctx.sub),
        list("roles", ctx.roles),
        scalar("clearance", ctx.clearance),
        scalar("unit", ctx.unit),
        list("compartments", ctx.compartments),
        scalar("acr", ctx.acr),
        list("amr", ctx.amr),
        ctx.breakGlass ? "on" : "off",
        scalar("justification", ctx.breakGlass?.justification ?? ""),
      ]);
      const out = await fn(client as unknown as Tx);
      await client.query("COMMIT");
      return out;
    } catch (e) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw e;
    }
  } finally {
    client.release();
  }
}
