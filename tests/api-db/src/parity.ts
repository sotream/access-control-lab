// Policy-vs-database parity harness: ask packages/policy `evaluate`, ask Postgres (row-level security + trigger) the same
// question as casefile_app with the same subject, and compare.
import { evaluate, type Environment, type Resource, type Subject } from "@acl/policy";
import type pg from "pg";
import { sql } from "../../../apps/api/src/db/sql.js";
import type { Tx } from "../../../apps/api/src/db/context.js";
import { ctxOf, probe, type Row } from "./db.js";

/**
 * Differences between the policy engine and the database layer that are INTENTIONAL. Anything not listed here
 * that differs is a bug and fails parity. Each entry names where the behaviour is tested instead.
 */
export const KNOWN_DIFFERENCES: readonly { id: string; what: string; coveredBy: string }[] = [
  { id: "export", what: "export (approved-only, managed network zone, UTC window) is decided by the app only; the database sees a read", coveredBy: "packages/policy evaluate.test.ts, apps/api policy.test.ts" },
  { id: "blank-break-glass", what: "a break-glass request with a blank justification is refused by the app before any query; the database never receives the flag", coveredBy: "packages/policy evaluate.test.ts; rls.test.ts (blank justification does not open rows)" },
  { id: "invalid-input", what: "unknown or malformed values (unknown clearance, missing fields) cannot exist in typed columns or are rejected as missing context", coveredBy: "roles.test.ts (no context, no rows); packages/policy malformed-input table" },
  { id: "no-table-actions", what: "readAudit and manageUsers have no table in this stage; they are role-only decisions in the app", coveredBy: "packages/policy role matrix; apps/api policy.test.ts" },
  { id: "immutable-columns", what: "the database forbids changing classification, unit, compartments, author and id of an existing file; the policy has no reclassify action", coveredBy: "rls.test.ts (immutable columns)" },
  { id: "break-glass-non-read", what: "the database ignores the break-glass flag for writes (no policy mentions it); the policy ignores it for non-read actions too", coveredBy: "rls.test.ts" },
];

export type DbAction = "read" | "create" | "update" | "submit" | "approve" | "delete";
export const DB_ACTIONS: readonly DbAction[] = ["read", "create", "update", "submit", "approve", "delete"];

export type GridRow = Required<Pick<Row, "id" | "classification" | "unit" | "compartments" | "status" | "authorId">> & { submittedById: string | null };

export const asResource = (r: GridRow): Resource => ({
  id: r.id,
  classification: r.classification,
  ownerUnit: r.unit,
  compartments: r.compartments,
  status: r.status,
  authorId: r.authorId,
  submittedById: r.submittedById,
});

const SELECT_IDS = sql`SELECT id FROM case_files`;
const UPD_TITLE = sql`UPDATE case_files SET title = 'changed' WHERE id = $1`;
const UPD_SUBMIT = sql`UPDATE case_files SET status = 'submitted' WHERE id = $1`;
const UPD_APPROVE = sql`UPDATE case_files SET status = 'approved' WHERE id = $1`;
const DEL = sql`DELETE FROM case_files WHERE id = $1`;
const INS = sql`INSERT INTO case_files (title, body, classification, unit, compartments, author_id, status) VALUES ('t', '', $1::classification, $2, $3::text[], $4, $5::case_status)`;

const DENIED_CODES = new Set(["42501", "23514"]); // insufficient_privilege (RLS, trigger), check_violation

async function attempt(tx: Tx, stmt: ReturnType<typeof sql>, params: unknown[], expectRows: boolean): Promise<boolean> {
  await tx.query(sql`SAVEPOINT parity` as never);
  try {
    const r = await tx.query(stmt, params);
    return expectRows ? r.rows.length > 0 : r.rowCount === 1;
  } catch (e) {
    const code = (e as { code?: string }).code;
    if (code && DENIED_CODES.has(code)) return false;
    throw e;
  } finally {
    await tx.query(sql`ROLLBACK TO SAVEPOINT parity` as never);
  }
}

/** What the database lets this subject do, for every row, in one transaction per (subject, env, action). */
export async function dbOutcomes(pool: pg.Pool, action: DbAction, subject: Subject, env: Environment, rows: readonly GridRow[]): Promise<Map<string, boolean>> {
  return probe(pool, ctxOf(subject, env, action), async (tx) => {
    const out = new Map<string, boolean>();
    if (action === "read") {
      const visible = new Set((await tx.query<{ id: string }>(SELECT_IDS)).rows.map((r) => r.id));
      for (const r of rows) out.set(r.id, visible.has(r.id));
      return out;
    }
    for (const r of rows) {
      let ok: boolean;
      if (action === "create") ok = await attempt(tx, INS, [r.classification, r.unit, r.compartments, r.authorId, r.status], false);
      else if (action === "update") ok = await attempt(tx, UPD_TITLE, [r.id], false);
      else if (action === "submit") ok = await attempt(tx, UPD_SUBMIT, [r.id], false);
      else if (action === "approve") ok = await attempt(tx, UPD_APPROVE, [r.id], false);
      else ok = await attempt(tx, DEL, [r.id], false);
      out.set(r.id, ok);
    }
    return out;
  });
}

export interface Mismatch {
  action: DbAction;
  subject: string;
  env: string;
  row: string;
  db: boolean;
  policy: boolean;
  policyReason: string;
}

const short = (r: GridRow) => `${r.classification}/${r.unit}/[${r.compartments}]/${r.status}/author=${r.authorId}/sub=${r.submittedById}`;
const sShort = (s: Subject) => `${s.roles.join("+") || "-"}/${s.clearance}/${s.unit}/[${s.compartments}]/id=${s.id}`;
const eShort = (e: Environment) => `acr=${e.acr}/amr=${e.amr}/bg=${e.breakGlass ? JSON.stringify(e.breakGlass.justification) : "-"}`;

export async function compare(pool: pg.Pool, action: DbAction, subject: Subject, env: Environment, rows: readonly GridRow[]): Promise<Mismatch[]> {
  const db = await dbOutcomes(pool, action, subject, env, rows);
  const bad: Mismatch[] = [];
  for (const r of rows) {
    const d = evaluate(subject, action, asResource(r), env);
    const policy = d.effect === "allow";
    if (db.get(r.id) !== policy) {
      bad.push({ action, subject: sShort(subject), env: eShort(env), row: short(r), db: db.get(r.id) as boolean, policy, policyReason: d.reason });
    }
  }
  return bad;
}

/** Readable failure text: the first mismatches as a table. */
export function diff(bad: readonly Mismatch[], limit = 15): string {
  if (bad.length === 0) return "";
  const lines = bad.slice(0, limit).map((m) => `${m.action.padEnd(7)} db=${String(m.db).padEnd(5)} policy=${String(m.policy).padEnd(5)} (${m.policyReason})\n    subject ${m.subject}\n    env     ${m.env}\n    row     ${m.row}`);
  return `${bad.length} parity mismatches (first ${Math.min(limit, bad.length)}):\n${lines.join("\n")}`;
}
