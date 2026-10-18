import { rowFromDb, verifyChain, type AuditKeys, type AuditRow, type Checkpoint, type VerifyResult } from "@acl/audit";
import type pg from "pg";
import { sql } from "../db/sql.js";

const ROWS = sql`SELECT id, ts, actor_sub, actor_roles, action, resource_type, resource_id, effect, reason_code, obligations, request_id, source, details, prev_hash, key_id, hash
  FROM audit_log WHERE id > $1 AND ($2::bigint IS NULL OR id <= $2) ORDER BY id LIMIT $3`;
const ROW_HASH = sql`SELECT hash FROM audit_log WHERE id = $1`;
const HEAD = sql`SELECT last_id, last_hash FROM audit_head WHERE singleton`;
const CHECKPOINTS = sql`SELECT id, ts, last_id, last_hash, key_id, mac FROM audit_checkpoints ORDER BY id`;

export interface DbVerifyOptions {
  fromId?: number;
  toId?: number;
  /** the trusted hash of row fromId - 1 (e.g. from an external checkpoint). Without it, range verification trusts the stored row. */
  prevHash?: Buffer;
  /** checkpoints from outside the database (an exported file) in addition to those stored in it */
  extraCheckpoints?: readonly Checkpoint[];
  batch?: number;
}

export const checkpointFromDb = (r: Record<string, unknown>): Checkpoint => ({ id: Number(r.id), ts: r.ts as Date, lastId: Number(r.last_id), lastHash: r.last_hash as Buffer, keyId: r.key_id as string, mac: r.mac as Buffer });

/** Recomputes the chain stored in Postgres, in batches (keyset pagination), against head and checkpoints. Use a role that can read every row (casefile_audit). */
export async function verifyDatabase(pool: Pick<pg.Pool, "query">, ring: AuditKeys, o: DbVerifyOptions = {}): Promise<VerifyResult> {
  const batch = o.batch ?? 1000;
  const fromId = o.fromId ?? 1;
  let startAfter: { id: number; hash: Buffer } | undefined;
  if (fromId > 1) {
    const hash = o.prevHash ?? (await pool.query<{ hash: Buffer }>(ROW_HASH, [fromId - 1])).rows[0]?.hash;
    if (!hash) throw new Error(`row ${fromId - 1} not found: cannot start a range at ${fromId}`);
    startAfter = { id: fromId - 1, hash };
  }
  async function* rows(): AsyncGenerator<AuditRow> {
    let after = fromId - 1;
    for (;;) {
      const r = await pool.query(ROWS, [after, o.toId ?? null, batch]);
      if (r.rows.length === 0) return;
      for (const row of r.rows) yield rowFromDb(row);
      after = Number(r.rows[r.rows.length - 1]?.id);
    }
  }
  const head = (await pool.query(HEAD)).rows[0];
  const checkpoints = [...(await pool.query(CHECKPOINTS)).rows.map(checkpointFromDb), ...(o.extraCheckpoints ?? [])];
  return verifyChain(rows(), ring, { ...(startAfter ? { startAfter } : {}), ...(o.toId !== undefined ? { toId: o.toId } : {}), ...(head ? { head: { lastId: Number(head.last_id), lastHash: head.last_hash as Buffer } } : {}), checkpoints });
}
