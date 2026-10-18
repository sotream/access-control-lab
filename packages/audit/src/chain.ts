import { canonicalBytes } from "./canonical.js";
import { validateDetails } from "./details.js";
import { mac, type AuditKeys } from "./keys.js";
import { GENESIS_HASH_HEX, type AuditEntry, type AuditRow, type Head } from "./model.js";

const SUB = /^[A-Za-z0-9_.:-]{1,128}$/;
const ACTION = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const RTYPE = /^[a-z_]{1,32}$/;
const REASON = /^[A-Z][A-Z0-9_]{0,63}$/;
const REQ = /^[A-Za-z0-9-]{8,64}$/;
const TAG = /^[A-Za-z0-9_.:-]{1,64}$/;

export const genesisHead = (): Head => ({ lastId: 0, lastHash: Buffer.from(GENESIS_HASH_HEX, "hex") });

/** Same rules as the table CHECK constraints, so a bad entry fails in the application with a message instead of in the database. */
export function validateEntry(e: AuditEntry): void {
  const bad = (what: string): never => {
    throw new Error(`invalid audit entry: ${what}`);
  };
  if (!SUB.test(e.actorSub)) bad("actorSub");
  if (e.actorRoles.length > 16 || !e.actorRoles.every((r) => TAG.test(r))) bad("actorRoles");
  if (!ACTION.test(e.action)) bad("action");
  if (!RTYPE.test(e.resourceType)) bad("resourceType");
  if (e.resourceId !== null && !SUB.test(e.resourceId)) bad("resourceId");
  if (e.effect !== "allow" && e.effect !== "deny") bad("effect");
  if (!REASON.test(e.reasonCode)) bad("reasonCode");
  if (e.obligations.length > 8 || !e.obligations.every((o) => TAG.test(o))) bad("obligations");
  if (!REQ.test(e.requestId)) bad("requestId");
  if (e.source !== "api" && e.source !== "bff") bad("source");
  validateDetails(e.details);
}

/** The next row of the chain after `head`, signed with the current key. Pure. */
export function buildRow(entry: AuditEntry, head: Head, ring: AuditKeys, now: Date): AuditRow {
  validateEntry(entry);
  const base = {
    ...entry,
    actorRoles: [...entry.actorRoles],
    obligations: [...entry.obligations],
    details: { ...entry.details },
    id: head.lastId + 1,
    ts: new Date(Math.floor(now.getTime())), // millisecond precision on purpose: JavaScript and the canonical bytes agree exactly
    prevHash: head.lastHash,
    keyId: ring.currentId,
  };
  return { ...base, hash: mac(ring, ring.currentId, canonicalBytes(base)) };
}

/** The slice of a database client the chain needs. `pg.PoolClient` fits. */
export interface Db {
  query(text: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount?: number | null }>;
}

const LOCK_ID = 727_274_077; // fixed: every writer of every process serialises on the same chain
const READ_HEAD = "SELECT last_id, last_hash FROM audit_head WHERE singleton";
const INSERT =
  "INSERT INTO audit_log (id, ts, actor_sub, actor_roles, action, resource_type, resource_id, effect, reason_code, obligations, request_id, source, details, prev_hash, key_id, hash) " +
  "VALUES ($1, $2, $3, $4::text[], $5, $6, $7, $8, $9, $10::text[], $11, $12, $13::jsonb, $14, $15, $16)";

/**
 * Appends one row INSIDE the caller's open transaction (so a business transaction can include its own audit row).
 * 1. take the chain lock (transaction-scoped advisory lock, released at COMMIT/ROLLBACK), 2. read the head, 3. build and sign the next row, 4. insert.
 * The database independently refuses a row that does not extend the head (id = head + 1, prev_hash = head hash), so a writer that skips the lock fails loudly instead of forking.
 */
export async function appendAudit(db: Db, entry: AuditEntry, ring: AuditKeys, now = new Date()): Promise<AuditRow> {
  await db.query("SELECT pg_advisory_xact_lock($1)", [LOCK_ID]);
  const h = (await db.query(READ_HEAD)).rows[0];
  if (!h) throw new Error("audit head missing");
  const row = buildRow(entry, { lastId: Number(h.last_id), lastHash: h.last_hash as Buffer }, ring, now);
  await db.query(INSERT, [row.id, row.ts, row.actorSub, row.actorRoles, row.action, row.resourceType, row.resourceId, row.effect, row.reasonCode, row.obligations, row.requestId, row.source, JSON.stringify(row.details), row.prevHash, row.keyId, row.hash]);
  return row;
}

/** Row as returned by `SELECT * FROM audit_log` (node-postgres types) to the typed shape. */
export function rowFromDb(r: Record<string, unknown>): AuditRow {
  return {
    id: Number(r.id),
    ts: r.ts as Date,
    actorSub: r.actor_sub as string,
    actorRoles: r.actor_roles as string[],
    action: r.action as string,
    resourceType: r.resource_type as string,
    resourceId: (r.resource_id as string | null) ?? null,
    effect: r.effect as "allow" | "deny",
    reasonCode: r.reason_code as string,
    obligations: r.obligations as string[],
    requestId: r.request_id as string,
    source: r.source as "api" | "bff",
    details: r.details as Record<string, unknown>,
    prevHash: r.prev_hash as Buffer,
    keyId: r.key_id as string,
    hash: r.hash as Buffer,
  };
}
