import { canonicalBytes, checkpointBytes } from "./canonical.js";
import { validateDetails } from "./details.js";
import { mac, macEquals, type AuditKeys } from "./keys.js";
import { GENESIS_HASH_HEX, type AuditRow, type Checkpoint, type Head } from "./model.js";

export type IssueCode =
  | "GAP"
  | "FORK"
  | "REORDER"
  | "PREV_HASH"
  | "HASH"
  | "KEY_UNKNOWN"
  | "SCHEMA"
  | "HEAD_MISMATCH"
  | "TAIL_TRUNCATED"
  | "CHECKPOINT_MAC"
  | "CHECKPOINT_MISMATCH";

export interface Issue {
  code: IssueCode;
  /** row id the problem is at (or the checkpoint's last id); null when it concerns the whole chain */
  id: number | null;
  message: string;
}

export interface VerifyResult {
  ok: boolean;
  checked: number;
  /** the first problem in chain order */
  firstBad?: Issue;
  issues: Issue[];
  lastId: number;
  lastHash: string;
}

export interface VerifyOptions {
  /** verify a range: the trusted row before the first one (id and hash, e.g. from a checkpoint). Default: genesis. */
  startAfter?: { id: number; hash: Buffer };
  /** stop after this id (range verification; head and tail checks are skipped) */
  toId?: number;
  /** the current head from the database: the last row must equal it */
  head?: Head;
  /** checkpoints from the database and/or an external copy */
  checkpoints?: readonly Checkpoint[];
}

export function verifyCheckpointMac(c: Checkpoint, ring: AuditKeys): boolean {
  if (!ring.keys.has(c.keyId)) return false;
  return macEquals(mac(ring, c.keyId, checkpointBytes(c)), c.mac);
}

/**
 * Recomputes the chain from the rows in order. Detects: edited fields (hash), edited hash or forged rows (HMAC with a key outside the database),
 * a deleted middle row (gap), a forked or duplicated id, reordered rows, a wrong or unknown key id, a malformed details object, a head that does not match
 * the last row, and (with checkpoints) a deleted tail. Keeps going after a problem so every issue is reported; `firstBad` is the earliest.
 */
export async function verifyChain(rows: AsyncIterable<AuditRow> | Iterable<AuditRow>, ring: AuditKeys, opts: VerifyOptions = {}): Promise<VerifyResult> {
  const issues: Issue[] = [];
  const add = (code: IssueCode, id: number | null, message: string) => issues.push({ code, id, message });

  let prevId = opts.startAfter?.id ?? 0;
  let prevHash = opts.startAfter?.hash ?? Buffer.from(GENESIS_HASH_HEX, "hex");
  const full = opts.startAfter === undefined && opts.toId === undefined;
  const wanted = new Map<number, Buffer>();
  for (const c of opts.checkpoints ?? []) wanted.set(c.lastId, c.lastHash);
  const seen = new Map<number, Buffer>();
  let checked = 0;

  for await (const r of rows) {
    if (opts.toId !== undefined && r.id > opts.toId) break;
    checked++;
    if (r.id === prevId && checked > 1) add("FORK", r.id, `two rows with id ${r.id}`);
    else if (r.id < prevId) add("REORDER", r.id, `row ${r.id} after row ${prevId}`);
    else if (r.id > prevId + 1) add("GAP", r.id, `rows ${prevId + 1}..${r.id - 1} are missing`);

    if (!macEquals(r.prevHash, prevHash)) add("PREV_HASH", r.id, `prev_hash of row ${r.id} does not match the hash of the row before it`);
    try {
      validateDetails(r.details);
    } catch (e) {
      add("SCHEMA", r.id, `row ${r.id}: ${(e as Error).message}`);
    }
    if (!ring.keys.has(r.keyId)) add("KEY_UNKNOWN", r.id, `row ${r.id} names key ${r.keyId}, which is not in the key ring`);
    else {
      const { hash: _stored, ...rest } = r;
      void _stored;
      if (!macEquals(mac(ring, r.keyId, canonicalBytes(rest)), r.hash)) add("HASH", r.id, `row ${r.id} does not match its hash (edited, or signed with another key)`);
    }
    if (wanted.has(r.id)) seen.set(r.id, r.hash);
    prevId = r.id;
    prevHash = r.hash; // continue from what is stored so later rows are judged on their own
  }

  if (full && opts.head) {
    if (opts.head.lastId !== prevId || !macEquals(opts.head.lastHash, prevHash)) add("HEAD_MISMATCH", prevId, `the head says ${opts.head.lastId}, the last row is ${prevId}: rows were removed or the head was edited`);
  }
  for (const c of opts.checkpoints ?? []) {
    if (!verifyCheckpointMac(c, ring)) {
      add("CHECKPOINT_MAC", c.lastId, `checkpoint for ${c.lastId} has an invalid signature`);
      continue;
    }
    if (full && c.lastId > prevId) add("TAIL_TRUNCATED", c.lastId, `a checkpoint covers row ${c.lastId} but the chain ends at ${prevId}`);
    else if (seen.has(c.lastId) && !macEquals(seen.get(c.lastId) as Buffer, c.lastHash)) add("CHECKPOINT_MISMATCH", c.lastId, `row ${c.lastId} differs from the hash a checkpoint recorded`);
    else if (!seen.has(c.lastId) && c.lastId <= prevId && c.lastId > (opts.startAfter?.id ?? 0) && (opts.toId === undefined || c.lastId <= opts.toId)) add("CHECKPOINT_MISMATCH", c.lastId, `a checkpoint covers row ${c.lastId} which is not in the chain`);
  }

  issues.sort((a, b) => (a.id ?? Number.MAX_SAFE_INTEGER) - (b.id ?? Number.MAX_SAFE_INTEGER));
  return { ok: issues.length === 0, checked, ...(issues[0] ? { firstBad: issues[0] } : {}), issues, lastId: prevId, lastHash: prevHash.toString("hex") };
}

/** Builds a signed checkpoint of the head. */
export function makeCheckpoint(head: Head, ring: AuditKeys, now = new Date()): Checkpoint {
  const base = { ts: new Date(Math.floor(now.getTime())), lastId: head.lastId, lastHash: head.lastHash, keyId: ring.currentId };
  return { ...base, mac: mac(ring, ring.currentId, checkpointBytes(base)) };
}
