import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { fingerprint, makeCursor, openCursor, csvLine, rowFromDb, verifyChain, type AuditEntry, type AuditKeys, type AuditRow, type Checkpoint, type Head } from "@acl/audit";
import type pg from "pg";
import type { Caller } from "../casefiles/case-file.service.js";
import { toDbContext, withContext } from "../db/context.js";
import { sql } from "../db/sql.js";
import { DB_POOL } from "../db/tokens.js";
import { AUDIT_KEYS, AUDIT_WRITER, type AuditWriter } from "./audit.js";
import { CheckpointService } from "./checkpoint.js";
import { checkpointFromDb } from "./verify-db.js";

const PAGE = sql`SELECT id, ts, actor_sub, actor_roles, action, resource_type, resource_id, effect, reason_code, obligations, request_id, source, details, prev_hash, key_id, hash
  FROM audit_log
  WHERE id > $1 AND ($2::timestamptz IS NULL OR ts >= $2) AND ($3::timestamptz IS NULL OR ts <= $3)
    AND ($4::text IS NULL OR actor_sub = $4) AND ($5::text IS NULL OR resource_id = $5)
    AND ($6::text IS NULL OR action = $6) AND ($7::text IS NULL OR effect = $7)
  ORDER BY id LIMIT $8`;
const HEAD = sql`SELECT last_id, last_hash FROM audit_head WHERE singleton`;
const LATEST_CHECKPOINT = sql`SELECT id, ts, last_id, last_hash, key_id, mac FROM audit_checkpoints ORDER BY id DESC LIMIT 1`;
const CHECKPOINTS = sql`SELECT id, ts, last_id, last_hash, key_id, mac FROM audit_checkpoints ORDER BY id DESC LIMIT 100`;
const ALL_ROWS = sql`SELECT id, ts, actor_sub, actor_roles, action, resource_type, resource_id, effect, reason_code, obligations, request_id, source, details, prev_hash, key_id, hash
  FROM audit_log WHERE id > $1 ORDER BY id LIMIT $2`;

export interface Filters {
  from?: string;
  to?: string;
  actor?: string;
  resource?: string;
  action?: string;
  effect?: string;
}

export const MAX_PAGE = 500;
export const MAX_EXPORT = 2000;

const hex = (b: Buffer) => b.toString("hex");
const wire = (r: AuditRow) => ({
  id: r.id,
  ts: r.ts.toISOString(),
  actor_sub: r.actorSub,
  actor_roles: r.actorRoles,
  action: r.action,
  resource_type: r.resourceType,
  resource_id: r.resourceId,
  effect: r.effect,
  reason_code: r.reasonCode,
  obligations: r.obligations,
  request_id: r.requestId,
  source: r.source,
  details: r.details,
  prev_hash: hex(r.prevHash),
  key_id: r.keyId,
  hash: hex(r.hash),
});

const cpWire = (c: Checkpoint) => ({ id: c.id, ts: c.ts.toISOString(), last_id: c.lastId, last_hash: hex(c.lastHash), key_id: c.keyId, mac: hex(c.mac) });

export interface Proof {
  chain: "acl-audit/v1";
  algorithm: "HMAC-SHA256";
  rows: number;
  firstId: number | null;
  firstPrevHash: string | null;
  lastId: number | null;
  lastHash: string | null;
  head: { lastId: number; lastHash: string };
  checkpoint: ReturnType<typeof cpWire> | null;
  truncated: boolean;
}

const CSV_HEADER = ["id", "ts", "actor_sub", "actor_roles", "action", "resource_type", "resource_id", "effect", "reason_code", "obligations", "request_id", "source", "details", "prev_hash", "key_id", "hash"];

/** Auditor reads. Everything goes through the request context, so the database's row-level security applies (only a subject with readAudit sees rows). */
@Injectable()
export class AuditLogService {
  constructor(
    @Inject(DB_POOL) private readonly pool: pg.Pool,
    @Inject(AUDIT_KEYS) private readonly keys: AuditKeys,
    @Inject(AUDIT_WRITER) private readonly audit: AuditWriter,
    @Inject(CheckpointService) private readonly checkpoints: CheckpointService,
  ) {}

  private ctx(c: Caller) {
    return toDbContext(c.subject, c.env, "readAudit");
  }

  private params(f: Filters, after: number, limit: number) {
    return [after, f.from ?? null, f.to ?? null, f.actor ?? null, f.resource ?? null, f.action ?? null, f.effect ?? null, limit];
  }

  private after(cursor: string | undefined, f: Filters): number {
    if (cursor === undefined) return 0;
    const id = openCursor(this.keys, cursor, fingerprint({ ...f }));
    if (id === undefined) throw new BadRequestException(); // forged, truncated or from another query
    return id;
  }

  async page(c: Caller, f: Filters, cursor: string | undefined, limit: number) {
    const after = this.after(cursor, f);
    const rows = await withContext(this.pool, this.ctx(c), async (tx) => (await tx.query(PAGE, this.params(f, after, Math.min(limit, MAX_PAGE) + 1))).rows.map(rowFromDb));
    const more = rows.length > Math.min(limit, MAX_PAGE);
    const out = more ? rows.slice(0, -1) : rows;
    const last = out[out.length - 1];
    return { rows: out.map(wire), nextCursor: more && last ? makeCursor(this.keys, last.id, fingerprint({ ...f })) : null };
  }

  async checkpointList(c: Caller) {
    return withContext(this.pool, this.ctx(c), async (tx) => (await tx.query(CHECKPOINTS)).rows.map((r) => cpWire(checkpointFromDb(r))));
  }

  /** The export itself is audited BEFORE the data leaves (fail closed): count, format, filters, range. */
  async export(c: Caller, f: Filters, format: "ndjson" | "csv", cursor: string | undefined) {
    const after = this.after(cursor, f);
    await this.checkpoints.writeIfAdvanced().catch(() => undefined); // anchor the head this export proves against
    const { rows, head, checkpoint } = await withContext(this.pool, this.ctx(c), async (tx) => ({
      rows: (await tx.query(PAGE, this.params(f, after, MAX_EXPORT + 1))).rows.map(rowFromDb),
      head: (await tx.query(HEAD)).rows[0] as { last_id: string; last_hash: Buffer },
      checkpoint: (await tx.query(LATEST_CHECKPOINT)).rows[0] as Record<string, unknown> | undefined,
    }));
    const truncated = rows.length > MAX_EXPORT;
    const out = truncated ? rows.slice(0, -1) : rows;
    const first = out[0];
    const last = out[out.length - 1];

    const entry: AuditEntry = {
      actorSub: c.subject.id,
      actorRoles: c.subject.roles.slice(0, 16),
      action: "audit.export",
      resourceType: "audit_log",
      resourceId: null,
      effect: "allow",
      reasonCode: "EXPORTED",
      obligations: ["audit"],
      requestId: c.reqId,
      source: "api",
      details: { format, count: out.length, ...(first ? { from_id: first.id } : {}), ...(last ? { to_id: last.id } : {}), ...(truncated ? { truncated: true } : {}), filters: Object.fromEntries(Object.entries(f).filter(([, v]) => v !== undefined)) as Record<string, string> },
    };
    await this.audit.append(entry); // throws AuditUnavailable: no audit row, no export

    const proof: Proof = {
      chain: "acl-audit/v1",
      algorithm: "HMAC-SHA256",
      rows: out.length,
      firstId: first?.id ?? null,
      firstPrevHash: first ? hex(first.prevHash) : null,
      lastId: last?.id ?? null,
      lastHash: last ? hex(last.hash) : null,
      head: { lastId: Number(head.last_id), lastHash: hex(head.last_hash) },
      checkpoint: checkpoint ? cpWire(checkpointFromDb(checkpoint)) : null,
      truncated,
    };
    const nextCursor = truncated && last ? makeCursor(this.keys, last.id, fingerprint({ ...f })) : null;
    if (format === "ndjson") {
      return { contentType: "application/x-ndjson; charset=utf-8", body: [...out.map((r) => JSON.stringify(wire(r))), JSON.stringify({ proof, nextCursor })].join("\n") + "\n", proof, nextCursor };
    }
    const body = [csvLine(CSV_HEADER), ...out.map((r) => { const w = wire(r); return csvLine([w.id, w.ts, w.actor_sub, w.actor_roles, w.action, w.resource_type, w.resource_id, w.effect, w.reason_code, w.obligations, w.request_id, w.source, JSON.stringify(w.details), w.prev_hash, w.key_id, w.hash]); })].join("\r\n") + "\r\n";
    return { contentType: "text/csv; charset=utf-8", body, proof, nextCursor };
  }

  /** Recompute the whole chain with the caller's read access (an auditor sees every row). Bounded; the CLI is the tool for big chains. */
  async verify(c: Caller) {
    const { rows, head, cps } = await withContext(this.pool, this.ctx(c), async (tx) => {
      const all: AuditRow[] = [];
      let after = 0;
      for (let i = 0; i < 20; i++) {
        const r = (await tx.query(ALL_ROWS, [after, 1000])).rows.map(rowFromDb);
        all.push(...r);
        if (r.length < 1000) break;
        after = r[r.length - 1]!.id;
      }
      return { rows: all, head: (await tx.query(HEAD)).rows[0] as { last_id: string; last_hash: Buffer }, cps: (await tx.query(CHECKPOINTS)).rows.map(checkpointFromDb) };
    });
    const h: Head = { lastId: Number(head.last_id), lastHash: head.last_hash };
    const res = await verifyChain(rows, this.keys, { head: h, checkpoints: cps });
    return { ok: res.ok, checked: res.checked, lastId: res.lastId, issues: res.issues.slice(0, 20), partial: rows.length >= 20_000 };
  }
}
