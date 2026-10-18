import { Inject, Injectable } from "@nestjs/common";
import { appendAudit, sanitizeText, type AuditEntry, type AuditKeys } from "@acl/audit";
import type pg from "pg";
import { DB_POOL } from "../db/tokens.js";

export const AUDIT_WRITER = Symbol("AUDIT_WRITER");
export const AUDIT_KEYS = Symbol("AUDIT_KEYS");

/** The audit write failed. Callers of protected actions must treat it as "do not proceed". Carries no cause text on purpose. */
export class AuditUnavailable extends Error {
  constructor() {
    super("audit unavailable");
  }
}

export interface AuditWriter {
  append(entry: AuditEntry): Promise<void>;
}

/**
 * One row per call in its own short transaction: take the chain lock, read the head, insert the next signed row, commit.
 * Never nested inside another transaction of the same request (a second connection per request could exhaust the pool).
 */
@Injectable()
export class PgAuditWriter implements AuditWriter {
  constructor(
    @Inject(DB_POOL) private readonly pool: pg.Pool,
    @Inject(AUDIT_KEYS) private readonly keys: AuditKeys,
  ) {}

  async append(entry: AuditEntry): Promise<void> {
    let client: pg.PoolClient | undefined;
    try {
      client = await this.pool.connect();
      await client.query("BEGIN");
      await appendAudit(client, entry, this.keys);
      await client.query("COMMIT");
    } catch {
      await client?.query("ROLLBACK").catch(() => undefined);
      throw new AuditUnavailable();
    } finally {
      client?.release();
    }
  }
}

/** Used when no database is configured (unit tests of the HTTP layer). Keeps the entries so tests can look at them. */
@Injectable()
export class MemoryAuditWriter implements AuditWriter {
  readonly entries: AuditEntry[] = [];
  async append(entry: AuditEntry): Promise<void> {
    this.entries.push(entry);
  }
}

const TAG = /^[A-Za-z0-9_.:-]{1,64}$/;

/** Builds the entry for a policy decision. Free text is limited to the sanitised break-glass justification; no claims, no tokens. */
export function decisionEntry(a: {
  sub: string;
  roles: readonly string[];
  action: string;
  resourceId?: string | undefined;
  effect: "allow" | "deny";
  reason: string;
  rules: readonly string[];
  obligations: readonly string[];
  requestId: string;
  authoritative?: boolean;
  justification?: string | undefined;
  resourceType?: string;
}): AuditEntry {
  const justification = a.justification === undefined ? undefined : sanitizeText(a.justification);
  const alert = a.obligations.includes("alert");
  return {
    actorSub: a.sub,
    actorRoles: a.roles.slice(0, 16),
    action: a.action,
    resourceType: a.resourceType ?? "case_file",
    resourceId: a.resourceId ?? null,
    effect: a.effect,
    reasonCode: a.reason,
    obligations: a.obligations.slice(0, 8),
    requestId: a.requestId,
    source: "api",
    details: {
      rule_ids: a.rules.filter((r) => TAG.test(r)).slice(0, 20),
      ...(a.authoritative ? { authoritative: true } : {}),
      ...(justification !== undefined && (alert || a.reason.startsWith("BREAK_GLASS") || a.reason === "ALLOWED_BREAK_GLASS") ? { justification } : {}),
      ...(alert ? { alert: true } : {}),
    },
  };
}
