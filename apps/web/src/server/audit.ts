import { randomUUID } from "node:crypto";
import { appendAudit, parseAuditKeys, type AuditEntry } from "@acl/audit";
import { config } from "./config";
import { webPool } from "./db";

export class AuditUnavailable extends Error {
  constructor() {
    super("audit unavailable");
  }
}

export interface AuthEvent {
  /** e.g. auth.login, auth.login_failed, auth.logout, auth.session_killed, auth.stepup, auth.csrf_denied */
  action: string;
  actorSub?: string | undefined;
  effect: "allow" | "deny";
  reason: string;
  details?: Record<string, unknown>;
  requestId?: string;
}

/**
 * Appends one authentication event to the audit chain (source "bff"), in its own short transaction.
 * `strict`: a failure throws AuditUnavailable (used for sign-in: no audit, no session). Otherwise the failure is logged and swallowed
 * (used where refusing would REDUCE security: sign-out, killing a session, recording a refusal).
 * Nothing but the fixed event fields goes in: no cookie, token, state, nonce, code, URL or header.
 */
export async function auditAuth(e: AuthEvent, strict = false): Promise<void> {
  const entry: AuditEntry = {
    actorSub: e.actorSub ?? "anonymous",
    actorRoles: [],
    action: e.action,
    resourceType: "session",
    resourceId: null,
    effect: e.effect,
    reasonCode: e.reason,
    obligations: e.effect === "allow" ? ["audit"] : [],
    requestId: e.requestId ?? randomUUID(),
    source: "bff",
    details: e.details ?? {},
  };
  const pool = webPool();
  const client = await pool.connect().catch(() => undefined);
  try {
    if (!client) throw new Error("no connection");
    await client.query("BEGIN");
    await appendAudit(client, entry, parseAuditKeys(config().auditKeys));
    await client.query("COMMIT");
  } catch {
    await client?.query("ROLLBACK").catch(() => undefined);
    console.error(JSON.stringify({ level: "error", msg: "audit_write_failed", action: e.action, effect: e.effect }));
    if (strict) throw new AuditUnavailable();
  } finally {
    client?.release();
  }
}
