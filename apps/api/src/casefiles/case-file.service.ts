import { ConflictException, ForbiddenException, HttpException, Inject, Injectable, NotFoundException, ServiceUnavailableException } from "@nestjs/common";
import { evaluate, readFilter, matchesReadFilter, type Action, type Decision, type Environment, type Subject } from "@acl/policy";
import type pg from "pg";
import { AUDIT_WRITER, decisionEntry, type AuditWriter } from "../audit/audit.js";
import type { AuditEntry } from "@acl/audit";
import { StepUpRequired } from "../http/errors.js";
import { type DbContext, type Tx, toDbContext, withContext } from "../db/context.js";
import { CaseFileRepository, type CaseFileRow, toResource, UUID } from "../db/case-file.repository.js";
import { sql } from "../db/sql.js";
import { DB_POOL } from "../db/tokens.js";
import { JsonLogger } from "../http/logger.js";
import { refusalFor } from "../policy/refusal.js";
import { LOGGER } from "../policy/policy.enforcer.js";


export interface Caller {
  subject: Subject;
  env: Environment;
  reqId: string;
}

export interface CaseFileView {
  id: string;
  title: string;
  body?: string;
  classification: string;
  unit: string;
  compartments: string[];
  status: string;
  authorId: string;
  version: number;
  createdAt: string;
  updatedAt: string;
}

const view = (r: CaseFileRow, withBody: boolean): CaseFileView => ({
  id: r.id,
  title: r.title,
  ...(withBody ? { body: r.body } : {}),
  classification: r.classification,
  unit: r.unit,
  compartments: r.compartments,
  status: r.status,
  authorId: r.authorId,
  version: r.version,
  createdAt: r.createdAt.toISOString(),
  updatedAt: r.updatedAt.toISOString(),
});

const MFA_PROBE = sql`SELECT set_config('app.acr', 'mfa', true), set_config('app.amr', 'pwd,otp', true), set_config('app.break_glass', 'off', true)`;
const EXISTS_ONE = sql`SELECT 1 AS one FROM case_files WHERE id = $1`;
const DENIAL_REASON = sql`SELECT audit_read_denial_reason($1) AS reason`;
const SAVEPOINT = sql`SAVEPOINT stepup_probe`;
const ROLLBACK_TO = sql`ROLLBACK TO SAVEPOINT stepup_probe`;

const hasMfa = (e: Environment) => e.acr === "mfa" && e.amr.includes("otp");

/**
 * Case-file use cases. Every operation is ONE transaction: set the request context, load (with a row lock for writes),
 * decide with packages/policy on the locked row, write. Postgres row-level security and the guard trigger then check the
 * same rules again independently (defence in depth). The decision made by the route guard is advisory; this one is authoritative.
 */
@Injectable()
export class CaseFileService {
  constructor(
    @Inject(DB_POOL) private readonly pool: pg.Pool,
    @Inject(CaseFileRepository) private readonly repo: CaseFileRepository,
    @Inject(LOGGER) private readonly logger: JsonLogger,
    @Inject(AUDIT_WRITER) private readonly audit: AuditWriter,
  ) {}

  private ctx(c: Caller, action: Action): DbContext {
    return toDbContext(c.subject, c.env, action);
  }

  /** database refusals that survive the app-level decision are alerts: the two layers disagree */
  private async run<T>(c: Caller, action: Action, fn: (tx: Tx) => Promise<T>, audits: AuditEntry[] = []): Promise<T> {
    try {
      return await withContext(this.pool, this.ctx(c, action), fn);
    } catch (e) {
      // refusals decided inside the transaction are audited AFTER it has ended (a row written inside would roll back with it,
      // and a second connection per request could exhaust the pool). The route guard has already audited the ALLOW it let through.
      for (const entry of audits) {
        try {
          await this.audit.append(entry);
        } catch {
          this.logger.event("error", "audit_write_failed", { reqId: c.reqId, sub: c.subject.id, action, effect: "deny" });
        }
      }
      if (e instanceof HttpException) throw e;
      const code = (e as { code?: string }).code;
      if (code === "42501") {
        this.logger.event("error", "db_denied_after_policy_allowed", { reqId: c.reqId, sub: c.subject.id, action });
        throw new ForbiddenException();
      }
      if (code === "23503") throw new ConflictException(); // a draft that still has attachments cannot be deleted
      if (code === "55P03" || code === "40001" || code === "40P01") throw new ConflictException(); // lock timeout, serialization, deadlock: retry
      if (code === "57014") throw new ServiceUnavailableException(); // statement timeout
      throw e;
    }
  }

  /** Why a file the caller cannot read was hidden: the policy's own reason code, from the database. For the AUDIT LOG only; the client sees 404. */
  private async denialReason(tx: Tx, id: string): Promise<string> {
    if (!UUID.test(id)) return "RESOURCE_NOT_FOUND";
    const r = (await tx.query<{ reason: string }>(DENIAL_REASON, [id])).rows[0]?.reason;
    return r && /^[A-Z_]{1,40}$/.test(r) ? r : "RESOURCE_NOT_FOUND";
  }

  /** visible for the advisory check in the route guard; read-only */
  async peek(c: Caller, id: string): Promise<{ row?: CaseFileRow; revealedByStepUp: boolean; denialReason?: string }> {
    return this.run(c, "read", async (tx) => {
      const row = await this.repo.get(tx, id);
      if (row) return { row, revealedByStepUp: false };
      const denialReason = await this.denialReason(tx, id);
      return { revealedByStepUp: await this.stepUpWouldReveal(tx, c, id), denialReason };
    });
  }

  /** Savepoint, pretend MFA, look, roll back: the context returns to what it was. Reveals only a boolean, never data. */
  private async stepUpWouldReveal(tx: Tx, c: Caller, id: string): Promise<boolean> {
    if (hasMfa(c.env) || !UUID.test(id)) return false;
    await tx.query(SAVEPOINT);
    try {
      await tx.query(MFA_PROBE);
      return ((await tx.query(EXISTS_ONE, [id])).rowCount ?? 0) > 0;
    } finally {
      await tx.query(ROLLBACK_TO);
    }
  }

  private log(c: Caller, action: Action, id: string | undefined, d: Decision | { effect: "deny"; reason: string; matchedRules: readonly string[]; obligations: readonly string[] }, audits?: AuditEntry[]) {
    if (d.effect === "deny" && audits) audits.push(decisionEntry({ sub: c.subject.id, roles: c.subject.roles, action, resourceId: id, effect: "deny", reason: d.reason, rules: d.matchedRules, obligations: d.obligations, requestId: c.reqId, authoritative: true }));
    this.logger.event(d.effect === "allow" ? "info" : "warn", "decision", { reqId: c.reqId, sub: c.subject.id, action, resourceId: id, effect: d.effect, reason: d.reason, rules: d.matchedRules, obligations: d.obligations, authoritative: true });
  }

  /** load (locking for writes), decide, return the row the decision was made on */
  private async decide(tx: Tx, c: Caller, action: Action, id: string, lock: boolean, audits: AuditEntry[]): Promise<CaseFileRow> {
    let row = lock ? await this.repo.lock(tx, id) : await this.repo.get(tx, id);
    const locked = lock && row !== undefined;
    if (!row && lock) row = await this.repo.get(tx, id); // visible but not lockable: the UPDATE policy refuses it, the decision below will say why
    if (!row) {
      if (await this.stepUpWouldReveal(tx, c, id)) {
        this.log(c, action, id, { effect: "deny", reason: "STEP_UP_REQUIRED", matchedRules: ["abac.step-up"], obligations: ["step-up"] }, audits);
        throw new StepUpRequired("mfa");
      }
      // the client gets 404 either way; the audit log gets the real reason (clearance, compartment, role, or really not found)
      const why = await this.denialReason(tx, id);
      this.log(c, action, id, { effect: "deny", reason: why, matchedRules: [why === "RESOURCE_NOT_FOUND" ? "resource.not-found" : "rls.hidden"], obligations: [] }, audits);
      throw new NotFoundException();
    }
    const resource = toResource(row);
    const d = evaluate(c.subject, action, resource, c.env);
    this.log(c, action, id, d, audits);
    if (d.effect === "deny") throw refusalFor(d, true, resource, c.subject, c.env);
    if (lock && !locked) {
      this.logger.event("error", "policy_allowed_but_row_not_lockable", { reqId: c.reqId, sub: c.subject.id, action, resourceId: id });
      throw new ForbiddenException();
    }
    return row;
  }

  /**
   * For features that hang off a case file (attachments): one transaction with the request context, the authoritative decision on the
   * (locked, for writes) parent row, then `fn`. Refusals are audited like every other decision of this service.
   */
  guarded<T>(c: Caller, action: "read" | "update", id: string, fn: (tx: Tx, parent: CaseFileRow) => Promise<T>): Promise<T> {
    const audits: AuditEntry[] = [];
    return this.run(c, action, async (tx) => fn(tx, await this.decide(tx, c, action, id, action === "update", audits)), audits);
  }

  list(c: Caller): Promise<CaseFileView[]> {
    return this.run(c, "read", async (tx) => {
      const rows = await this.repo.list(tx, 200);
      // belt and braces: the same read rule applied in the app. Row-level security should already have removed these.
      const f = readFilter(c.subject, c.env);
      const ok = rows.filter((r) => matchesReadFilter(f, { classification: r.classification, compartments: r.compartments }));
      if (ok.length !== rows.length) {
        this.logger.event("error", "rls_returned_rows_policy_denies", { reqId: c.reqId, sub: c.subject.id, extra: rows.length - ok.length });
      }
      return ok.map((r) => view(r, false));
    });
  }

  read(c: Caller, id: string): Promise<CaseFileView> {
    const audits: AuditEntry[] = [];
    return this.run(c, "read", async (tx) => view(await this.decide(tx, c, "read", id, false, audits), true), audits);
  }

  export(c: Caller, id: string): Promise<CaseFileView> {
    const audits: AuditEntry[] = [];
    return this.run(c, "export", async (tx) => view(await this.decide(tx, c, "export", id, false, audits), true), audits);
  }

  create(c: Caller, v: { title: string; body: string; classification: string; compartments: readonly string[] }): Promise<CaseFileView> {
    const audits: AuditEntry[] = [];
    return this.run(c, "create", async (tx) => {
      const candidate = { classification: v.classification, ownerUnit: c.subject.unit, compartments: v.compartments, status: "draft", authorId: c.subject.id };
      const d = evaluate(c.subject, "create", candidate, c.env);
      this.log(c, "create", undefined, d, audits);
      if (d.effect === "deny") throw refusalFor(d, false, undefined, c.subject, c.env);
      return view(await this.repo.insert(tx, { ...v, unit: c.subject.unit, authorId: c.subject.id }), true);
    }, audits);
  }

  update(c: Caller, id: string, v: { title?: string; body?: string; version: number }): Promise<CaseFileView> {
    const audits: AuditEntry[] = [];
    return this.run(c, "update", async (tx) => {
      const row = await this.decide(tx, c, "update", id, true, audits);
      if (row.version !== v.version) throw new ConflictException(); // somebody else changed it since the client read it
      const out = await this.repo.updateText(tx, id, v.title ?? row.title, v.body ?? row.body, row.version);
      if (!out) throw new ConflictException();
      return view(out, true);
    }, audits);
  }

  submit(c: Caller, id: string): Promise<CaseFileView> {
    return this.transition(c, "submit", id, "submitted");
  }

  approve(c: Caller, id: string): Promise<CaseFileView> {
    return this.transition(c, "approve", id, "approved");
  }

  private transition(c: Caller, action: "submit" | "approve", id: string, to: "submitted" | "approved"): Promise<CaseFileView> {
    const audits: AuditEntry[] = [];
    return this.run(c, action, async (tx) => {
      const row = await this.decide(tx, c, action, id, true, audits);
      const out = await this.repo.updateStatus(tx, id, to, row.version);
      if (!out) throw new ConflictException();
      return view(out, true);
    }, audits);
  }

  async remove(c: Caller, id: string): Promise<void> {
    const audits: AuditEntry[] = [];
    await this.run(c, "delete", async (tx) => {
      const row = await this.decide(tx, c, "delete", id, true, audits);
      if (!(await this.repo.delete(tx, id, row.version))) throw new ConflictException();
    }, audits);
  }
}
