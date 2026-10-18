import { ConflictException, ForbiddenException, HttpException, Inject, Injectable, NotFoundException, ServiceUnavailableException } from "@nestjs/common";
import { evaluate, readFilter, matchesReadFilter, type Action, type Decision, type Environment, type Subject } from "@acl/policy";
import type pg from "pg";
import { StepUpRequired } from "../http/errors.js";
import { type DbContext, type Tx, toDbContext, withContext } from "../db/context.js";
import { CaseFileRepository, type CaseFileRow, toResource, UUID } from "../db/case-file.repository.js";
import { sql } from "../db/sql.js";
import { JsonLogger } from "../http/logger.js";
import { refusalFor } from "../policy/refusal.js";
import { LOGGER } from "../policy/policy.enforcer.js";

export const DB_POOL = Symbol("DB_POOL");

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
  ) {}

  private ctx(c: Caller, action: Action): DbContext {
    return toDbContext(c.subject, c.env, action);
  }

  /** database refusals that survive the app-level decision are alerts: the two layers disagree */
  private async run<T>(c: Caller, action: Action, fn: (tx: Tx) => Promise<T>): Promise<T> {
    try {
      return await withContext(this.pool, this.ctx(c, action), fn);
    } catch (e) {
      if (e instanceof HttpException) throw e;
      const code = (e as { code?: string }).code;
      if (code === "42501") {
        this.logger.event("error", "db_denied_after_policy_allowed", { reqId: c.reqId, sub: c.subject.id, action });
        throw new ForbiddenException();
      }
      if (code === "55P03" || code === "40001" || code === "40P01") throw new ConflictException(); // lock timeout, serialization, deadlock: retry
      if (code === "57014") throw new ServiceUnavailableException(); // statement timeout
      throw e;
    }
  }

  /** visible for the advisory check in the route guard; read-only */
  async peek(c: Caller, id: string): Promise<{ row?: CaseFileRow; revealedByStepUp: boolean }> {
    return this.run(c, "read", async (tx) => {
      const row = await this.repo.get(tx, id);
      if (row) return { row, revealedByStepUp: false };
      return { revealedByStepUp: await this.stepUpWouldReveal(tx, c, id) };
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

  private log(c: Caller, action: Action, id: string | undefined, d: Decision | { effect: "deny"; reason: string; matchedRules: readonly string[]; obligations: readonly string[] }) {
    this.logger.event(d.effect === "allow" ? "info" : "warn", "decision", { reqId: c.reqId, sub: c.subject.id, action, resourceId: id, effect: d.effect, reason: d.reason, rules: d.matchedRules, obligations: d.obligations, authoritative: true });
  }

  /** load (locking for writes), decide, return the row the decision was made on */
  private async decide(tx: Tx, c: Caller, action: Action, id: string, lock: boolean): Promise<CaseFileRow> {
    let row = lock ? await this.repo.lock(tx, id) : await this.repo.get(tx, id);
    const locked = lock && row !== undefined;
    if (!row && lock) row = await this.repo.get(tx, id); // visible but not lockable: the UPDATE policy refuses it, the decision below will say why
    if (!row) {
      if (await this.stepUpWouldReveal(tx, c, id)) {
        this.log(c, action, id, { effect: "deny", reason: "STEP_UP_REQUIRED", matchedRules: ["abac.step-up"], obligations: ["step-up"] });
        throw new StepUpRequired("mfa");
      }
      this.log(c, action, id, { effect: "deny", reason: "RESOURCE_NOT_FOUND", matchedRules: ["resource.not-found"], obligations: [] });
      throw new NotFoundException();
    }
    const resource = toResource(row);
    const d = evaluate(c.subject, action, resource, c.env);
    this.log(c, action, id, d);
    if (d.effect === "deny") throw refusalFor(d, true, resource, c.subject, c.env);
    if (lock && !locked) {
      this.logger.event("error", "policy_allowed_but_row_not_lockable", { reqId: c.reqId, sub: c.subject.id, action, resourceId: id });
      throw new ForbiddenException();
    }
    return row;
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
    return this.run(c, "read", async (tx) => view(await this.decide(tx, c, "read", id, false), true));
  }

  export(c: Caller, id: string): Promise<CaseFileView> {
    return this.run(c, "export", async (tx) => view(await this.decide(tx, c, "export", id, false), true));
  }

  create(c: Caller, v: { title: string; body: string; classification: string; compartments: readonly string[] }): Promise<CaseFileView> {
    return this.run(c, "create", async (tx) => {
      const candidate = { classification: v.classification, ownerUnit: c.subject.unit, compartments: v.compartments, status: "draft", authorId: c.subject.id };
      const d = evaluate(c.subject, "create", candidate, c.env);
      this.log(c, "create", undefined, d);
      if (d.effect === "deny") throw refusalFor(d, false, undefined, c.subject, c.env);
      return view(await this.repo.insert(tx, { ...v, unit: c.subject.unit, authorId: c.subject.id }), true);
    });
  }

  update(c: Caller, id: string, v: { title?: string; body?: string; version: number }): Promise<CaseFileView> {
    return this.run(c, "update", async (tx) => {
      const row = await this.decide(tx, c, "update", id, true);
      if (row.version !== v.version) throw new ConflictException(); // somebody else changed it since the client read it
      const out = await this.repo.updateText(tx, id, v.title ?? row.title, v.body ?? row.body, row.version);
      if (!out) throw new ConflictException();
      return view(out, true);
    });
  }

  submit(c: Caller, id: string): Promise<CaseFileView> {
    return this.transition(c, "submit", id, "submitted");
  }

  approve(c: Caller, id: string): Promise<CaseFileView> {
    return this.transition(c, "approve", id, "approved");
  }

  private transition(c: Caller, action: "submit" | "approve", id: string, to: "submitted" | "approved"): Promise<CaseFileView> {
    return this.run(c, action, async (tx) => {
      const row = await this.decide(tx, c, action, id, true);
      const out = await this.repo.updateStatus(tx, id, to, row.version);
      if (!out) throw new ConflictException();
      return view(out, true);
    });
  }

  async remove(c: Caller, id: string): Promise<void> {
    await this.run(c, "delete", async (tx) => {
      const row = await this.decide(tx, c, "delete", id, true);
      if (!(await this.repo.delete(tx, id, row.version))) throw new ConflictException();
    });
  }
}
