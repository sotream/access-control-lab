import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import { ModuleRef } from "@nestjs/core";
import { evaluate, evaluateRole, type Decision, type Environment, type Resource, type Subject } from "@acl/policy";
import { CONFIG, type AppConfig } from "../config.js";
import { ServiceUnavailableException } from "@nestjs/common";
import { sanitizeText } from "@acl/audit";
import { AUDIT_WRITER, decisionEntry, type AuditWriter } from "../audit/audit.js";
import { StepUpRequired } from "../http/errors.js";
import { refusalFor } from "./refusal.js";
import { JsonLogger } from "../http/logger.js";
import type { AppRequest } from "../http/request.js";
import type { Access, ResourceLoader } from "../auth/access.js";
import type { Principal } from "../auth/principal.js";

export const LOGGER = Symbol("LOGGER");
export const CLOCK = Symbol("CLOCK");
export type Clock = () => number; // epoch milliseconds

const BREAK_GLASS_HEADER = "x-break-glass-justification";
const MAX_JUSTIFICATION = 500;

export const toSubject = (p: Principal): Subject => ({
  id: p.sub,
  roles: p.roles,
  clearance: p.clearance,
  unit: p.unit,
  compartments: p.compartments,
});

/** the id the client asked for, if it is shaped like an id (audit rows only hold such values; hostile strings are dropped, not stored) */
const requestedId = (req: AppRequest): string | undefined => {
  const id = (req.params as Record<string, unknown> | undefined)?.id;
  return typeof id === "string" && /^[A-Za-z0-9_.:-]{1,128}$/.test(id) ? id : undefined;
};

/** `::ffff:127.0.0.1` and `127.0.0.1` are the same client */
const normalize = (ip: string | undefined) => (ip ?? "").replace(/^::ffff:/, "");

@Injectable()
export class PolicyEnforcer {
  constructor(
    @Inject(ModuleRef) private readonly modules: ModuleRef,
    @Inject(CONFIG) private readonly cfg: AppConfig,
    @Inject(LOGGER) private readonly logger: JsonLogger,
    @Inject(CLOCK) private readonly clock: Clock,
    @Inject(AUDIT_WRITER) private readonly audit: AuditWriter,
  ) {}

  /** Everything the policy needs besides subject and resource. Built here from the request and the verified token, never from client claims. */
  environment(req: AppRequest, p: Principal): Environment {
    const header = req.headers[BREAK_GLASS_HEADER];
    return {
      acr: p.acr,
      amr: p.amr,
      now: Math.floor(this.clock() / 1000),
      networkZone: this.cfg.managedAddresses.includes(normalize(req.ip)) ? "managed" : "unmanaged",
      ...(header === undefined
        ? {}
        : // control and bidi characters become spaces, whitespace collapses: the cleaned text is what the policy, the database context and the audit row all see.
          // A header that is empty after cleaning stays an (empty) request, which the policy refuses.
          { breakGlass: { justification: sanitizeText(Array.isArray(header) ? header.join(", ") : header, MAX_JUSTIFICATION) ?? "" } }),
    };
  }

  /** Throws the HTTP refusal, or returns when the decision is allow. Always writes the decision log. */
  async enforce(req: AppRequest, access: Extract<Access, { kind: "policy" }>, p: Principal): Promise<void> {
    const subject = toSubject(p);
    const env = this.environment(req, p);
    req.policyContext = { subject, env };

    let resource: Resource | undefined;
    let existing = false;
    let decision: Decision;

    if (access.resource === null) {
      decision = evaluateRole(subject, access.action);
    } else {
      const loader = this.modules.get<ResourceLoader>(access.resource, { strict: false });
      existing = loader.existing;
      resource = await loader.load(req);
      if (resource === undefined) {
        // same refusal as a hidden resource: nonexistent and forbidden are indistinguishable to the client
        // unless the only thing in the way is MFA for a file this subject is cleared for (the loader can tell)
        if (loader.revealedByStepUp && (await loader.revealedByStepUp(req))) {
          await this.record(req, p, access.action, requestedId(req), "deny", "STEP_UP_REQUIRED", ["abac.step-up"], ["step-up"]);
          throw new StepUpRequired("mfa");
        }
        // the client gets 404 either way; the audit log gets the real reason when the loader can tell (clearance, compartment, role)
        const why = (loader.hiddenReason && (await loader.hiddenReason(req))) || "RESOURCE_NOT_FOUND";
        await this.record(req, p, access.action, requestedId(req), "deny", why, [why === "RESOURCE_NOT_FOUND" ? "resource.not-found" : "rls.hidden"], []);
        throw new NotFoundException();
      }
      decision = evaluate(subject, access.action, resource, env);
    }

    await this.record(req, p, access.action, resource?.id, decision.effect, decision.reason, decision.matchedRules, decision.obligations, env);
    if (decision.effect === "allow") return;

    // 404 vs 403: a subject who may not even read the resource is told it does not exist
    throw refusalFor(decision, existing, resource, subject, env);
  }

  /**
   * stdout log line plus the audit row. An ALLOW without its audit row is not allowed to proceed (no audit, no action): 503.
   * A DENY is refused either way, so a failed audit write is only logged.
   */
  private async record(req: AppRequest, p: Principal, action: string, resourceId: string | undefined, effect: "allow" | "deny", reason: string, rules: readonly string[], obligations: readonly string[], env?: Environment): Promise<void> {
    this.log(req, p, action, resourceId, effect, reason, rules, obligations, env);
    try {
      await this.audit.append(decisionEntry({ sub: p.sub, roles: p.roles, action, resourceId, effect, reason, rules, obligations, requestId: req.id, justification: env?.breakGlass?.justification }));
    } catch {
      this.logger.event("error", "audit_write_failed", { reqId: req.id, sub: p.sub, action, effect });
      if (effect === "allow") throw new ServiceUnavailableException();
    }
  }

  private log(
    req: AppRequest,
    p: Principal,
    action: string,
    resourceId: string | undefined,
    effect: "allow" | "deny",
    reason: string,
    rules: readonly string[],
    obligations: readonly string[],
    env?: Environment,
  ): void {
    const base = { reqId: req.id, sub: p.sub, action, resourceId, effect, reason, rules, obligations };
    this.logger.event(effect === "allow" ? "info" : "warn", "decision", base);
    if (obligations.includes("alert")) {
      // break-glass: a human reads this. The justification is audit content, not a secret.
      this.logger.event("warn", "break_glass_alert", { ...base, justification: env?.breakGlass?.justification });
    }
  }
}
