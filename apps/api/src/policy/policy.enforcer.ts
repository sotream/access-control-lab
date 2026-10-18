import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import { ModuleRef } from "@nestjs/core";
import { evaluate, evaluateRole, type Decision, type Environment, type Resource, type Subject } from "@acl/policy";
import { CONFIG, type AppConfig } from "../config.js";
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

/** `::ffff:127.0.0.1` and `127.0.0.1` are the same client */
const normalize = (ip: string | undefined) => (ip ?? "").replace(/^::ffff:/, "");

@Injectable()
export class PolicyEnforcer {
  constructor(
    @Inject(ModuleRef) private readonly modules: ModuleRef,
    @Inject(CONFIG) private readonly cfg: AppConfig,
    @Inject(LOGGER) private readonly logger: JsonLogger,
    @Inject(CLOCK) private readonly clock: Clock,
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
        : { breakGlass: { justification: (Array.isArray(header) ? header.join(", ") : header).trim().slice(0, MAX_JUSTIFICATION) } }),
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
          this.log(req, p, access.action, undefined, "deny", "STEP_UP_REQUIRED", ["abac.step-up"], ["step-up"]);
          throw new StepUpRequired("mfa");
        }
        this.log(req, p, access.action, undefined, "deny", "RESOURCE_NOT_FOUND", ["resource.not-found"], []);
        throw new NotFoundException();
      }
      decision = evaluate(subject, access.action, resource, env);
    }

    this.log(req, p, access.action, resource?.id, decision.effect, decision.reason, decision.matchedRules, decision.obligations, env);
    if (decision.effect === "allow") return;

    // 404 vs 403: a subject who may not even read the resource is told it does not exist
    throw refusalFor(decision, existing, resource, subject, env);
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
