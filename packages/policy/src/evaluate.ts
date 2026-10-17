import { ALLOWED_STATUS, EXPORT_WINDOW_UTC, MANAGED_ZONE, RESOURCE_ACTIONS, ROLE_GRANTS, WRITE_ACTIONS, type RoleGrant } from "./matrix.js";
import {
  ACTIONS,
  STATUSES,
  clearanceRank,
  type Action,
  type Decision,
  type Environment,
  type Obligation,
  type ReasonCode,
  type Resource,
  type Role,
  type Subject,
} from "./model.js";

/**
 * Pure and deterministic: same inputs, same Decision. No I/O, no clock, no randomness, no mutation of inputs.
 * Default deny; every applicable rule is evaluated and any violation denies (deny overrides allow).
 */

/** Violation priority = order of this list. The first violated rule gives the reported reason. */
const PRIORITY: readonly ReasonCode[] = [
  "INVALID_INPUT",
  "ROLE_NOT_PERMITTED",
  "CLEARANCE_TOO_LOW",
  "COMPARTMENT_MISSING",
  "UNIT_MISMATCH",
  "NOT_OWNER",
  "STATUS_FORBIDS",
  "SEPARATION_OF_DUTIES",
  "STEP_UP_REQUIRED",
  "NETWORK_ZONE_FORBIDS",
  "OUTSIDE_EXPORT_WINDOW",
];

const RULE_ID: Partial<Record<ReasonCode, string>> = {
  INVALID_INPUT: "input.well-formed",
  ROLE_NOT_PERMITTED: "rbac.role-grants-action",
  CLEARANCE_TOO_LOW: "abac.clearance-floor",
  COMPARTMENT_MISSING: "abac.need-to-know",
  UNIT_MISMATCH: "abac.unit-scope",
  NOT_OWNER: "abac.ownership",
  STATUS_FORBIDS: "abac.status-machine",
  SEPARATION_OF_DUTIES: "abac.separation-of-duties",
  STEP_UP_REQUIRED: "abac.step-up",
  NETWORK_ZONE_FORBIDS: "abac.export-network-zone",
  OUTSIDE_EXPORT_WINDOW: "abac.export-window",
};

/** Violations break-glass may override: need-to-know only. Never the clearance floor, step-up, role or input checks. */
const BREAK_GLASS_OVERRIDES: readonly ReasonCode[] = ["COMPARTMENT_MISSING", "UNIT_MISMATCH"];

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const isStrArr = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");
const isAction = (v: unknown): v is Action => (ACTIONS as readonly string[]).includes(v as string);
const isRole = (v: string): v is Role => Object.hasOwn(ROLE_GRANTS, v);

function subjectValid(s: unknown): s is Subject {
  return (
    isObj(s) &&
    isStr(s.id) &&
    isStrArr(s.roles) &&
    clearanceRank(s.clearance) >= 0 &&
    isStr(s.unit) &&
    isStrArr(s.compartments)
  );
}

function envValid(e: unknown): e is Environment {
  return (
    isObj(e) &&
    typeof e.acr === "string" &&
    isStrArr(e.amr) &&
    typeof e.now === "number" &&
    Number.isFinite(e.now) &&
    typeof e.networkZone === "string" &&
    (e.breakGlass === undefined || (isObj(e.breakGlass) && typeof e.breakGlass.justification === "string"))
  );
}

function resourceValid(r: unknown): r is Resource {
  return (
    isObj(r) &&
    clearanceRank(r.classification) >= 0 &&
    isStr(r.ownerUnit) &&
    isStrArr(r.compartments) &&
    (STATUSES as readonly string[]).includes(r.status as string) &&
    isStr(r.authorId) &&
    (r.submittedById === undefined || r.submittedById === null || typeof r.submittedById === "string")
  );
}

export interface Analysis {
  /** violated rules, in priority order */
  violations: ReasonCode[];
  /** rules that applied and passed, plus role grants */
  passed: string[];
  grantingRoles: Role[];
}

const deny = (reason: ReasonCode, matchedRules: string[], obligations: Obligation[] = []): Decision =>
  Object.freeze({ effect: "deny", reason, obligations: Object.freeze(obligations), matchedRules: Object.freeze(matchedRules) });

const mfa = (env: Environment): boolean => env.acr === "mfa" && env.amr.includes("otp");

/** Rule by rule analysis without break-glass. Exported for the visibility helper; not part of the public API. */
export function analyse(subject: unknown, action: unknown, resource: unknown, env: unknown): Analysis {
  const invalid = (): Analysis => ({ violations: ["INVALID_INPUT"], passed: [], grantingRoles: [] });
  if (!isAction(action) || !subjectValid(subject) || !envValid(env)) return invalid();
  const needsResource = (RESOURCE_ACTIONS as readonly string[]).includes(action);
  if (needsResource && !resourceValid(resource)) return invalid();

  const violations = new Set<ReasonCode>();
  const passed: string[] = [];
  const check = (reason: ReasonCode, ok: boolean) => {
    if (ok) passed.push(RULE_ID[reason] as string);
    else violations.add(reason);
  };

  // RBAC. Unknown roles carry no grants. A subject with several roles gets the union.
  const grantingRoles = subject.roles.filter(isRole).filter((r) => ROLE_GRANTS[r].actions.includes(action));
  const granting: RoleGrant[] = [...new Set(grantingRoles)].map((r) => ROLE_GRANTS[r]);
  check("ROLE_NOT_PERMITTED", granting.length > 0);
  for (const r of new Set(grantingRoles)) passed.push(`rbac.grant:${r}`);

  if (needsResource) {
    const res = resource as Resource;
    check("CLEARANCE_TOO_LOW", clearanceRank(subject.clearance) >= clearanceRank(res.classification));
    check("COMPARTMENT_MISSING", res.compartments.every((c) => subject.compartments.includes(c)));
    if ((WRITE_ACTIONS as readonly string[]).includes(action)) {
      check("UNIT_MISMATCH", res.ownerUnit === subject.unit || granting.some((g) => g.crossUnit.includes(action)));
    }
    // a new file is always authored by its creator; otherwise ownership binds only if every role that grants
    // the action is own-only for it
    if (action === "create" || (granting.length > 0 && granting.every((g) => g.ownOnly.includes(action)))) {
      check("NOT_OWNER", res.authorId === subject.id);
    }
    check("STATUS_FORBIDS", (ALLOWED_STATUS[action] as readonly string[]).includes(res.status));
    if (action === "approve") {
      check("SEPARATION_OF_DUTIES", res.authorId !== subject.id && (res.submittedById ?? null) !== subject.id);
    }
    // any action on a SECRET file needs multi-factor authentication; the claim values come from the verified token
    if (res.classification === "SECRET") check("STEP_UP_REQUIRED", mfa(env));
    if (action === "export") {
      check("NETWORK_ZONE_FORBIDS", env.networkZone === MANAGED_ZONE);
      const hour = new Date(env.now * 1000).getUTCHours();
      check("OUTSIDE_EXPORT_WINDOW", hour >= EXPORT_WINDOW_UTC.startHour && hour < EXPORT_WINDOW_UTC.endHour);
    }
  }

  return { violations: PRIORITY.filter((p) => violations.has(p)), passed, grantingRoles: [...new Set(grantingRoles)] };
}

export function evaluate(subject: Subject, action: Action, resource: Resource | null, env: Environment): Decision {
  const a = analyse(subject, action, resource, env);
  // malformed input: nothing below may touch the (possibly garbage) arguments
  if (a.violations[0] === "INVALID_INPUT") return deny("INVALID_INPUT", ["input.well-formed"]);

  if (a.violations.length === 0) {
    // break-glass was asked for but not needed: still require a justification, it is an explicit request
    if (action === "read" && env.breakGlass !== undefined && env.breakGlass.justification.trim() === "") {
      return deny("BREAK_GLASS_JUSTIFICATION_REQUIRED", ["break-glass.justification"], ["require-justification"]);
    }
    return Object.freeze({
      effect: "allow",
      reason: "ALLOWED",
      obligations: Object.freeze<Obligation[]>(["audit"]),
      matchedRules: Object.freeze(a.passed),
    });
  }

  const reason = a.violations[0] as ReasonCode;
  const violated = a.violations.map((v) => RULE_ID[v] as string);
  const obligations: Obligation[] = reason === "STEP_UP_REQUIRED" ? ["step-up"] : [];

  // break-glass: explicit request, justification, a role that may use it, and only need-to-know violations
  if (action === "read" && env.breakGlass !== undefined && a.violations.every((v) => BREAK_GLASS_OVERRIDES.includes(v))) {
    if (env.breakGlass.justification.trim() === "") {
      return deny("BREAK_GLASS_JUSTIFICATION_REQUIRED", ["break-glass.justification"], ["require-justification"]);
    }
    const roles = (subject.roles as readonly string[]).filter(isRole);
    if (!roles.some((r) => ROLE_GRANTS[r].breakGlass && ROLE_GRANTS[r].actions.includes("read"))) {
      return deny("BREAK_GLASS_NOT_PERMITTED", ["break-glass.role", ...violated]);
    }
    return Object.freeze({
      effect: "allow",
      reason: "ALLOWED_BREAK_GLASS",
      obligations: Object.freeze<Obligation[]>(["audit", "alert"]),
      matchedRules: Object.freeze([...a.passed, "break-glass.override-need-to-know"]),
    });
  }

  return deny(reason, violated, obligations);
}
