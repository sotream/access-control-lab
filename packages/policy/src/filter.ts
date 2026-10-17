import { analyse } from "./evaluate.js";
import { ROLE_GRANTS } from "./matrix.js";
import { CLEARANCES, clearanceRank, type Environment, type Resource, type Role, type Subject } from "./model.js";

/**
 * The read decision expressed as plain attributes, so a data layer can express the same rule as a query
 * (stage 5: SQL / RLS parity) without importing the policy engine. Read has no unit or status condition,
 * so this is exactly equivalent to evaluate(read) without break-glass; a property test pins that.
 */
export interface ReadFilter {
  /** false: the subject may read nothing, the other fields are empty */
  readonly roleAllowed: boolean;
  /** classifications the subject may read right now (floor and step-up applied) */
  readonly classifications: readonly string[];
  /** a row is readable only if all its compartments are in this set */
  readonly compartmentsSubsetOf: readonly string[];
}

const NOTHING: ReadFilter = Object.freeze({ roleAllowed: false, classifications: Object.freeze([]), compartmentsSubsetOf: Object.freeze([]) });

export function readFilter(subject: Subject, env: Environment): ReadFilter {
  // reuse the evaluator's input validation through a probe: an invalid subject or environment yields INVALID_INPUT
  const probe = analyse(subject, "readAudit", null, env);
  if (probe.violations.includes("INVALID_INPUT")) return NOTHING;

  const roleAllowed = subject.roles.some((r) => Object.hasOwn(ROLE_GRANTS, r) && ROLE_GRANTS[r as Role].actions.includes("read"));
  if (!roleAllowed) return NOTHING;

  const mfa = env.acr === "mfa" && env.amr.includes("otp");
  const classifications = CLEARANCES.filter((c) => clearanceRank(c) <= clearanceRank(subject.clearance) && (c !== "SECRET" || mfa));
  return Object.freeze({
    roleAllowed: true,
    classifications: Object.freeze(classifications),
    compartmentsSubsetOf: Object.freeze([...new Set(subject.compartments)]),
  });
}

export function matchesReadFilter(f: ReadFilter, r: Pick<Resource, "classification" | "compartments">): boolean {
  return (
    f.roleAllowed &&
    f.classifications.includes(r.classification) &&
    Array.isArray(r.compartments) &&
    r.compartments.every((c) => f.compartmentsSubsetOf.includes(c))
  );
}
