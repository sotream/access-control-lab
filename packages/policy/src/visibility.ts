import { analyse } from "./evaluate.js";
import type { Environment, Resource, Subject } from "./model.js";

/**
 * May this subject know the resource exists? Hidden unless the read check fails at most on step-up
 * (a cleared user learns the file exists and is told to authenticate more strongly). Used to answer 404
 * instead of 403 so a refusal does not confirm that an id exists. Break-glass is ignored on purpose.
 */
export function visibility(subject: Subject, resource: Resource, env: Environment): "visible" | "hidden" {
  const a = analyse(subject, "read", resource, env);
  return a.violations.every((v) => v === "STEP_UP_REQUIRED") ? "visible" : "hidden";
}
