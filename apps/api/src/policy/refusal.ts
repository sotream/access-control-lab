import { ForbiddenException, HttpException, NotFoundException } from "@nestjs/common";
import { visibility, type Decision, type Environment, type Resource, type Subject } from "@acl/policy";
import { StepUpRequired } from "../http/errors.js";

/**
 * The HTTP refusal for a denied decision (ADR-9). A resource the subject may not read is "not found"; a cleared user who
 * only lacks MFA gets the step-up challenge; everything else is a plain 403 without a reason.
 */
export function refusalFor(decision: Decision, existing: boolean, resource: Resource | undefined, subject: Subject, env: Environment): HttpException {
  if (existing && resource && visibility(subject, resource, env) === "hidden") return new NotFoundException();
  if (decision.reason === "STEP_UP_REQUIRED") return new StepUpRequired("mfa");
  return new ForbiddenException();
}
