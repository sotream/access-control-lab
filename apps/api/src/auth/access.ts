import { SetMetadata, type Type } from "@nestjs/common";
import type { Action, Resource } from "@acl/policy";
import type { AppRequest } from "../http/request.js";

export const ACCESS_KEY = "acl:access";

/** Loads the resource a policy decision is about. Registered as a provider; referenced by class in @Policy. */
export interface ResourceLoader {
  /** true: the resource already exists, so a refusal must not reveal it (404 vs 403, see docs/policy.md) */
  readonly existing: boolean;
  /** `undefined`: no such resource. Input from the request is untrusted; validate before querying. */
  load(req: AppRequest): Promise<Resource | undefined>;
}

/** `null`: no resource (lists, audit, user management); only the role is checked, the handler must filter rows. */
export type ResourceSource = Type<ResourceLoader> | null;

/** Declared access of a route. A route with none of these is denied. */
export type Access =
  | { kind: "public" }
  | { kind: "authenticated" }
  | { kind: "policy"; action: Action; resource: ResourceSource };

/** No authentication. Allowed for /health only; a test pins that list. */
export const Public = () => SetMetadata(ACCESS_KEY, { kind: "public" } satisfies Access);

/** Valid access token required, no further decision (identity-only routes). */
export const Authenticated = () => SetMetadata(ACCESS_KEY, { kind: "authenticated" } satisfies Access);

/** Actions that may be declared without a resource: lists (`read`), audit and user management. Everything else needs a loader. */
const ROLE_ONLY_ACTIONS: readonly Action[] = ["read", "readAudit", "manageUsers"];

/**
 * Authorization by the policy engine: RBAC, then ABAC against the loaded resource. Default deny.
 * `resource: null` checks the role only, so it is refused at declaration time for actions that change or export a case file.
 */
export const Policy = (o: { action: Action; resource: ResourceSource }) => {
  if (o.resource === null && !ROLE_ONLY_ACTIONS.includes(o.action)) {
    throw new Error(`@Policy({ action: "${o.action}", resource: null }) would skip every per-resource rule; provide a ResourceLoader`);
  }
  return SetMetadata(ACCESS_KEY, { kind: "policy", ...o } satisfies Access);
};
