// Vocabulary and shapes shared by the API, the tests and (later) the SQL layer. Single source of truth.
// Inputs are deliberately loose (`string`, not the enums): data from tokens or the database can drift,
// and the evaluator must deny on what it does not recognise instead of failing to compile it away.

/** Ordered, lowest first. The index is the rank. */
export const CLEARANCES = ["OFFICIAL", "CONFIDENTIAL", "SECRET"] as const;
export type Clearance = (typeof CLEARANCES)[number];

export const ROLES = ["analyst", "reviewer", "unit-admin", "auditor", "platform-admin"] as const;
export type Role = (typeof ROLES)[number];

export const ACTIONS = [
  "create",
  "read",
  "update",
  "submit",
  "approve",
  "delete",
  "export",
  "readAudit",
  "manageUsers",
] as const;
export type Action = (typeof ACTIONS)[number];

export const STATUSES = ["draft", "submitted", "approved"] as const;
export type Status = (typeof STATUSES)[number];

export interface Subject {
  /** token `sub` */
  readonly id: string;
  readonly roles: readonly string[];
  readonly clearance: string;
  readonly unit: string;
  readonly compartments: readonly string[];
}

export interface Resource {
  readonly id?: string;
  readonly classification: string;
  readonly ownerUnit: string;
  readonly compartments: readonly string[];
  readonly status: string;
  readonly authorId: string;
  /** who moved it to `submitted`; the approver must differ from author and submitter */
  readonly submittedById?: string | null;
}

/** Everything that is not about the subject or the resource. The caller supplies it; the policy never reads a clock. */
export interface Environment {
  readonly acr: string;
  readonly amr: readonly string[];
  /** seconds since epoch */
  readonly now: number;
  readonly networkZone: string;
  /** present when the caller asked for break-glass access; an empty justification is a denial, not a default */
  readonly breakGlass?: { readonly justification: string };
}

export type Effect = "allow" | "deny";

/** What the caller must do besides honouring the effect. */
export type Obligation = "audit" | "alert" | "require-justification" | "step-up";

/** Stable codes: logs, tests and API responses depend on them. Never rename, only add. */
export type ReasonCode =
  | "ALLOWED"
  | "ALLOWED_BREAK_GLASS"
  | "INVALID_INPUT"
  | "ROLE_NOT_PERMITTED"
  | "CLEARANCE_TOO_LOW"
  | "COMPARTMENT_MISSING"
  | "UNIT_MISMATCH"
  | "NOT_OWNER"
  | "STATUS_FORBIDS"
  | "SEPARATION_OF_DUTIES"
  | "STEP_UP_REQUIRED"
  | "NETWORK_ZONE_FORBIDS"
  | "OUTSIDE_EXPORT_WINDOW"
  | "BREAK_GLASS_NOT_PERMITTED"
  | "BREAK_GLASS_JUSTIFICATION_REQUIRED";

export interface Decision {
  readonly effect: Effect;
  readonly reason: ReasonCode;
  readonly obligations: readonly Obligation[];
  /** ids of the rules that decided: role grants plus every ABAC rule that applied (denying ones for a deny) */
  readonly matchedRules: readonly string[];
}

export const clearanceRank = (c: unknown): number =>
  typeof c === "string" ? (CLEARANCES as readonly string[]).indexOf(c) : -1;
