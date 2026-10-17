// Builders and an independently written expectation of the RBAC matrix for the tests.
// The matrix is repeated here on purpose: if matrix.ts is edited by mistake, the table below disagrees and tests fail.
import type { Action, Environment, Resource, Role, Subject } from "./model.js";

/** 2026-10-17T12:00:00Z, inside the export window */
export const NOON = Date.UTC(2026, 9, 17, 12, 0, 0) / 1000;
export const at = (hourUtc: number, minute = 0) => Date.UTC(2026, 9, 17, hourUtc, minute, 0) / 1000;

export const subject = (o: Partial<Subject> = {}): Subject => ({
  id: "u1",
  roles: ["analyst"],
  clearance: "OFFICIAL",
  unit: "alpha",
  compartments: [],
  ...o,
});

export const resource = (o: Partial<Resource> = {}): Resource => ({
  id: "f1",
  classification: "OFFICIAL",
  ownerUnit: "alpha",
  compartments: [],
  status: "draft",
  authorId: "u1",
  submittedById: null,
  ...o,
});

export const env = (o: Partial<Environment> = {}): Environment => ({
  acr: "pwd",
  amr: ["pwd"],
  now: NOON,
  networkZone: "managed",
  ...o,
});

export const MFA = { acr: "mfa", amr: ["pwd", "otp"] } as const;

/** Role -> actions it may attempt (RBAC only). */
export const EXPECTED_RBAC: Record<Role, Action[]> = {
  analyst: ["create", "read", "update", "submit", "delete", "export"],
  reviewer: ["read", "approve", "export"],
  "unit-admin": ["create", "read", "update", "submit", "approve", "delete", "export", "manageUsers"],
  auditor: ["readAudit"],
  "platform-admin": ["manageUsers"],
};

export const STATUS_FOR: Partial<Record<Action, string>> = {
  create: "draft",
  read: "draft",
  update: "draft",
  submit: "draft",
  approve: "submitted",
  delete: "draft",
  export: "approved",
};

/** A resource and subject for which every ABAC rule passes, so only the role decides. */
export function perfect(role: Role, action: Action): { s: Subject; r: Resource | null; e: Environment } {
  const s = subject({ id: "actor", roles: [role], unit: "alpha", clearance: "SECRET", compartments: ["A"] });
  if (action === "readAudit" || action === "manageUsers") return { s, r: null, e: env({ ...MFA }) };
  return {
    s,
    r: resource({ authorId: action === "approve" ? "someone-else" : "actor", status: STATUS_FOR[action], classification: "OFFICIAL", compartments: ["A"] }),
    e: env({ ...MFA }),
  };
}
