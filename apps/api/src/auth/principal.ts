// Strict mapping from verified token claims to a typed Principal.
// Anything missing, mistyped or outside the known vocabulary fails closed: no partial principal exists.
export const CLEARANCES = ["OFFICIAL", "CONFIDENTIAL", "SECRET"] as const;
export type Clearance = (typeof CLEARANCES)[number];

export const ROLES = ["analyst", "reviewer", "unit-admin", "auditor", "platform-admin"] as const;
export type Role = (typeof ROLES)[number];

export interface Principal {
  readonly sub: string;
  readonly sessionId: string | undefined;
  /** application roles only; other realm roles in the token are dropped */
  readonly roles: readonly Role[];
  readonly clearance: Clearance;
  readonly unit: string;
  readonly compartments: readonly string[];
  readonly acr: string;
  readonly amr: readonly string[];
  /** seconds since epoch of the interactive authentication */
  readonly authTime: number;
}

/** Reason codes are safe to log and never contain claim values. */
export class PrincipalError extends Error {
  constructor(readonly reason: string) {
    super(reason);
  }
}

const TAG = /^[A-Za-z0-9_-]{1,32}$/;
const ID = /^[A-Za-z0-9_.:-]{1,128}$/;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function str(v: unknown, re: RegExp, reason: string): string {
  if (typeof v !== "string" || !re.test(v)) throw new PrincipalError(reason);
  return v;
}

function strArray(v: unknown, re: RegExp, reason: string, max: number): string[] {
  if (!Array.isArray(v) || v.length > max) throw new PrincipalError(reason);
  return v.map((x) => str(x, re, reason));
}

export function toPrincipal(claims: Record<string, unknown>): Principal {
  const realm = claims.realm_access;
  if (!isObj(realm)) throw new PrincipalError("claim_realm_access");
  const rawRoles = strArray(realm.roles, /^[A-Za-z0-9_.:-]{1,64}$/, "claim_roles", 200);
  const roles = [...new Set(rawRoles.filter((r): r is Role => (ROLES as readonly string[]).includes(r)))];

  const clearance = claims.clearance;
  if (typeof clearance !== "string" || !(CLEARANCES as readonly string[]).includes(clearance)) {
    throw new PrincipalError("claim_clearance");
  }

  // absent compartments claim means none; present but malformed is an error
  const compartments =
    claims.compartments === undefined ? [] : [...new Set(strArray(claims.compartments, TAG, "claim_compartments", 64))];

  const amr = claims.amr === undefined ? [] : strArray(claims.amr, TAG, "claim_amr", 16);

  const authTime = claims.auth_time;
  if (typeof authTime !== "number" || !Number.isFinite(authTime) || authTime <= 0) {
    throw new PrincipalError("claim_auth_time");
  }

  return Object.freeze({
    sub: str(claims.sub, ID, "claim_sub"),
    sessionId: claims.sid === undefined ? undefined : str(claims.sid, ID, "claim_sid"),
    roles: Object.freeze(roles),
    clearance: clearance as Clearance,
    unit: str(claims.unit, TAG, "claim_unit"),
    compartments: Object.freeze(compartments),
    acr: str(claims.acr, TAG, "claim_acr"),
    amr: Object.freeze(amr),
    authTime,
  });
}
