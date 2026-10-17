import type { Action, Role } from "./model.js";

/** One row of the RBAC matrix. Data, not code, so it can be reviewed and rendered as a table. */
export interface RoleGrant {
  /** actions the role may attempt at all (RBAC). Anything else is denied. */
  readonly actions: readonly Action[];
  /** write actions this role may perform on another unit's resource */
  readonly crossUnit: readonly Action[];
  /** actions limited to resources the subject authored */
  readonly ownOnly: readonly Action[];
  /** may request break-glass read */
  readonly breakGlass: boolean;
}

const g = (x: RoleGrant): RoleGrant => Object.freeze({ ...x, actions: Object.freeze([...x.actions]), crossUnit: Object.freeze([...x.crossUnit]), ownOnly: Object.freeze([...x.ownOnly]) });

export const ROLE_GRANTS: Readonly<Record<Role, RoleGrant>> = Object.freeze({
  analyst: g({
    actions: ["create", "read", "update", "submit", "delete", "export"],
    crossUnit: [],
    ownOnly: ["update", "submit", "delete"],
    breakGlass: false,
  }),
  reviewer: g({ actions: ["read", "approve", "export"], crossUnit: ["approve"], ownOnly: [], breakGlass: false }),
  "unit-admin": g({
    actions: ["create", "read", "update", "submit", "approve", "delete", "export", "manageUsers"],
    crossUnit: [],
    ownOnly: [],
    breakGlass: true,
  }),
  auditor: g({ actions: ["readAudit"], crossUnit: [], ownOnly: [], breakGlass: false }),
  "platform-admin": g({ actions: ["manageUsers"], crossUnit: [], ownOnly: [], breakGlass: false }),
});

/** Actions that concern a case file. The others (readAudit, manageUsers) are decided by role alone. */
export const RESOURCE_ACTIONS: readonly Action[] = Object.freeze([
  "create",
  "read",
  "update",
  "submit",
  "approve",
  "delete",
  "export",
]);

/** Actions that change data and therefore need the resource in the subject's unit (unless the role is cross-unit). */
export const WRITE_ACTIONS: readonly Action[] = Object.freeze(["create", "update", "submit", "approve", "delete"]);

/** Allowed resource status per action (status machine): draft -> submitted -> approved. */
export const ALLOWED_STATUS: Readonly<Partial<Record<Action, readonly string[]>>> = Object.freeze({
  create: ["draft"],
  read: ["draft", "submitted", "approved"],
  update: ["draft"],
  submit: ["draft"],
  approve: ["submitted"],
  delete: ["draft"],
  export: ["approved"],
});

/** Export window, UTC hours [start, end). Example of a time condition; `now` is supplied by the caller. */
export const EXPORT_WINDOW_UTC = Object.freeze({ startHour: 6, endHour: 20 });
export const MANAGED_ZONE = "managed";
