import { randomBytes } from "node:crypto";
import { buildRow, genesisHead } from "./chain.js";
import { parseAuditKeys, type AuditKeys } from "./keys.js";
import type { AuditEntry, AuditRow, Head } from "./model.js";

export const keyB64 = (n = 1) => Buffer.alloc(32, n).toString("base64");
export const ring = (spec = `k1:${keyB64(1)}`): AuditKeys => parseAuditKeys(spec);
export const randomRing = () => parseAuditKeys(`r:${randomBytes(32).toString("base64")}`);

export const entry = (over: Partial<AuditEntry> = {}): AuditEntry => ({
  actorSub: "user-1",
  actorRoles: ["analyst"],
  action: "read",
  resourceType: "case_file",
  resourceId: "0f1e2d3c-4b5a-4968-8776-655443322110",
  effect: "allow",
  reasonCode: "ALLOWED",
  obligations: ["audit"],
  requestId: "req-00000001",
  source: "api",
  details: { rule_ids: ["rbac.role-grants-action"] },
  ...over,
});

export const T0 = Date.UTC(2026, 9, 18, 12, 0, 0);

/** n correctly chained rows. */
export function chain(n: number, r: AuditKeys = ring(), mk: (i: number) => AuditEntry = (i) => entry({ requestId: `req-${String(i).padStart(8, "0")}` })): AuditRow[] {
  const rows: AuditRow[] = [];
  let head: Head = genesisHead();
  for (let i = 1; i <= n; i++) {
    const row = buildRow(mk(i), head, r, new Date(T0 + i * 1000));
    rows.push(row);
    head = { lastId: row.id, lastHash: row.hash };
  }
  return rows;
}

export const clone = (r: AuditRow): AuditRow => ({ ...r, actorRoles: [...r.actorRoles], obligations: [...r.obligations], details: JSON.parse(JSON.stringify(r.details)), prevHash: Buffer.from(r.prevHash), hash: Buffer.from(r.hash), ts: new Date(r.ts) });
