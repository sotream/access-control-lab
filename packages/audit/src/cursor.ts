import { createHash } from "node:crypto";
import { mac, macEquals, type AuditKeys } from "./keys.js";

/** Fingerprint of the filter set a cursor belongs to: a cursor from one query cannot be replayed on another. */
export const fingerprint = (filters: Readonly<Record<string, string | undefined>>): string =>
  createHash("sha256")
    .update(JSON.stringify(Object.keys(filters).filter((k) => filters[k] !== undefined).sort().map((k) => [k, filters[k]])))
    .digest("hex")
    .slice(0, 16);

const body = (keyId: string, afterId: number, fp: string) => Buffer.from(`cursor/v1|${keyId}|${afterId}|${fp}`);

/** `keyId.afterId.mac`: stable (ids only grow), tamper-evident, bound to the filters. */
export function makeCursor(ring: AuditKeys, afterId: number, fp: string): string {
  return `${ring.currentId}.${afterId}.${mac(ring, ring.currentId, body(ring.currentId, afterId, fp)).toString("hex").slice(0, 32)}`;
}

export function openCursor(ring: AuditKeys, cursor: string, fp: string): number | undefined {
  const m = /^([A-Za-z0-9_.-]{1,32})\.(\d{1,15})\.([0-9a-f]{32})$/.exec(cursor);
  if (!m || !ring.keys.has(m[1] as string)) return undefined;
  const afterId = Number(m[2]);
  const want = mac(ring, m[1] as string, body(m[1] as string, afterId, fp)).subarray(0, 16);
  return macEquals(want, Buffer.from(m[3] as string, "hex")) ? afterId : undefined;
}
