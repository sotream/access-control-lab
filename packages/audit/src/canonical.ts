import { CHAIN_VERSION, CHECKPOINT_VERSION, type AuditRow, type Checkpoint } from "./model.js";

/** JSON with object keys sorted (by UTF-16 code unit), no whitespace; integers and strings, booleans, null, arrays and objects only. */
export function stableStringify(v: unknown): string {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error("canonical JSON allows integers only");
    return String(v);
  }
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stableStringify(o[k])}`)
      .join(",")}}`;
  }
  throw new Error("value not representable in canonical JSON");
}

/**
 * The exact bytes that are authenticated for a row (format `acl-audit/v1`): UTF-8 of the JSON text of this array, in this order:
 * [version, id as decimal string, ts as ISO-8601 UTC with milliseconds, actor_sub, actor_roles sorted, action, resource_type, resource_id or null, effect,
 *  reason_code, obligations sorted, request_id, source, details as canonical JSON TEXT (a string inside the array), prev_hash hex, key_id].
 * The hash itself is HMAC-SHA256(key[key_id], those bytes).
 */
export function canonicalBytes(r: Omit<AuditRow, "hash">): Buffer {
  const arr = [
    CHAIN_VERSION,
    String(r.id),
    r.ts.toISOString(),
    r.actorSub,
    [...r.actorRoles].sort(),
    r.action,
    r.resourceType,
    r.resourceId,
    r.effect,
    r.reasonCode,
    [...r.obligations].sort(),
    r.requestId,
    r.source,
    stableStringify(r.details),
    r.prevHash.toString("hex"),
    r.keyId,
  ];
  return Buffer.from(JSON.stringify(arr), "utf8");
}

/** Checkpoint bytes: [version, ts ISO, last id as decimal string, last hash hex, key id]; mac = HMAC-SHA256 over them. */
export function checkpointBytes(c: Omit<Checkpoint, "mac" | "id">): Buffer {
  return Buffer.from(JSON.stringify([CHECKPOINT_VERSION, c.ts.toISOString(), String(c.lastId), c.lastHash.toString("hex"), c.keyId]), "utf8");
}
