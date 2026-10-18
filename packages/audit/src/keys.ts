import { createHmac, timingSafeEqual } from "node:crypto";

/** HMAC key ring. The first entry signs new rows and checkpoints; every entry can verify old ones (rotation). */
export interface AuditKeys {
  readonly currentId: string;
  readonly keys: ReadonlyMap<string, Buffer>;
}

export function parseAuditKeys(spec: string): AuditKeys {
  const keys = new Map<string, Buffer>();
  let first: string | undefined;
  for (const part of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    const i = part.indexOf(":");
    const id = part.slice(0, i);
    if (i < 1 || !/^[A-Za-z0-9_.-]{1,32}$/.test(id)) throw new Error("audit key entry must look like id:base64");
    const key = Buffer.from(part.slice(i + 1), "base64");
    if (key.length < 32) throw new Error(`audit key ${id} must be at least 32 bytes`);
    if (keys.has(id)) throw new Error(`duplicate audit key id ${id}`);
    keys.set(id, key);
    first ??= id;
  }
  if (!first) throw new Error("audit key ring is empty");
  return { currentId: first, keys };
}

export function mac(ring: AuditKeys, keyId: string, bytes: Buffer): Buffer {
  const key = ring.keys.get(keyId);
  if (!key) throw new Error("unknown audit key id");
  return createHmac("sha256", key).update(bytes).digest();
}

export const macEquals = (a: Buffer, b: Buffer): boolean => a.length === b.length && timingSafeEqual(a, b);
