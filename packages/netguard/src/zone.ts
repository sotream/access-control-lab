import { createHmac, timingSafeEqual } from "node:crypto";

export type Zone = "managed" | "unmanaged";

/** Ring of zone-signing keys, `id:base64,...`. The first signs, all verify (rotation). */
export interface ZoneKeys {
  readonly currentId: string;
  readonly keys: ReadonlyMap<string, Buffer>;
}

export function parseZoneKeys(spec: string): ZoneKeys {
  const keys = new Map<string, Buffer>();
  let first: string | undefined;
  for (const part of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    const i = part.indexOf(":");
    const id = part.slice(0, i);
    if (i < 1 || !/^[A-Za-z0-9_-]{1,32}$/.test(id)) throw new Error("zone key entry must look like id:base64");
    const key = Buffer.from(part.slice(i + 1), "base64");
    if (key.length < 32) throw new Error(`zone key ${id} must be at least 32 bytes`);
    if (keys.has(id)) throw new Error(`duplicate zone key id ${id}`);
    keys.set(id, key);
    first ??= id;
  }
  if (!first) throw new Error("zone key ring is empty");
  return { currentId: first, keys };
}

const mac = (key: Buffer, ts: number, zone: Zone, sub: string): Buffer => createHmac("sha256", key).update(`acl-zone/v1\n${ts}\n${zone}\n${sub}`).digest();

/**
 * `v1.<keyId>.<unix seconds>.<zone>.<mac>`: only the holder of a key can produce it, it names the subject it was made for (a header copied
 * to another user's request fails) and it expires, so the API can accept a network zone from the BFF and from nobody else.
 */
export function signZone(keys: ZoneKeys, zone: Zone, sub: string, nowSeconds: number): string {
  const key = keys.keys.get(keys.currentId) as Buffer;
  return `v1.${keys.currentId}.${nowSeconds}.${zone}.${mac(key, nowSeconds, zone, sub).toString("base64url")}`;
}

/** The zone the header proves for this subject, or undefined for anything else (absent, malformed, unknown key, wrong subject, stale, forged). */
export function verifyZone(keys: ZoneKeys, header: string | undefined, sub: string, nowSeconds: number, maxAgeSeconds = 30): Zone | undefined {
  if (header === undefined || header.length > 200) return undefined;
  const [v, kid, ts, zone, tag, extra] = header.split(".");
  if (v !== "v1" || extra !== undefined || !kid || !ts || !tag || !/^\d{1,12}$/.test(ts) || (zone !== "managed" && zone !== "unmanaged")) return undefined;
  const key = keys.keys.get(kid);
  const t = Number(ts);
  if (!key || t > nowSeconds + 5 || nowSeconds - t > maxAgeSeconds) return undefined;
  const given = Buffer.from(tag, "base64url");
  const want = mac(key, t, zone, sub);
  return given.length === want.length && timingSafeEqual(given, want) ? zone : undefined;
}
