import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from "node:crypto";

/** AES-256-GCM key ring. The first entry encrypts; every entry can decrypt, which is how keys are rotated. */
export interface KeyRing {
  readonly currentId: string;
  readonly keys: ReadonlyMap<string, Buffer>;
}

export function parseKeyRing(spec: string): KeyRing {
  const keys = new Map<string, Buffer>();
  let first: string | undefined;
  for (const part of spec.split(",").map((s) => s.trim()).filter(Boolean)) {
    const i = part.indexOf(":");
    const id = part.slice(0, i);
    const b64 = part.slice(i + 1);
    if (i < 1 || !/^[A-Za-z0-9_.-]{1,32}$/.test(id)) throw new Error("key ring entry must look like id:base64");
    const key = Buffer.from(b64, "base64");
    if (key.length !== 32) throw new Error(`key ${id} must be 32 bytes (AES-256)`);
    if (keys.has(id)) throw new Error(`duplicate key id ${id}`);
    keys.set(id, key);
    first ??= id;
  }
  if (!first) throw new Error("key ring is empty");
  return { currentId: first, keys };
}

const IV = 12;
const TAG = 16;

/** iv || tag || ciphertext. `aad` binds the ciphertext to its row (a blob copied to another row will not decrypt). */
export function encrypt(ring: KeyRing, plaintext: Buffer, aad: Buffer): { keyId: string; data: Buffer } {
  const iv = randomBytes(IV);
  const c = createCipheriv("aes-256-gcm", ring.keys.get(ring.currentId) as Buffer, iv);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return { keyId: ring.currentId, data: Buffer.concat([iv, c.getAuthTag(), ct]) };
}

export function decrypt(ring: KeyRing, keyId: string, data: Buffer, aad: Buffer): Buffer {
  const key = ring.keys.get(keyId);
  if (!key) throw new Error("unknown key id");
  if (data.length < IV + TAG) throw new Error("ciphertext too short");
  const d = createDecipheriv("aes-256-gcm", key, data.subarray(0, IV));
  d.setAAD(aad);
  d.setAuthTag(data.subarray(IV, IV + TAG));
  return Buffer.concat([d.update(data.subarray(IV + TAG)), d.final()]); // throws on any tampering
}

export const randomToken = (bytes = 32): string => randomBytes(bytes).toString("base64url");
export const sha256 = (s: string | Buffer): Buffer => createHash("sha256").update(s).digest();

export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
