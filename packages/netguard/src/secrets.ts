import { readFileSync } from "node:fs";

type Env = Record<string, string | undefined>;

/**
 * `NAME_FILE=/run/secrets/name` replaces `NAME` (Docker/Kubernetes secrets, no secret in the environment of the process listing).
 * Both set is an error, an unreadable or empty file is an error, one trailing newline is dropped. Only the listed names are looked at.
 */
export function resolveSecretFiles(env: Env, names: readonly string[], read: (path: string) => string = (p) => readFileSync(p, "utf8")): Env {
  const out: Env = { ...env };
  for (const name of names) {
    const file = env[`${name}_FILE`];
    if (!file) continue;
    if (env[name]) throw new Error(`${name} and ${name}_FILE are both set`);
    let value: string;
    try {
      value = read(file).replace(/\r?\n$/, "");
    } catch {
      throw new Error(`${name}_FILE is not readable`); // the path may be informative, the content never is
    }
    if (!value) throw new Error(`${name}_FILE is empty`);
    out[name] = value;
  }
  return out;
}

/** `production` only when ACL_ENV says so. A typo is an error, not a silent downgrade to development. */
export function profileOf(env: Env): "production" | "development" {
  const v = env.ACL_ENV;
  if (v === undefined || v === "" || v === "development") return "development";
  if (v === "production") return "production";
  throw new Error("ACL_ENV must be production or development");
}

const DEV = /dev-only|changeme|change-me|example|password|secret123/i;

/** True for the values this repository ships for development, and for the obvious placeholders. */
export const looksLikeDevValue = (v: string): boolean => DEV.test(v);

function keysOf(spec: string): { id: string; key: Buffer }[] {
  return spec.split(",").map((s) => s.trim()).filter(Boolean).map((p) => ({ id: p.slice(0, p.indexOf(":")), key: Buffer.from(p.slice(p.indexOf(":") + 1), "base64") }));
}

/** A key ring `id:base64,...` fit for production: every key at least 32 bytes, not text, not a repeated byte, not low entropy, not a dev value. */
export function assertStrongKeyRing(name: string, spec: string): void {
  for (const { id, key } of keysOf(spec)) {
    if (key.length < 32) throw new Error(`${name} key ${id} is shorter than 32 bytes`);
    const text = key.toString("utf8");
    if (looksLikeDevValue(text) || looksLikeDevValue(id) || /^dev[-_]/i.test(id)) throw new Error(`${name} key ${id} is a development value`);
    if (new Set(key).size < 12) throw new Error(`${name} key ${id} has too little entropy`);
  }
}

/** A secret string (client secret, proxy secret) fit for production. */
export function assertStrongSecret(name: string, value: string, minBytes = 32): void {
  if (Buffer.byteLength(value) < minBytes) throw new Error(`${name} must be at least ${minBytes} bytes in production`);
  if (looksLikeDevValue(value)) throw new Error(`${name} is a development value`);
  if (new Set(value).size < 10) throw new Error(`${name} has too little entropy`);
}

/** The password inside a postgres URL, fit for production. */
export function assertStrongDbUrl(name: string, url: string): void {
  const pw = decodeURIComponent(new URL(url).password);
  if (pw.length < 16) throw new Error(`${name} password must be at least 16 characters in production`);
  if (looksLikeDevValue(pw)) throw new Error(`${name} password is a development value`);
}
