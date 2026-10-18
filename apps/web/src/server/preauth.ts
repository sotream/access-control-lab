import { config } from "./config";
import { decrypt, encrypt, parseKeyRing } from "./crypto";
import { cookieAttrs, preAuthCookieName } from "./cookies";

/** What must survive the round trip to the identity provider. Encrypted and authenticated in a short-lived httpOnly cookie. */
export interface PreAuth {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
  /** set when this login is a step-up request (acr_values=mfa) */
  acr?: "mfa";
  /** seconds since epoch */
  exp: number;
}

const TTL = 300;
const AAD = Buffer.from("casefile-pre-auth-v1");

export function sealPreAuth(p: Omit<PreAuth, "exp">): string {
  const ring = parseKeyRing(config().keyRing);
  const { keyId, data } = encrypt(ring, Buffer.from(JSON.stringify({ ...p, exp: Math.floor(Date.now() / 1000) + TTL })), AAD);
  return `${keyId}.${data.toString("base64url")}`;
}

export function openPreAuth(value: string | undefined): PreAuth | undefined {
  if (!value) return undefined;
  const i = value.indexOf(".");
  if (i < 1) return undefined;
  try {
    const p = JSON.parse(decrypt(parseKeyRing(config().keyRing), value.slice(0, i), Buffer.from(value.slice(i + 1), "base64url"), AAD).toString("utf8")) as PreAuth;
    if (typeof p.state !== "string" || typeof p.nonce !== "string" || typeof p.verifier !== "string" || typeof p.returnTo !== "string" || typeof p.exp !== "number" || (p.acr !== undefined && p.acr !== "mfa")) return undefined;
    return p.exp > Math.floor(Date.now() / 1000) ? p : undefined;
  } catch {
    return undefined; // tampered, wrong key, malformed
  }
}

export const preAuthCookie = (value: string) => ({ name: preAuthCookieName(), value, ...cookieAttrs(TTL) });
export const clearPreAuthCookie = () => ({ name: preAuthCookieName(), value: "", ...cookieAttrs(0) });
