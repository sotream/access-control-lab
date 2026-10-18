// Token forging helpers for the abuse cases.
import { createHmac, createSign } from "node:crypto";

export const b64 = (o: unknown): string => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");
export const parts = (jwt: string) => {
  const [h, p, s] = jwt.split(".") as [string, string, string];
  return { header: JSON.parse(Buffer.from(h, "base64url").toString()) as Record<string, unknown>, payload: JSON.parse(Buffer.from(p, "base64url").toString()) as Record<string, unknown>, signature: s, h, p };
};
export const withPayload = (jwt: string, edit: (p: Record<string, unknown>) => void): string => {
  const x = parts(jwt);
  edit(x.payload);
  return `${x.h}.${b64(x.payload)}.${x.signature}`; // original signature kept: the payload no longer matches it
};
export const withHeader = (jwt: string, edit: (h: Record<string, unknown>) => void): string => {
  const x = parts(jwt);
  edit(x.header);
  return `${b64(x.header)}.${x.p}.${x.signature}`;
};
export const unsigned = (header: Record<string, unknown>, payload: Record<string, unknown>, sig = ""): string => `${b64(header)}.${b64(payload)}.${sig}`;
export const hs256 = (payload: Record<string, unknown>, key: string | Buffer, header: Record<string, unknown> = { alg: "HS256", typ: "JWT" }): string => {
  const data = `${b64(header)}.${b64(payload)}`;
  return `${data}.${createHmac("sha256", key).update(data).digest("base64url")}`;
};
/** RS256 with an attacker's own key pair (the signature is valid, the key is not the realm's) */
export const rs256 = (payload: Record<string, unknown>, privatePem: string, header: Record<string, unknown> = { alg: "RS256", typ: "JWT" }): string => {
  const data = `${b64(header)}.${b64(payload)}`;
  return `${data}.${createSign("RSA-SHA256").update(data).sign(privatePem).toString("base64url")}`;
};
