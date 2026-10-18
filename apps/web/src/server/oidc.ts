import * as client from "openid-client";
import { config } from "./config";

const g = globalThis as unknown as { __casefileOidc?: Promise<client.Configuration> };

/**
 * Discovery against the pinned issuer (the library refuses a document whose `issuer` differs). Cached per process.
 * Plain http to the identity provider is allowed only for a loopback issuer (dev).
 */
export function oidc(): Promise<client.Configuration> {
  g.__casefileOidc ??= (async () => {
    const c = config();
    const cfg = await client.discovery(new URL(c.issuer), c.clientId, undefined, client.ClientSecretPost(c.clientSecret), c.allowInsecureIdp ? { execute: [client.allowInsecureRequests] } : undefined);
    return cfg;
  })().catch((e: unknown) => {
    g.__casefileOidc = undefined; // do not cache a failed discovery
    throw e;
  });
  return g.__casefileOidc;
}

export const redirectUri = (): string => `${config().origin}/api/auth/callback`;
export const postLogoutUri = (): string => `${config().origin}/`;

export { client };
