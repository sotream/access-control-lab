import { cookies } from "next/headers";
import { auditAuth } from "./audit";
import { config } from "./config";
import { parseCookies, sessionCookieName } from "./cookies";
import { sessionStore } from "./db";
import { client, oidc } from "./oidc";
import type { Session, TokenSet } from "./session-store";

export const tokenSetFrom = (t: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers, previous?: TokenSet): TokenSet => {
  const access = t.access_token;
  const refresh = t.refresh_token ?? previous?.refreshToken;
  const id = t.id_token ?? previous?.idToken;
  if (!refresh || !id) throw new Error("token response without refresh or id token");
  return { accessToken: access, refreshToken: refresh, idToken: id, accessExpiresAt: Math.floor(Date.now() / 1000) + (t.expires_in ?? 60) };
};

/** The live session for a request (cookie header), or undefined. Tokens are refreshed first when close to expiry. */
export async function sessionFromCookieHeader(header: string | null): Promise<Session | undefined> {
  const sid = parseCookies(header).get(sessionCookieName());
  if (!sid) return undefined;
  const store = sessionStore();
  const s = await store.get(sid);
  if (!s) return undefined;
  const skew = config().refreshSkewSeconds;
  const needs = (t: TokenSet) => t.accessExpiresAt - Math.floor(Date.now() / 1000) < skew;
  if (!needs(s.tokens)) return s;
  return store.withRefresh(sid, needs, async (t) => {
    const grant = await client.refreshTokenGrant(await oidc(), t.refreshToken);
    return tokenSetFrom(grant, t);
  }, (killed) => void auditAuth({ action: "auth.session_killed", actorSub: killed.userSub, effect: "deny", reason: "REFRESH_REFUSED" }));
}

/** Server components and route handlers: the session for the current request. */
export async function currentSession(): Promise<Session | undefined> {
  const jar = await cookies();
  const sid = jar.get(sessionCookieName())?.value;
  return sid ? sessionFromCookieHeader(`${sessionCookieName()}=${sid}`) : undefined;
}

export { sessionStore };
