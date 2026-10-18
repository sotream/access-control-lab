import { NextResponse, type NextRequest } from "next/server";
import { AuditUnavailable, auditAuth } from "../../../../src/server/audit";
import { config } from "../../../../src/server/config";
import { clearPreAuthCookie, openPreAuth } from "../../../../src/server/preauth";
import { cookieAttrs, parseCookies, preAuthCookieName, sessionCookieName } from "../../../../src/server/cookies";
import { sessionStore, tokenSetFrom } from "../../../../src/server/session";
import { client, oidc, redirectUri } from "../../../../src/server/oidc";

export const dynamic = "force-dynamic";

const fail = async (status: number, reason: string) => {
  await auditAuth({ action: "auth.login_failed", effect: "deny", reason });
  const res = new NextResponse("Sign-in failed. Start again from the home page.", { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
  res.cookies.set(clearPreAuthCookie());
  return res;
};

/**
 * Completes the login. The library checks state, the RFC 9207 `iss` parameter when the server sends one, the PKCE verifier, and
 * the ID token (signature, issuer, audience, nonce, expiry). Only then a NEW session is created (fixation: the id is always fresh,
 * any session the browser already had is destroyed). The pre-auth cookie is single use.
 */
export async function GET(req: NextRequest) {
  const cookies = parseCookies(req.headers.get("cookie"));
  const pre = openPreAuth(cookies.get(preAuthCookieName()));
  if (!pre) return fail(400, "NO_PREAUTH");

  let tokens;
  try {
    // the redirect_uri the library compares against is OUR configured one, not whatever Host header arrived
    const current = new URL(redirectUri() + req.nextUrl.search);
    tokens = await client.authorizationCodeGrant(await oidc(), current, { pkceCodeVerifier: pre.verifier, expectedState: pre.state, expectedNonce: pre.nonce, idTokenExpected: true });
  } catch {
    return fail(400, req.nextUrl.searchParams.has("error") ? "IDP_ERROR" : "CALLBACK_REJECTED");
  }
  const claims = tokens.claims();
  const sub = claims?.sub;
  if (typeof sub !== "string" || !/^[A-Za-z0-9_.:-]{1,128}$/.test(sub)) return fail(400, "SUB_INVALID");

  // no audit row, no session: a sign-in that cannot be recorded does not happen
  const acr = typeof claims?.acr === "string" && /^[A-Za-z0-9_.:-]{1,64}$/.test(claims.acr) ? claims.acr : undefined;
  try {
    await auditAuth({ action: pre.acr === "mfa" ? "auth.stepup" : "auth.login", actorSub: sub, effect: "allow", reason: "LOGIN_OK", details: { event: "login", ...(acr ? { acr } : {}) } }, true);
  } catch (e) {
    if (e instanceof AuditUnavailable) return new NextResponse("Sign-in is temporarily unavailable.", { status: 503, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
    throw e;
  }

  const store = sessionStore();
  const old = cookies.get(sessionCookieName());
  if (old) await store.destroy(old);
  const { sid } = await store.create(sub, tokenSetFrom(tokens));

  const res = NextResponse.redirect(new URL(pre.returnTo, config().origin), 303);
  res.cookies.set(clearPreAuthCookie());
  res.cookies.set({ name: sessionCookieName(), value: sid, ...cookieAttrs(config().absoluteSeconds) });
  res.headers.set("cache-control", "no-store");
  return res;
}
