import { NextResponse, type NextRequest } from "next/server";
import { client, oidc, redirectUri } from "../../../../src/server/oidc";
import { clearPreAuthCookie, preAuthCookie, sealPreAuth } from "../../../../src/server/preauth";
import { safeAcr, safeReturnTo } from "../../../../src/server/redirect";

export const dynamic = "force-dynamic";

/** Starts Authorization Code + PKCE (S256). state, nonce and the verifier go into a short-lived encrypted httpOnly cookie. */
export async function GET(req: NextRequest) {
  const cfg = await oidc();
  const returnTo = safeReturnTo(req.nextUrl.searchParams.get("returnTo"));
  const acr = safeAcr(req.nextUrl.searchParams.get("acr"));
  const state = client.randomState();
  const nonce = client.randomNonce();
  const verifier = client.randomPKCECodeVerifier();
  const challenge = await client.calculatePKCECodeChallenge(verifier);

  const url = client.buildAuthorizationUrl(cfg, {
    redirect_uri: redirectUri(),
    scope: "openid",
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
    nonce,
    ...(acr ? { acr_values: acr } : {}),
  });
  const res = NextResponse.redirect(url, 303);
  res.cookies.set(clearPreAuthCookie()); // never two flows in one cookie
  res.cookies.set(preAuthCookie(sealPreAuth({ state, nonce, verifier, returnTo, ...(acr ? { acr } : {}) })));
  res.headers.set("cache-control", "no-store");
  return res;
}
