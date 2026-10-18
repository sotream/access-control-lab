import { NextResponse } from "next/server";
import { auditAuth } from "../../../../src/server/audit";
import { config } from "../../../../src/server/config";
import { requireCsrfSession } from "../../../../src/server/guard";
import { cookieAttrs, preAuthCookieName, sessionCookieName } from "../../../../src/server/cookies";
import { sessionStore } from "../../../../src/server/session";
import { client, oidc, postLogoutUri } from "../../../../src/server/oidc";

export const dynamic = "force-dynamic";

/** POST only (no GET handler: a link or an image cannot log anyone out). Needs the CSRF token and a same-origin Origin. */
export async function POST(req: Request) {
  const form = await req.formData().catch(() => undefined);
  const token = (form?.get("csrf") as string | null) ?? req.headers.get("x-csrf-token");
  const r = await requireCsrfSession(req, token);
  const clear = (res: NextResponse) => {
    res.cookies.set({ name: sessionCookieName(), value: "", ...cookieAttrs(0) });
    res.cookies.set({ name: preAuthCookieName(), value: "", ...cookieAttrs(0) });
    res.headers.set("cache-control", "no-store");
    return res;
  };
  if ("refusal" in r) {
    // no valid session: nothing to revoke. A wrong token WITH a live session is a refusal and keeps the session.
    return r.refusal.status === 401 ? clear(NextResponse.redirect(new URL("/", config().origin), 303)) : r.refusal;
  }
  const { session } = r;
  await sessionStore().destroyAllForUser(session.userSub); // every session of this user, every browser
  await auditAuth({ action: "auth.logout", actorSub: session.userSub, effect: "allow", reason: "LOGOUT" }); // best effort: signing out is never blocked by the audit

  let target = new URL("/", config().origin);
  try {
    target = client.buildEndSessionUrl(await oidc(), { id_token_hint: session.tokens.idToken, post_logout_redirect_uri: postLogoutUri(), state: client.randomState() });
  } catch {
    // the identity provider is unreachable: the local session is already gone
  }
  return clear(NextResponse.redirect(target, 303));
}
