import { json } from "../../../../src/server/guard";
import { limited } from "../../../../src/server/limits";
import { sessionFromCookieHeader } from "../../../../src/server/session";

export const dynamic = "force-dynamic";

/** What the page scripts may know: whether there is a session and the CSRF token for it. Never a token of the identity provider. */
export async function GET(req: Request) {
  const s = await sessionFromCookieHeader(req.headers.get("cookie"));
  if (!s) return json(200, { authenticated: false });
  const slow = await limited("user", s.userSub);
  if (slow) return slow;
  return json(200, { authenticated: true, sub: s.userSub, expiresAt: s.expiresAt.toISOString(), csrfToken: s.csrfToken });
}
