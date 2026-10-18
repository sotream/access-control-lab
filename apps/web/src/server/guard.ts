import { NextResponse } from "next/server";
import { config } from "./config";
import { auditAuth } from "./audit";
import { checkCsrf } from "./csrf";
import { limited } from "./limits";
import { sessionFromCookieHeader } from "./session";
import type { Session } from "./session-store";

export const json = (status: number, body: unknown, extra: Record<string, string> = {}) =>
  NextResponse.json(body, { status, headers: { "cache-control": "no-store", ...extra } });

/** For state-changing route handlers: session, Origin, Sec-Fetch-Site and the synchronizer token (header or form field). */
export async function requireCsrfSession(req: Request, presented: string | null | undefined): Promise<{ session: Session } | { refusal: NextResponse }> {
  const session = await sessionFromCookieHeader(req.headers.get("cookie"));
  if (!session) return { refusal: json(401, { error: "unauthenticated" }) };
  const slowDown = await limited("user", session.userSub);
  if (slowDown) return { refusal: slowDown };
  const failure = checkCsrf(req.headers, config().origin, session.csrfToken, presented);
  if (failure) {
    await auditAuth({ action: "auth.csrf_denied", actorSub: session.userSub, effect: "deny", reason: failure.toUpperCase() });
    return { refusal: json(403, { error: "csrf" }) }; // the reason stays out of the response
  }
  return { session };
}

/**
 * For uploads: the body is large, so everything that can be decided WITHOUT reading it is decided first (session, rate limit, Origin, Sec-Fetch-Site);
 * `verify` checks the synchronizer token once the form has been read (it is a form field, and the body is bounded by the caller beforehand).
 */
export async function requireOriginSession(req: Request): Promise<{ session: Session; verify(presented: string | null | undefined): Promise<NextResponse | undefined> } | { refusal: NextResponse }> {
  const session = await sessionFromCookieHeader(req.headers.get("cookie"));
  if (!session) return { refusal: json(401, { error: "unauthenticated" }) };
  const slowDown = await limited("user", session.userSub);
  if (slowDown) return { refusal: slowDown };
  const deny = async (reason: string) => {
    await auditAuth({ action: "auth.csrf_denied", actorSub: session.userSub, effect: "deny", reason });
    return json(403, { error: "csrf" });
  };
  const early = checkCsrf(req.headers, config().origin, session.csrfToken, session.csrfToken); // origin and fetch metadata only: the token is the same value on both sides
  if (early) return { refusal: await deny(early.toUpperCase()) };
  return { session, verify: async (presented) => (checkCsrf(req.headers, config().origin, session.csrfToken, presented) ? deny("TOKEN_MISMATCH") : undefined) };
}

/**
 * Route handlers have no body limit of their own. A request must declare its length (chunked bodies are refused with 411) and stay under `max`
 * (413); Node's HTTP parser then delivers at most that many bytes. Call before reading the body.
 */
export function boundBody(req: Request, max: number): NextResponse | undefined {
  const raw = req.headers.get("content-length");
  if (raw === null || !/^\d{1,12}$/.test(raw)) return json(411, { error: "length_required" });
  return Number(raw) > max ? json(413, { error: "too_large" }) : undefined;
}
