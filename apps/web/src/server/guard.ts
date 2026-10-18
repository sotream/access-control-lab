import { NextResponse } from "next/server";
import { config } from "./config";
import { checkCsrf } from "./csrf";
import { sessionFromCookieHeader } from "./session";
import type { Session } from "./session-store";

export const json = (status: number, body: unknown, extra: Record<string, string> = {}) =>
  NextResponse.json(body, { status, headers: { "cache-control": "no-store", ...extra } });

/** For state-changing route handlers: session, Origin, Sec-Fetch-Site and the synchronizer token (header or form field). */
export async function requireCsrfSession(req: Request, presented: string | null | undefined): Promise<{ session: Session } | { refusal: NextResponse }> {
  const session = await sessionFromCookieHeader(req.headers.get("cookie"));
  if (!session) return { refusal: json(401, { error: "unauthenticated" }) };
  const failure = checkCsrf(req.headers, config().origin, session.csrfToken, presented);
  if (failure) return { refusal: json(403, { error: "csrf" }) }; // the reason stays out of the response
  return { session };
}
