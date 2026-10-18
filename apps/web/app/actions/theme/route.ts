import { NextResponse } from "next/server";
import { config } from "../../../src/server/config";
import { boundBody } from "../../../src/server/guard";
import { cookieAttrs, themeCookieName } from "../../../src/server/cookies";
import { checkCsrf } from "../../../src/server/csrf";
import { sessionFromCookieHeader } from "../../../src/server/session";
import { parseTheme } from "../../../src/server/theme";

export const dynamic = "force-dynamic";

const PATHS = /^\/(session|cases|cases\/new|review|audit|audit\/verify|break-glass)?$/;
const back = (path: string) => {
  const res = NextResponse.redirect(new URL(PATHS.test(path) ? path : "/", config().origin), 303);
  res.headers.set("cache-control", "no-store");
  return res;
};

/**
 * Stores the light/dark choice in a host-only cookie (a cosmetic preference, not a secret). With a session the synchronizer token is required like
 * on every form; without one (the sign-in page) Origin and Sec-Fetch-Site are still checked. The redirect target is matched against a fixed list.
 */
export async function POST(req: Request) {
  const tooBig = boundBody(req, 4096);
  if (tooBig) return tooBig;
  const form = await req.formData().catch(() => undefined);
  if (!form) return NextResponse.json({ error: "bad_form" }, { status: 400, headers: { "cache-control": "no-store" } });
  const session = await sessionFromCookieHeader(req.headers.get("cookie"));
  const presented = form.get("csrf");
  const failure = session
    ? checkCsrf(req.headers, config().origin, session.csrfToken, typeof presented === "string" ? presented : undefined)
    : checkCsrf(req.headers, config().origin, "-", "-");
  if (failure) return NextResponse.json({ error: "csrf" }, { status: 403, headers: { "cache-control": "no-store" } });
  const theme = parseTheme(form.get("theme"));
  const next = form.get("next");
  const res = back(typeof next === "string" ? next : "/");
  res.cookies.set({ name: themeCookieName(), value: theme, ...cookieAttrs(theme === "system" ? 0 : 365 * 24 * 3600) });
  return res;
}
