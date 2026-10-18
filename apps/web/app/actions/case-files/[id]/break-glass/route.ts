import { NextResponse } from "next/server";
import { config } from "../../../../../src/server/config";
import { formAction, text, UUID_RE } from "../../../../../src/server/actions";
import { BG_COOKIE_SECONDS, packJustification } from "../../../../../src/server/break-glass";
import { breakGlassCookieName, cookieAttrs } from "../../../../../src/server/cookies";

export const dynamic = "force-dynamic";

const go = (path: string) => NextResponse.redirect(new URL(path, config().origin), { status: 303, headers: { "cache-control": "no-store" } });

/**
 * Validates the form (session, CSRF, length) and hands over to the result page, which does the audited read. The justification
 * is kept in a 2-minute HttpOnly cookie, not in the URL.
 */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!UUID_RE.test(id)) return NextResponse.json({ error: "not_found" }, { status: 404 });
  return formAction(req, async ({ form }) => {
    const justification = (text(form, "justification") ?? "").trim().slice(0, 500);
    if (justification.length < 5) return go(`/cases/${id}/break-glass?e=short`);
    const res = go(`/cases/${id}/break-glass/result`);
    res.cookies.set({ name: breakGlassCookieName(), value: packJustification(id, justification), ...cookieAttrs(BG_COOKIE_SECONDS) });
    return res;
  });
}
