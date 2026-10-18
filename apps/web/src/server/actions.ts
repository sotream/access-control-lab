import { NextResponse } from "next/server";
import { config } from "./config";
import { ProxyRefused, type ApiResult } from "./api";
import { boundBody, requireCsrfSession } from "./guard";
import type { Session } from "./session-store";

/** ordinary forms are small: titles and bodies up to 50 000 characters (4 bytes each in the worst case) plus fields */
export const MAX_FORM = 256 * 1024;

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Parses the form, checks session + CSRF, hands over. Refusals are JSON 401/403 (a browser form post that fails CSRF is not a user mistake). */
export async function formAction(req: Request, run: (a: { session: Session; form: FormData }) => Promise<Response>): Promise<Response> {
  const tooBig = boundBody(req, MAX_FORM);
  if (tooBig) return tooBig;
  const form = await req.formData().catch(() => undefined);
  if (!form) return NextResponse.json({ error: "bad_form" }, { status: 400, headers: { "cache-control": "no-store" } });
  const r = await requireCsrfSession(req, (form.get("csrf") as string | null) ?? undefined);
  if ("refusal" in r) return r.refusal;
  try {
    return await run({ session: r.session, form });
  } catch (e) {
    if (e instanceof ProxyRefused) return NextResponse.json({ error: "refused" }, { status: e.status, headers: { "cache-control": "no-store" } });
    return NextResponse.json({ error: "upstream_unavailable" }, { status: 502, headers: { "cache-control": "no-store" } });
  }
}

/** Post/Redirect/Get to a page of ours; the message is one of a fixed set of codes, never text from the request or the API. */
export function back(path: string, key: "m" | "e", code: string): NextResponse {
  return withNoStore(NextResponse.redirect(new URL(`${path}?${key}=${code}`, config().origin), 303));
}
const withNoStore = (r: NextResponse) => (r.headers.set("cache-control", "no-store"), r);

export function codeFor(r: ApiResult): string {
  if (r.stepUp) return "stepup";
  if (r.status === 201) return "uploaded";
  if (r.status === 413) return "toolarge";
  if (r.status === 415 || r.status === 422) return "rejected";
  if (r.status === 503) return "unavailable";
  if (r.status >= 200 && r.status < 300) return "done";
  if (r.status === 409) return "conflict";
  if (r.status === 400) return "invalid";
  return "forbidden";
}

export const text = (form: FormData, name: string): string | undefined => {
  const v = form.get(name);
  return typeof v === "string" ? v : undefined;
};
