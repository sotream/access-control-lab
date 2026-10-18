import { NextResponse } from "next/server";
import { apiFetch } from "../../../../../src/server/api";
import { formAction, text, UUID_RE } from "../../../../../src/server/actions";
import { esc } from "../../../../../src/server/html";

export const dynamic = "force-dynamic";

const page = (title: string, inner: string, status = 200) =>
  new NextResponse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(title)}</title></head><body><main><h1>${esc(title)}</h1>${inner}<p><a href="/cases">Back</a></p></main></body></html>`, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });

/** The one route that sends the break-glass header upstream. The result is rendered directly (the justification never goes into a URL). */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!UUID_RE.test(id)) return NextResponse.json({ error: "not_found" }, { status: 404 });
  return formAction(req, async ({ session, form }) => {
    const justification = (text(form, "justification") ?? "").trim();
    if (justification.length < 5) return page("Justification required", "<p>Please give a reason of at least five characters.</p>", 400);
    const r = await apiFetch(session, "GET", `/case-files/${id}`, { breakGlass: justification });
    if (r.status === 200) {
      const f = JSON.parse(r.body) as { title: string; classification: string; unit: string; compartments: string[]; status: string; body?: string };
      return page(
        "Case file (break-glass)",
        `<p>This access was recorded.</p><h2>${esc(f.title)}</h2><dl><dt>Classification</dt><dd>${esc(f.classification)}</dd><dt>Unit</dt><dd>${esc(f.unit)}</dd><dt>Compartments</dt><dd>${esc(f.compartments.join(", ") || "none")}</dd><dt>Status</dt><dd>${esc(f.status)}</dd></dl><pre>${esc(f.body ?? "")}</pre>`,
      );
    }
    if (r.stepUp) return page("Second factor required", `<p><a href="/api/auth/login?acr=mfa&amp;returnTo=${encodeURIComponent(`/cases/${id}`)}">Authenticate with a second factor</a></p>`, 403);
    return page("Not available", "<p>Emergency access was not granted.</p>", r.status === 404 ? 404 : 403);
  });
}
