import { NextResponse } from "next/server";
import { apiFetch } from "../../../../src/server/api";
import { formAction, text } from "../../../../src/server/actions";

export const dynamic = "force-dynamic";

/** Auditor export as a download. The export itself is audited by the API before any data is returned. */
export async function POST(req: Request) {
  return formAction(req, async ({ session, form }) => {
    const format = text(form, "format") === "csv" ? "csv" : "ndjson";
    const query: Record<string, string | undefined> = { format };
    for (const k of ["from", "to", "actor", "resource", "action", "effect", "cursor"]) query[k] = text(form, k);
    const r = await apiFetch(session, "GET", "/audit-log/export", { query });
    if (r.status !== 200) return NextResponse.json({ error: r.status === 403 ? "forbidden" : "unavailable" }, { status: r.status === 403 ? 403 : 502, headers: { "cache-control": "no-store" } });
    return new NextResponse(r.body, {
      status: 200,
      headers: {
        "content-type": r.contentType === "text/csv" ? "text/csv; charset=utf-8" : "application/x-ndjson; charset=utf-8",
        "content-disposition": `attachment; filename="audit-log.${format}"`,
        "x-content-type-options": "nosniff",
        "cache-control": "no-store",
        ...(r.proof ? { "x-audit-proof": r.proof } : {}),
      },
    });
  });
}
