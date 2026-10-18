import { NextResponse } from "next/server";
import { apiFetch } from "../../../../../src/server/api";
import { back, codeFor, formAction, text, UUID_RE } from "../../../../../src/server/actions";

export const dynamic = "force-dynamic";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!UUID_RE.test(id)) return NextResponse.json({ error: "not_found" }, { status: 404 });
  return formAction(req, async ({ session, form }) => {
    const version = Number(text(form, "version"));
    const r = await apiFetch(session, "PATCH", `/case-files/${id}`, { json: { title: text(form, "title"), body: text(form, "body"), version } });
    return back(`/cases/${id}`, "m", codeFor(r));
  });
}
