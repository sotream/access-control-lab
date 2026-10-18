import { NextResponse } from "next/server";
import { config } from "../../../../../src/server/config";
import { apiFetch } from "../../../../../src/server/api";
import { back, codeFor, formAction, UUID_RE } from "../../../../../src/server/actions";

export const dynamic = "force-dynamic";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!UUID_RE.test(id)) return NextResponse.json({ error: "not_found" }, { status: 404 });
  return formAction(req, async ({ session }) => {
    const r = await apiFetch(session, "DELETE", `/case-files/${id}`);
    if (r.status === 200) return NextResponse.redirect(new URL("/cases", config().origin), { status: 303, headers: { "cache-control": "no-store" } });
    return back(`/cases/${id}`, "m", codeFor(r));
  });
}
