import { NextResponse } from "next/server";
import { apiFetch } from "../../../../../src/server/api";
import { back, codeFor, formAction, UUID_RE } from "../../../../../src/server/actions";

export const dynamic = "force-dynamic";

export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!UUID_RE.test(id)) return NextResponse.json({ error: "not_found" }, { status: 404 });
  return formAction(req, async ({ session }) => back(`/cases/${id}`, "m", codeFor(await apiFetch(session, "POST", `/case-files/${id}/submit`))));
}
