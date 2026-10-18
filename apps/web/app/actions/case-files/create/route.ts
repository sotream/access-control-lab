import { NextResponse } from "next/server";
import { config } from "../../../../src/server/config";
import { apiFetch } from "../../../../src/server/api";
import { back, codeFor, formAction, text } from "../../../../src/server/actions";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  return formAction(req, async ({ session, form }) => {
    const compartments = (text(form, "compartments") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
    const r = await apiFetch(session, "POST", "/case-files", { json: { title: text(form, "title"), body: text(form, "body") ?? "", classification: text(form, "classification"), compartments } });
    if (r.status === 201) {
      const id = (JSON.parse(r.body) as { id?: string }).id;
      if (typeof id === "string" && /^[0-9a-f-]{36}$/.test(id)) {
        return NextResponse.redirect(new URL(`/cases/${id}?m=done`, config().origin), { status: 303, headers: { "cache-control": "no-store" } });
      }
    }
    return back("/cases/new", "e", codeFor(r));
  });
}
