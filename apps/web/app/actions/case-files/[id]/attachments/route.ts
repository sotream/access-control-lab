import { NextResponse } from "next/server";
import { apiUpload, MAX_UPLOAD, ProxyRefused } from "../../../../../src/server/api";
import { back, codeFor, UUID_RE } from "../../../../../src/server/actions";
import { boundBody, requireOriginSession } from "../../../../../src/server/guard";

export const dynamic = "force-dynamic";

const refuse = (status: number, error: string) => NextResponse.json({ error }, { status, headers: { "cache-control": "no-store" } });

/**
 * Browser form upload (multipart). Order matters: length bound, session, rate limit and Origin first (all without reading the body),
 * then the body (bounded by its declared length), then the synchronizer token from the form, then one call to the API with raw bytes.
 * Nothing the browser sends except the bytes, the file's own name and its declared type reaches the API, and the API trusts neither name nor type.
 */
export async function POST(req: Request, ctx: { params: Promise<{ id: string }> }) {
  const { id } = await ctx.params;
  if (!UUID_RE.test(id)) return refuse(404, "not_found");
  const tooBig = boundBody(req, MAX_UPLOAD + 16 * 1024);
  if (tooBig) return tooBig;
  const r = await requireOriginSession(req);
  if ("refusal" in r) return r.refusal;
  const form = await req.formData().catch(() => undefined);
  if (!form) return refuse(400, "bad_form");
  const bad = await r.verify(typeof form.get("csrf") === "string" ? (form.get("csrf") as string) : undefined);
  if (bad) return bad;
  const file = form.get("file");
  if (!(file instanceof File) || file.size === 0 || file.size > MAX_UPLOAD) return back(`/cases/${id}`, "m", file instanceof File && file.size > MAX_UPLOAD ? "toolarge" : "rejected");
  try {
    return back(`/cases/${id}`, "m", codeFor(await apiUpload(r.session, id, Buffer.from(await file.arrayBuffer()), file.type, file.name)));
  } catch (e) {
    if (e instanceof ProxyRefused) return refuse(e.status, "refused");
    return refuse(502, "upstream_unavailable");
  }
}
