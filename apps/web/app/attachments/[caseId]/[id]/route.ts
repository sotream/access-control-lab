import { NextResponse } from "next/server";
import { apiDownload, ProxyRefused } from "../../../../src/server/api";
import { UUID_RE } from "../../../../src/server/actions";
import { limited } from "../../../../src/server/limits";
import { sessionFromCookieHeader } from "../../../../src/server/session";
import { config } from "../../../../src/server/config";

export const dynamic = "force-dynamic";

const TYPES = new Set(["application/pdf", "image/png", "image/jpeg", "text/plain"]);
// what the API's disposition looks like: attachment, an ASCII name, the UTF-8 name percent-encoded. Anything else is replaced.
const DISPOSITION = /^attachment; filename="[\x20-\x7e]{1,100}"; filename\*=UTF-8''[A-Za-z0-9%._~-]{1,700}$/;
const plain = (status: number) => new NextResponse(null, { status, headers: { "cache-control": "no-store" } });

/**
 * GET only (a link). The bytes always leave as a download: attachment disposition, a type from a fixed allow-list, nosniff, a sandbox CSP,
 * no caching. Headers from the API are not copied, the two that matter are checked against a pattern and replaced when they do not match.
 */
export async function GET(req: Request, ctx: { params: Promise<{ caseId: string; id: string }> }) {
  const { caseId, id } = await ctx.params;
  if (!UUID_RE.test(caseId) || !UUID_RE.test(id)) return plain(404);
  const session = await sessionFromCookieHeader(req.headers.get("cookie"));
  if (!session) return NextResponse.redirect(new URL(`/api/auth/login?returnTo=${encodeURIComponent(`/cases/${caseId}`)}`, config().origin), 303);
  const slow = await limited("user", session.userSub);
  if (slow) return slow;
  try {
    const d = await apiDownload(session, caseId, id);
    if (d.stepUp) return NextResponse.redirect(new URL(`/api/auth/login?acr=mfa&returnTo=${encodeURIComponent(`/cases/${caseId}`)}`, config().origin), 303);
    if (d.status === 404) return plain(404);
    if (d.status === 409) return plain(409);
    const type = d.contentType?.split(";")[0]?.trim() ?? "";
    if (d.status !== 200 || !TYPES.has(type)) return plain(d.status === 200 ? 502 : d.status === 503 ? 503 : 502);
    return new NextResponse(new Uint8Array(d.bytes), {
      status: 200,
      headers: {
        "content-type": type,
        "content-disposition": d.disposition && DISPOSITION.test(d.disposition) ? d.disposition : 'attachment; filename="download"',
        "content-length": String(d.bytes.length),
        "x-content-type-options": "nosniff",
        "content-security-policy": "sandbox; default-src 'none'",
        "cache-control": "no-store",
        "cross-origin-resource-policy": "same-origin",
      },
    });
  } catch (e) {
    return plain(e instanceof ProxyRefused ? e.status : 502);
  }
}
