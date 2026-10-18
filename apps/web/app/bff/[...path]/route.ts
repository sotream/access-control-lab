import { allowed, apiFetch, MAX_PROXY_BODY, ProxyRefused, QUERY_KEYS } from "../../../src/server/api";
import { json, requireCsrfSession } from "../../../src/server/guard";
import { sessionFromCookieHeader } from "../../../src/server/session";

export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ path: string[] }> };

async function handle(req: Request, ctx: Ctx): Promise<Response> {
  const path = "/" + (await ctx.params).path.join("/");
  const method = req.method;
  if (!allowed(method, path)) return json(404, { error: "not_found" }); // checked before anything else: not an open proxy

  let jsonBody: unknown;
  let session;
  if (method === "GET") {
    session = await sessionFromCookieHeader(req.headers.get("cookie"));
    if (!session) return json(401, { error: "unauthenticated" });
  } else {
    const r = await requireCsrfSession(req, req.headers.get("x-csrf-token"));
    if ("refusal" in r) return r.refusal;
    session = r.session;
    if (method === "POST" || method === "PATCH") {
      const ct = req.headers.get("content-type") ?? "";
      const raw = await req.text();
      if (raw.length > 0) {
        if (!ct.toLowerCase().startsWith("application/json")) return json(415, { error: "unsupported_media_type" });
        if (Buffer.byteLength(raw) > MAX_PROXY_BODY) return json(413, { error: "too_large" });
        try {
          jsonBody = JSON.parse(raw);
        } catch {
          return json(400, { error: "bad_json" });
        }
      }
    }
  }

  try {
    // the browser's query string, cookies and headers are not forwarded; neither is any break-glass header (own route only)
    // only the audit endpoints take parameters, and only the listed ones; any other path ignores the query string entirely
    const query = QUERY_KEYS[path] ? Object.fromEntries(new URL(req.url).searchParams) : undefined;
    const res = await apiFetch(session, method, path, { ...(jsonBody === undefined ? {} : { json: jsonBody }), ...(query ? { query } : {}) });
    const headers: Record<string, string> = { "content-type": res.contentType, "cache-control": "no-store" };
    if (res.wwwAuthenticate) headers["www-authenticate"] = res.wwwAuthenticate; // lets the UI start a step-up (RFC 9470)
    if (res.retryAfter) headers["retry-after"] = res.retryAfter;
    if (res.proof) headers["x-audit-proof"] = res.proof;
    return new Response(res.body, { status: res.status, headers });
  } catch (e) {
    if (e instanceof ProxyRefused) return json(e.status, { error: "refused" });
    return json(502, { error: "upstream_unavailable" });
  }
}

export { handle as GET, handle as POST, handle as PATCH, handle as DELETE };
