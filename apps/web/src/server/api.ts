import { signZone, parseZoneKeys } from "@acl/netguard";
import { zoneOf, currentHeaders } from "./client";
import { config } from "./config";
import type { Session } from "./session-store";

const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

/** The only upstream calls the BFF will make. Everything else is refused: not an open proxy. */
export const ROUTES: readonly { method: string; path: RegExp }[] = [
  { method: "GET", path: /^\/me$/ },
  { method: "GET", path: /^\/case-files$/ },
  { method: "POST", path: /^\/case-files$/ },
  { method: "GET", path: new RegExp(`^/case-files/${UUID}$`) },
  { method: "PATCH", path: new RegExp(`^/case-files/${UUID}$`) },
  { method: "DELETE", path: new RegExp(`^/case-files/${UUID}$`) },
  { method: "POST", path: new RegExp(`^/case-files/${UUID}/submit$`) },
  { method: "POST", path: new RegExp(`^/case-files/${UUID}/approve$`) },
  { method: "GET", path: new RegExp(`^/case-files/${UUID}/export$`) },
  // auditor endpoints (the API refuses everyone else; these entries only make them reachable through the BFF)
  { method: "GET", path: /^\/audit-log$/ },
  { method: "GET", path: /^\/audit-log\/export$/ },
  { method: "GET", path: /^\/audit-log\/checkpoints$/ },
  { method: "GET", path: /^\/audit-log\/verify$/ },
];

/** Query parameters that may be forwarded, per path. Everything else is refused (never silently passed on). */
export const QUERY_KEYS: Readonly<Record<string, readonly string[]>> = {
  "/audit-log": ["from", "to", "actor", "resource", "action", "effect", "limit", "cursor"],
  "/audit-log/export": ["from", "to", "actor", "resource", "action", "effect", "cursor", "format"],
};

export const allowed = (method: string, path: string): boolean => ROUTES.some((r) => r.method === method && r.path.test(path));

const MAX_BODY = 64 * 1024;
const MAX_RESPONSE = 2 * 1024 * 1024;
const TIMEOUT_MS = 10_000;

export interface ApiResult {
  status: number;
  body: string;
  contentType: string;
  /** RFC 6750 / 9470 challenge from the API, passed through so the UI can start a step-up */
  wwwAuthenticate: string | null;
  retryAfter: string | null;
  /** true when the API asked for a stronger authentication (RFC 9470) */
  stepUp: boolean;
  /** `X-Audit-Proof` of an audit export, passed through unchanged (base64 JSON) */
  proof: string | null;
}

export class ProxyRefused extends Error {
  constructor(readonly status: number) {
    super("refused");
  }
}

async function readCapped(res: Response, max: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel();
      throw new ProxyRefused(502);
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Calls the NestJS API with the session's access token. Builds the request from scratch: no cookies, no browser headers, fixed host
 * from configuration, path and method from the allow-list, no redirects followed, size and time limits.
 * `breakGlass` is the ONLY way the break-glass header is sent (the dedicated route sets it; the generic proxy never does).
 */
export async function apiFetch(session: Session, method: string, path: string, opts: { json?: unknown; breakGlass?: string; query?: Record<string, string | undefined> } = {}): Promise<ApiResult> {
  if (!allowed(method, path)) throw new ProxyRefused(404);
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(opts.query ?? {})) {
    if (v === undefined || v === "") continue;
    if (!(QUERY_KEYS[path] ?? []).includes(k) || v.length > 200) throw new ProxyRefused(400); // unknown or oversized parameter: refuse, do not forward
    qs.set(k, v);
  }
  const headers: Record<string, string> = { authorization: `Bearer ${session.tokens.accessToken}`, accept: "application/json" };
  let body: string | undefined;
  if (opts.json !== undefined) {
    body = JSON.stringify(opts.json);
    if (Buffer.byteLength(body) > MAX_BODY) throw new ProxyRefused(413);
    headers["content-type"] = "application/json";
  }
  // the client's network zone, signed for this user: the API believes a zone from nobody else (no key configured: none sent, the API assumes unmanaged)
  const ring = config().zoneKeys;
  if (ring) {
    const h = await currentHeaders();
    headers["x-acl-zone"] = signZone(parseZoneKeys(ring), h ? zoneOf(h) : "unmanaged", session.userSub, Math.floor(Date.now() / 1000));
  }
  if (opts.breakGlass !== undefined) headers["x-break-glass-justification"] = opts.breakGlass.trim().slice(0, 500);

  const res = await fetch(`${config().apiBase}${path}${qs.size ? `?${qs}` : ""}`, { method, headers, body, redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS), cache: "no-store" });
  if (res.status >= 300 && res.status < 400) throw new ProxyRefused(502);
  const text = await readCapped(res, MAX_RESPONSE);
  const www = res.headers.get("www-authenticate");
  return {
    status: res.status,
    body: text,
    contentType: ((t) => (t === "application/json" || t === "text/csv" || t === "application/x-ndjson" ? t : "text/plain"))(res.headers.get("content-type")?.split(";")[0]),
    proof: res.headers.get("x-audit-proof"),
    wwwAuthenticate: www,
    retryAfter: res.headers.get("retry-after"),
    stepUp: res.status === 403 && (www ?? "").includes("insufficient_user_authentication"),
  };
}

export const MAX_PROXY_BODY = MAX_BODY;
