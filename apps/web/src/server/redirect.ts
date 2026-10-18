// return-to handling: only same-origin paths that the application itself serves, query and fragment dropped.
const ALLOWED = [/^\/$/, /^\/session$/, /^\/cases$/, /^\/cases\/new$/, /^\/cases\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(\/break-glass)?$/];
const DEFAULT = "/";
// control characters (including NUL), DEL, backslash, and any scheme-like or protocol-relative start
const FORBIDDEN = /[\u0000-\u001f\u007f\\]/;

function decodeFully(s: string): string | undefined {
  let cur = s;
  for (let i = 0; i < 4; i++) {
    let next: string;
    try {
      next = decodeURIComponent(cur);
    } catch {
      return undefined; // malformed escape: refuse
    }
    if (next === cur) return cur;
    cur = next;
  }
  return undefined; // still changing after four rounds: refuse
}

/** Returns a safe application path, or "/" for anything doubtful. Never returns a value with a host, scheme, query or fragment. */
export function safeReturnTo(raw: unknown): string {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 200) return DEFAULT;
  const decoded = decodeFully(raw);
  if (decoded === undefined) return DEFAULT;
  for (const candidate of [raw, decoded]) {
    if (FORBIDDEN.test(candidate)) return DEFAULT;
    if (!candidate.startsWith("/") || candidate.startsWith("//")) return DEFAULT;
  }
  let url: URL;
  try {
    url = new URL(raw, "http://placeholder.invalid");
  } catch {
    return DEFAULT;
  }
  if (url.origin !== "http://placeholder.invalid") return DEFAULT;
  const path = url.pathname;
  return ALLOWED.some((re) => re.test(path)) && path === decodeFully(path) ? path : DEFAULT;
}

/** acr_values the login route may ask for. Anything else is dropped. */
export function safeAcr(raw: unknown): "mfa" | undefined {
  return raw === "mfa" ? "mfa" : undefined;
}
