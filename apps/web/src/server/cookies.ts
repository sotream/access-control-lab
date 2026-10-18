import { config } from "./config";

/** `__Host-` needs Secure, Path=/ and no Domain: it pins the cookie to this exact host and blocks overwrites from sibling subdomains. */
export const sessionCookieName = (): string => (config().cookieSecure ? "__Host-casefile_session" : "casefile_session");
export const themeCookieName = (): string => (config().cookieSecure ? "__Host-casefile_theme" : "casefile_theme");
export const breakGlassCookieName = (): string => (config().cookieSecure ? "__Host-casefile_bg" : "casefile_bg");
export const preAuthCookieName = (): string => (config().cookieSecure ? "__Host-casefile_pre" : "casefile_pre");

export interface CookieAttrs {
  httpOnly: true;
  secure: boolean;
  sameSite: "lax";
  path: "/";
  maxAge: number;
}

/** No Domain attribute on purpose (host-only). HttpOnly always. SameSite=Lax: Strict would drop the cookie on the return from the identity provider. */
export const cookieAttrs = (maxAgeSeconds: number): CookieAttrs => ({ httpOnly: true, secure: config().cookieSecure, sameSite: "lax", path: "/", maxAge: maxAgeSeconds });

export function parseCookies(header: string | null): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of (header ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i < 1) continue;
    const name = part.slice(0, i).trim();
    if (!out.has(name)) out.set(name, part.slice(i + 1).trim()); // first wins: a duplicate cannot override
  }
  return out;
}
