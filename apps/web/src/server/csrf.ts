import { safeEqual } from "./crypto";

export type CsrfFailure = "origin_missing" | "origin_mismatch" | "fetch_site" | "token_missing" | "token_mismatch";

/**
 * State-changing routes need ALL of: an Origin header equal to our origin, Sec-Fetch-Site (when the browser sends it) same-origin,
 * and the session's synchronizer token. SameSite=Lax cookies are the first layer, not the only one.
 */
export function checkCsrf(headers: { get(name: string): string | null }, origin: string, sessionToken: string, presentedToken: string | null | undefined): CsrfFailure | undefined {
  const o = headers.get("origin");
  if (!o) return "origin_missing";
  if (o !== origin) return "origin_mismatch";
  const site = headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin") return "fetch_site";
  if (!presentedToken) return "token_missing";
  return safeEqual(presentedToken, sessionToken) ? undefined : "token_mismatch";
}
