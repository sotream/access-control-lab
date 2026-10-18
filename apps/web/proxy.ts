import { NextResponse, type NextRequest } from "next/server";

/**
 * Security headers for every response and the per-request CSP nonce.
 * Next.js reads the nonce from the request's CSP header and applies it to its own scripts; pages are dynamic so every render gets a fresh one.
 * No 'unsafe-inline', no 'unsafe-eval' in production (development needs eval for React's debug stacks), no third-party origins.
 */
export function proxy(request: NextRequest) {
  // a path with a percent-escape that is not valid UTF-8 (/cases/%ff%fe) makes Next.js's own routing throw and answer 500: a client error is a 400
  try {
    decodeURIComponent(new URL(request.url).pathname);
  } catch {
    return new NextResponse("Bad Request", { status: 400, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
  }
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const dev = process.env.NODE_ENV === "development";
  const hsts = process.env.HSTS_ENABLED === "true";
  const download = request.nextUrl.pathname.startsWith("/attachments/");
  const csp = [
    "default-src 'none'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    ...(hsts ? ["upgrade-insecure-requests"] : []),
    ...(download ? ["sandbox"] : []), // a downloaded file may never run as part of this origin
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("x-pathname", request.nextUrl.pathname); // for the navigation highlight; set here, so a client-sent value never gets through
  requestHeaders.set("content-security-policy", csp);

  const res = NextResponse.next({ request: { headers: requestHeaders } });
  res.headers.set("content-security-policy", csp);
  res.headers.set("x-content-type-options", "nosniff");
  res.headers.set("x-frame-options", "DENY");
  res.headers.set("referrer-policy", "no-referrer");
  res.headers.set("cross-origin-opener-policy", "same-origin");
  res.headers.set("cross-origin-resource-policy", "same-origin");
  res.headers.set("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()");
  res.headers.set("cache-control", "no-store"); // everything dynamic here is per user
  if (hsts) res.headers.set("strict-transport-security", "max-age=31536000; includeSubDomains");
  return res;
}

export const config = {
  matcher: [{ source: "/((?!_next/static|_next/image|favicon.ico).*)", missing: [{ type: "header", key: "next-router-prefetch" }, { type: "header", key: "purpose", value: "prefetch" }] }],
};
