import { describe, expect, it } from "vitest";
import { checkCsrf } from "./csrf";

const ORIGIN = "http://127.0.0.1:3000";
const TOKEN = "t".repeat(43);
const h = (o: Record<string, string>) => ({ get: (n: string) => o[n.toLowerCase()] ?? null });

describe("checkCsrf (T-05)", () => {
  it("passes with same Origin, no fetch metadata, matching token", () => {
    expect(checkCsrf(h({ origin: ORIGIN }), ORIGIN, TOKEN, TOKEN)).toBeUndefined();
  });
  it("passes with Sec-Fetch-Site same-origin", () => {
    expect(checkCsrf(h({ origin: ORIGIN, "sec-fetch-site": "same-origin" }), ORIGIN, TOKEN, TOKEN)).toBeUndefined();
  });
  it.each([
    ["missing Origin", {}, TOKEN, "origin_missing"],
    ["empty Origin", { origin: "" }, TOKEN, "origin_missing"],
    ["null Origin (sandboxed iframe, redirects)", { origin: "null" }, TOKEN, "origin_mismatch"],
    ["other host", { origin: "https://evil.example" }, TOKEN, "origin_mismatch"],
    ["same host, other port", { origin: "http://127.0.0.1:3001" }, TOKEN, "origin_mismatch"],
    ["same host, other scheme", { origin: "https://127.0.0.1:3000" }, TOKEN, "origin_mismatch"],
    ["suffix trick", { origin: `${ORIGIN}.evil.example` }, TOKEN, "origin_mismatch"],
    ["trailing slash", { origin: `${ORIGIN}/` }, TOKEN, "origin_mismatch"],
    ["cross-site fetch metadata", { origin: ORIGIN, "sec-fetch-site": "cross-site" }, TOKEN, "fetch_site"],
    ["same-site (sibling subdomain) fetch metadata", { origin: ORIGIN, "sec-fetch-site": "same-site" }, TOKEN, "fetch_site"],
    ["none (user typed the URL) on a POST", { origin: ORIGIN, "sec-fetch-site": "none" }, TOKEN, "fetch_site"],
    ["missing token", { origin: ORIGIN }, undefined, "token_missing"],
    ["empty token", { origin: ORIGIN }, "", "token_missing"],
    ["wrong token", { origin: ORIGIN }, "x".repeat(43), "token_mismatch"],
    ["token of another length", { origin: ORIGIN }, TOKEN.slice(1), "token_mismatch"],
    ["token with a suffix", { origin: ORIGIN }, TOKEN + "x", "token_mismatch"],
  ])("refuses: %s", (_n, headers, token, reason) => expect(checkCsrf(h(headers as Record<string, string>), ORIGIN, TOKEN, token as string | undefined)).toBe(reason));
});
