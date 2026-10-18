// Harness self-check: the attacker's tooling works against the stack before any attack is trusted to mean something.
import { describe, expect, it } from "vitest";
import { api, vault } from "./http.js";
import { bffLogin, claimsOf, oidcTokens } from "./kc.js";

describe("harness", () => {
  it("reaches the BFF through the proxy and the API through the test-only route", async () => {
    expect((await vault("/api/auth/session")).status).toBe(200);
    expect((await api("/health")).status).toBe(200);
  });
  it("logs in through the BFF and obtains real tokens with an own code flow", async () => {
    const s = await bffLogin("analyst-official");
    expect(s.csrf.length).toBeGreaterThan(20);
    expect((await vault("/bff/me", { jar: s.jar })).status).toBe(200);
    const t = await oidcTokens("analyst-official");
    expect(claimsOf(t.access_token).azp).toBe("casefile-web");
    expect((await api("/me", { headers: { authorization: `Bearer ${t.access_token}` } })).status).toBe(200);
  });
});
