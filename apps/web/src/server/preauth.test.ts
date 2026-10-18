import { randomBytes } from "node:crypto";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

const KEY = `dev-1:${randomBytes(32).toString("base64")}`;
beforeAll(() => {
  Object.assign(process.env, {
    WEB_ORIGIN: "http://127.0.0.1:3000",
    KEYCLOAK_ISSUER: "http://127.0.0.1:8080/realms/casefile",
    CASEFILE_WEB_SECRET: "s",
    API_BASE_URL: "http://127.0.0.1:3001",
    WEB_DATABASE_URL: "postgres://u:p@127.0.0.1:5432/db",
    SESSION_ENCRYPTION_KEYS: KEY,
    AUDIT_HMAC_KEYS: `audit-1:${randomBytes(32).toString("base64")}`,
    COOKIE_SECURE: "false",
  });
});
afterEach(() => vi.useRealTimers());

describe("pre-auth cookie (state, nonce, PKCE verifier)", () => {
  const p = { state: "s".repeat(43), nonce: "n".repeat(43), verifier: "v".repeat(64), returnTo: "/cases" };

  it("round-trips", async () => {
    const { sealPreAuth, openPreAuth } = await import("./preauth");
    const sealed = sealPreAuth(p);
    expect(sealed).not.toContain(p.verifier);
    expect(openPreAuth(sealed)).toMatchObject(p);
  });

  it("is single-purpose: tampering, truncation, garbage and a wrong key are all refused", async () => {
    const { sealPreAuth, openPreAuth } = await import("./preauth");
    const sealed = sealPreAuth(p);
    const flip = (s: string, i: number) => s.slice(0, i) + (s[i] === "A" ? "B" : "A") + s.slice(i + 1);
    for (const bad of [flip(sealed, sealed.length - 3), flip(sealed, 8), sealed.slice(0, -4), "x", "", "a.b", `${sealed}AAAA`, sealed.replace("dev-1.", "dev-2."), undefined]) {
      expect(openPreAuth(bad), String(bad).slice(0, 20)).toBeUndefined();
    }
  });

  it("expires after five minutes", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-18T10:00:00Z"));
    const { sealPreAuth, openPreAuth } = await import("./preauth");
    const sealed = sealPreAuth(p);
    vi.setSystemTime(new Date("2026-10-18T10:04:59Z"));
    expect(openPreAuth(sealed)).toBeDefined();
    vi.setSystemTime(new Date("2026-10-18T10:05:01Z"));
    expect(openPreAuth(sealed)).toBeUndefined();
  });
});
