import { describe, expect, it } from "vitest";
import { loadWebConfig } from "./config";
import { esc } from "./html";
import { allowed } from "./api";

const KEY = "dev-1:" + Buffer.alloc(32, 1).toString("base64");
const base = {
  WEB_ORIGIN: "http://127.0.0.1:3000",
  KEYCLOAK_ISSUER: "http://127.0.0.1:8080/realms/casefile",
  CASEFILE_WEB_SECRET: "s",
  API_BASE_URL: "http://127.0.0.1:3001",
  WEB_DATABASE_URL: "postgres://u:p@127.0.0.1:5432/db",
  SESSION_ENCRYPTION_KEYS: KEY,
  AUDIT_HMAC_KEYS: "audit-1:" + Buffer.alloc(32, 2).toString("base64"),
  COOKIE_SECURE: "false",
};

describe("web configuration fails closed", () => {
  it("parses a valid dev configuration", () => {
    const c = loadWebConfig(base);
    expect(c.cookieSecure).toBe(false);
    expect(c.allowInsecureIdp).toBe(true);
    expect(c.hsts).toBe(false);
    expect(c.idleSeconds).toBeLessThanOrEqual(c.absoluteSeconds);
  });
  it("secure cookies are the default", () => expect(loadWebConfig({ ...base, COOKIE_SECURE: undefined }).cookieSecure).toBe(true));
  it("https origin turns HSTS on by default and forbids insecure cookies", () => {
    const c = loadWebConfig({ ...base, WEB_ORIGIN: "https://vault.example", KEYCLOAK_ISSUER: "https://id.example/realms/casefile", API_BASE_URL: "https://api.example", COOKIE_SECURE: "true" });
    expect(c.hsts).toBe(true);
    expect(c.allowInsecureIdp).toBe(false);
    expect(() => loadWebConfig({ ...base, WEB_ORIGIN: "https://vault.example", KEYCLOAK_ISSUER: "https://id.example/realms/casefile", API_BASE_URL: "https://api.example", COOKIE_SECURE: "false" })).toThrow(/COOKIE_SECURE/);
  });
  it.each([
    ["missing origin", { WEB_ORIGIN: undefined }],
    ["origin with path", { WEB_ORIGIN: "http://127.0.0.1:3000/app" }],
    ["http origin off loopback", { WEB_ORIGIN: "http://vault.example" }],
    ["http issuer off loopback", { KEYCLOAK_ISSUER: "http://id.example/realms/casefile" }],
    ["http api off loopback", { API_BASE_URL: "http://api.example" }],
    ["api with path", { API_BASE_URL: "http://127.0.0.1:3001/v1" }],
    ["db url not postgres", { WEB_DATABASE_URL: "mysql://x" }],
    ["no key ring", { SESSION_ENCRYPTION_KEYS: undefined }],
    ["no client secret", { CASEFILE_WEB_SECRET: undefined }],
    ["bad boolean", { COOKIE_SECURE: "yes" }],
    ["idle timeout absurd", { SESSION_IDLE_SECONDS: "5" }],
    ["session cap zero", { MAX_SESSIONS_PER_USER: "0" }],
  ])("refuses %s", (_n, over) => expect(() => loadWebConfig({ ...base, ...over })).toThrow());
});

describe("proxy allow-list (no open proxy, no SSRF)", () => {
  const ID = "0f1e2d3c-4b5a-4968-8776-655443322110";
  it.each([
    ["GET", "/me"],
    ["GET", "/case-files"],
    ["POST", "/case-files"],
    ["GET", `/case-files/${ID}`],
    ["PATCH", `/case-files/${ID}`],
    ["DELETE", `/case-files/${ID}`],
    ["POST", `/case-files/${ID}/submit`],
    ["POST", `/case-files/${ID}/approve`],
    ["GET", `/case-files/${ID}/export`],
    ["GET", "/audit-log"],
    ["GET", "/audit-log/export"],
    ["GET", "/audit-log/checkpoints"],
    ["GET", "/audit-log/verify"],
  ])("%s %s is allowed", (m, p) => expect(allowed(m, p)).toBe(true));
  it.each([
    ["GET", "/health"],
    ["POST", "/me"],
    ["DELETE", "/case-files"],
    ["PUT", `/case-files/${ID}`],
    ["GET", "/case-files/"],
    ["GET", `/case-files/${ID}/`],
    ["GET", `/case-files/${ID}/submit`],
    ["GET", "/case-files/../me"],
    ["GET", `/case-files/${ID}/../${ID}`],
    ["GET", "//evil.example/me"],
    ["GET", "http://evil.example/me"],
    ["GET", "/case-files/x"],
    ["GET", `/case-files/${ID}%2f..%2f..`],
    ["GET", "/me?x=1"],
    ["GET", "/me#x"],
    ["GET", "/ME"],
    ["get", "/me"],
    ["POST", `/case-files/${ID}/export`],
    ["POST", "/audit-log"],
    ["DELETE", "/audit-log"],
    ["PUT", "/audit-log/export"],
    ["GET", "/audit-log/"],
    ["GET", "/audit-log/other"],
    ["GET", "/audit-log/export/x"],
    ["GET", "/audit-logs"],
  ])("%s %s is refused", (m, p) => expect(allowed(m, p)).toBe(false));
});

describe("esc", () => {
  it("neutralises markup and attribute breakouts", () => {
    expect(esc(`<script>alert("x")</script>`)).toBe("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;");
    expect(esc(`" onmouseover='x' \``)).toBe("&quot; onmouseover=&#39;x&#39; &#96;");
    expect(esc("a & b")).toBe("a &amp; b");
    expect(esc(5)).toBe("5");
  });
});
