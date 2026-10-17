import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";

describe("config fails closed", () => {
  it("defaults are strict", () => {
    const c = loadConfig({});
    expect(c.audience).toBe("casefile-api");
    expect(c.allowedAzp).toEqual(["casefile-web"]);
    expect(c.corsOrigins).toEqual([]);
    expect(c.clockSkewSeconds).toBeLessThanOrEqual(10);
  });

  it.each([
    ["http issuer off loopback", { KEYCLOAK_ISSUER: "http://keycloak.example.com/realms/x" }],
    ["issuer with trailing slash", { KEYCLOAK_ISSUER: "http://127.0.0.1:8080/realms/casefile/" }],
    ["issuer with query", { KEYCLOAK_ISSUER: "https://k.example/realms/x?a=1" }],
    ["not a URL", { KEYCLOAK_ISSUER: "nope" }],
    ["wildcard CORS", { CORS_ORIGINS: "*" }],
    ["CORS with path", { CORS_ORIGINS: "https://a.example/x" }],
    ["clock skew too large", { CLOCK_SKEW_SECONDS: "3600" }],
    ["clock skew not a number", { CLOCK_SKEW_SECONDS: "abc" }],
    ["negative-looking value", { AUTH_FAIL_LIMIT: "-1" }],
  ])("rejects %s", (_n, env) => {
    expect(() => loadConfig(env)).toThrow();
  });

  it("accepts https issuer and exact origins", () => {
    const c = loadConfig({ KEYCLOAK_ISSUER: "https://id.example/realms/casefile", CORS_ORIGINS: "https://a.example, https://b.example:8443" });
    expect(c.corsOrigins).toEqual(["https://a.example", "https://b.example:8443"]);
    expect(c.jwksUri).toBe("https://id.example/realms/casefile/protocol/openid-connect/certs");
  });
});
