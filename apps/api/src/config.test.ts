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

describe("production profile refuses development values and missing secrets (ACL_ENV=production)", () => {
  const key = (seed: number) => Buffer.from(Array.from({ length: 32 }, (_, i) => (i * seed + 11) % 251)).toString("base64");
  const good = {
    ACL_ENV: "production",
    KEYCLOAK_ISSUER: "https://id.example/realms/casefile",
    DATABASE_URL: "postgres://casefile_app:q9Xv2LmT8sWk4RzP7nYd@db.internal:5432/acl",
    AUDIT_HMAC_KEYS: `audit-2026:${key(37)}`,
    ZONE_SIGNING_KEYS: `zone-2026:${key(41)}`,
  };
  it("accepts a complete, strong configuration and reports the profile", () => {
    expect(loadConfig(good).profile).toBe("production");
    expect(loadConfig({}).profile).toBe("development");
  });
  it.each([
    ["typo in the profile", { ACL_ENV: "prod" }],
    ["http issuer on loopback", { KEYCLOAK_ISSUER: "http://127.0.0.1:8080/realms/casefile" }],
    ["no database", { DATABASE_URL: undefined }],
    ["no zone key ring", { ZONE_SIGNING_KEYS: undefined }],
    ["no audit key ring", { AUDIT_HMAC_KEYS: undefined }],
    ["dev database password", { DATABASE_URL: "postgres://casefile_app:dev-only-casefile-app-password@db:5432/acl" }],
    ["short database password", { DATABASE_URL: "postgres://casefile_app:short@db:5432/acl" }],
    ["dev audit key", { AUDIT_HMAC_KEYS: "audit-1:ZGV2LW9ubHktYXVkaXQtaG1hYy1rZXktMDEyMzQ1Njc=" }],
    ["dev zone key", { ZONE_SIGNING_KEYS: "zone-1:ZGV2LW9ubHktem9uZS1zaWduaW5nLWtleS0wMTIzNDU2" }],
    ["repeated-byte zone key", { ZONE_SIGNING_KEYS: `z:${Buffer.alloc(32, 5).toString("base64")}` }],
  ])("refuses %s", (_n, over) => {
    expect(() => loadConfig({ ...good, ...over })).toThrow();
  });
  it("error messages never carry a secret value", () => {
    const canary = "CANARY-SECRET-VALUE-8812";
    for (const env of [{ ...good, DATABASE_URL: `postgres://u:${canary}@h/db` }, { ...good, AUDIT_HMAC_KEYS: `dev-1:${Buffer.from(canary.padEnd(32, "x")).toString("base64")}` }, { ...good, ZONE_SIGNING_KEYS: Buffer.from(canary).toString("base64") }]) {
      try {
        loadConfig(env);
      } catch (e) {
        expect(String((e as Error).message)).not.toContain(canary);
      }
    }
  });
  it("NAME_FILE supplies a secret and cannot be combined with NAME", async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");
    const dir = mkdtempSync(join(tmpdir(), "acl-secret-"));
    writeFileSync(join(dir, "db"), `${good.DATABASE_URL}\n`);
    const { DATABASE_URL, ...rest } = good;
    expect(loadConfig({ ...rest, DATABASE_URL_FILE: join(dir, "db") }).databaseUrl).toBe(DATABASE_URL);
    expect(() => loadConfig({ ...rest, DATABASE_URL, DATABASE_URL_FILE: join(dir, "db") })).toThrow(/both set/);
  });
});
