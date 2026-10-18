// All runtime configuration, parsed once and validated. Fails closed: a bad value stops startup.
import { assertStrongDbUrl, assertStrongKeyRing, parseZoneKeys, profileOf, resolveSecretFiles } from "@acl/netguard";
export const CONFIG = Symbol("CONFIG");

/** secrets that may be given as `NAME_FILE=/path` (container secrets) instead of `NAME` */
export const SECRET_ENV = ["DATABASE_URL", "AUDIT_DATABASE_URL", "AUDIT_HMAC_KEYS", "ZONE_SIGNING_KEYS"] as const;

export interface AppConfig {
  /** `production` only with ACL_ENV=production: then dev values, weak keys and missing secrets stop the start */
  profile: "production" | "development";
  /** exact `iss` value; also the base for the JWKS URL */
  issuer: string;
  jwksUri: string;
  /** every access token must list this in `aud` */
  audience: string;
  /** accepted `azp` (the client the token was issued to) */
  allowedAzp: readonly string[];
  /** clock tolerance for exp/nbf, seconds */
  clockSkewSeconds: number;
  /** minimum ms between JWKS refetches triggered by unknown `kid` (storm guard) */
  jwksCooldownMs: number;
  /** how long a fetched JWKS is trusted before refetch, ms */
  jwksMaxAgeMs: number;
  /**
   * Zone-signing key ring (`id:base64,...`, shared with the BFF). The network zone is believed only when it arrives in a header signed with one of
   * these keys for the token's subject; without a ring the zone is always "unmanaged". The socket address is never used (it is the BFF's).
   */
  zoneKeys: string | undefined;
  corsOrigins: readonly string[];
  /** postgres connection string of the application role; absent: the data layer is not mounted */
  databaseUrl: string | undefined;
  dbPoolMax: number;
  /** audit HMAC key ring (id:base64,...), required whenever the data layer is mounted */
  auditKeys: string | undefined;
  /** seconds between audit checkpoints written by the API (0 disables the scheduler) */
  auditCheckpointSeconds: number;
  /** where attachment bytes live (a dedicated volume, outside any web root) */
  attachmentDir: string;
  attachmentMaxBytes: number;
  /** `none`: development stub (everything clean; in production it refuses to answer, nothing becomes downloadable); `clamd`: INSTREAM over TCP */
  attachmentScanner: "none" | "clamd";
  clamdHost: string;
  clamdPort: number;
  /** address the server binds; loopback unless a container needs its private-network interface */
  host: string;
  bodyLimit: string;
  /** general rate limit: requests per window per authenticated subject (public routes: per client address) */
  throttleLimit: number;
  throttleWindowMs: number;
  /** failed authentications tolerated per window per client address before 429 */
  authFailLimit: number;
  authFailWindowMs: number;
}

type Env = Record<string, string | undefined>;

function int(env: Env, name: string, def: number, min: number, max: number): number {
  const raw = env[name];
  if (raw === undefined || raw === "") return def;
  if (!/^\d+$/.test(raw)) throw new Error(`${name} must be a non-negative integer`);
  const n = Number(raw);
  if (n < min || n > max) throw new Error(`${name} must be between ${min} and ${max}`);
  return n;
}

function list(env: Env, name: string, def: string): string[] {
  return (env[name] ?? def)
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function scanner(v: string | undefined): "none" | "clamd" {
  if (v === undefined || v === "" || v === "none") return "none";
  if (v === "clamd") return "clamd";
  throw new Error("ATTACHMENT_SCANNER must be none or clamd");
}

export function loadConfig(raw: Env = process.env): AppConfig {
  const env = resolveSecretFiles(raw, SECRET_ENV);
  const profile = profileOf(env);
  const prod = profile === "production";
  const issuer = env.KEYCLOAK_ISSUER ?? "http://127.0.0.1:8080/realms/casefile";
  const url = new URL(issuer); // throws on garbage
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && (!loopback || prod)) {
    throw new Error(prod ? "KEYCLOAK_ISSUER must be https in production" : "KEYCLOAK_ISSUER must be https unless it points at loopback (dev only)");
  }
  if (url.search || url.hash || issuer.endsWith("/")) throw new Error("KEYCLOAK_ISSUER must be the bare issuer URL");

  const zoneKeys = env.ZONE_SIGNING_KEYS || undefined;
  if (zoneKeys !== undefined) parseZoneKeys(zoneKeys); // throws on a short or malformed key
  const databaseUrl = env.DATABASE_URL || undefined;
  if (databaseUrl !== undefined && !/^postgres(ql)?:\/\//.test(databaseUrl)) throw new Error("DATABASE_URL must be a postgres:// URL");
  const auditKeys = env.AUDIT_HMAC_KEYS || undefined;
  if (databaseUrl !== undefined && auditKeys === undefined) throw new Error("AUDIT_HMAC_KEYS is required when DATABASE_URL is set: no audit key, no audit, no service");
  if (prod) {
    if (databaseUrl === undefined) throw new Error("DATABASE_URL is required in production");
    if (zoneKeys === undefined) throw new Error("ZONE_SIGNING_KEYS is required in production (without it every export is refused as unmanaged)");
    assertStrongDbUrl("DATABASE_URL", databaseUrl);
    assertStrongKeyRing("AUDIT_HMAC_KEYS", auditKeys as string);
    assertStrongKeyRing("ZONE_SIGNING_KEYS", zoneKeys);
  }
  const corsOrigins = list(env, "CORS_ORIGINS", "");
  for (const o of corsOrigins) {
    if (o === "*" || !/^https?:\/\/[^/*]+$/.test(o)) throw new Error(`CORS_ORIGINS entry not an exact origin: ${o}`);
  }

  return {
    profile,
    issuer,
    jwksUri: env.KEYCLOAK_JWKS_URI ?? `${issuer}/protocol/openid-connect/certs`,
    audience: env.API_AUDIENCE ?? "casefile-api",
    allowedAzp: list(env, "ALLOWED_AZP", "casefile-web"),
    clockSkewSeconds: int(env, "CLOCK_SKEW_SECONDS", 5, 0, 60),
    jwksCooldownMs: int(env, "JWKS_COOLDOWN_MS", 30_000, 0, 3_600_000),
    jwksMaxAgeMs: int(env, "JWKS_MAX_AGE_MS", 600_000, 1_000, 86_400_000),
    zoneKeys,
    corsOrigins,
    databaseUrl,
    dbPoolMax: int(env, "DB_POOL_MAX", 10, 1, 50),
    auditKeys,
    auditCheckpointSeconds: int(env, "AUDIT_CHECKPOINT_SECONDS", 300, 0, 86_400),
    attachmentDir: env.ATTACHMENT_DIR ?? "./data/attachments",
    attachmentMaxBytes: int(env, "ATTACHMENT_MAX_BYTES", 5 * 1024 * 1024, 1024, 25 * 1024 * 1024),
    attachmentScanner: scanner(env.ATTACHMENT_SCANNER),
    clamdHost: env.CLAMD_HOST ?? "127.0.0.1",
    clamdPort: int(env, "CLAMD_PORT", 3310, 1, 65_535),
    host: env.API_HOST ?? "127.0.0.1",
    bodyLimit: env.BODY_LIMIT ?? "64kb",
    throttleLimit: int(env, "THROTTLE_LIMIT", 120, 1, 100_000),
    throttleWindowMs: int(env, "THROTTLE_WINDOW_MS", 60_000, 1_000, 3_600_000),
    authFailLimit: int(env, "AUTH_FAIL_LIMIT", 10, 1, 10_000),
    authFailWindowMs: int(env, "AUTH_FAIL_WINDOW_MS", 60_000, 1_000, 3_600_000),
  };
}
