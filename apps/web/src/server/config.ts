import { assertStrongDbUrl, assertStrongKeyRing, assertStrongSecret, parseNetworks, parseZoneKeys, profileOf, resolveSecretFiles } from "@acl/netguard";

/** secrets that may be given as `NAME_FILE=/path` (container secrets) instead of `NAME` */
export const SECRET_ENV = ["CASEFILE_WEB_SECRET", "WEB_DATABASE_URL", "SESSION_ENCRYPTION_KEYS", "AUDIT_HMAC_KEYS", "ZONE_SIGNING_KEYS", "TRUSTED_PROXY_SECRET"] as const;

// Runtime configuration of the BFF, parsed once on first use and validated. A bad value stops the request, never weakens a default.
export interface WebConfig {
  /** `production` only with ACL_ENV=production: then dev values, weak keys, plain http and missing secrets stop the start */
  profile: "production" | "development";
  /** exact origin the browser uses; the redirect and post-logout URIs are derived from it */
  origin: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** fixed upstream; the proxy can only ever talk to this host */
  apiBase: string;
  databaseUrl: string;
  /** AES-256-GCM key ring: first entry encrypts, all decrypt */
  keyRing: string;
  /** audit HMAC key ring (same value as the API): the BFF appends authentication events to the same chain */
  auditKeys: string;
  cookieSecure: boolean;
  hsts: boolean;
  idleSeconds: number;
  absoluteSeconds: number;
  maxSessionsPerUser: number;
  /** refresh when the access token has less than this many seconds left */
  refreshSkewSeconds: number;
  /** client networks (IPs or CIDRs) counted as the managed zone; empty: nobody is */
  managedCidrs: readonly string[];
  /** the reverse proxy proves itself with this secret before any forwarded client address is believed; absent: forwarded headers are ignored */
  trustedProxySecret: string | undefined;
  /** zone-signing ring shared with the API; absent: no zone is sent and the API treats every request as unmanaged */
  zoneKeys: string | undefined;
  /** per minute: login, callback and logout per client address */
  rateAuthPerMinute: number;
  /** per minute: authenticated traffic per user */
  rateUserPerMinute: number;
  /** per minute: all traffic per client address (backstop) */
  rateIpPerMinute: number;
  /** http to the identity provider is accepted only for loopback (dev) */
  allowInsecureIdp: boolean;
}

type Env = Record<string, string | undefined>;
const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]"]);

function need(env: Env, n: string): string {
  const v = env[n];
  if (!v) throw new Error(`missing configuration ${n}`);
  return v;
}

function int(env: Env, n: string, def: number, min: number, max: number): number {
  const raw = env[n];
  if (raw === undefined || raw === "") return def;
  if (!/^\d+$/.test(raw) || Number(raw) < min || Number(raw) > max) throw new Error(`${n} must be an integer between ${min} and ${max}`);
  return Number(raw);
}

function bool(env: Env, n: string, def: boolean): boolean {
  const raw = env[n];
  if (raw === undefined || raw === "") return def;
  if (raw !== "true" && raw !== "false") throw new Error(`${n} must be true or false`);
  return raw === "true";
}

export function loadWebConfig(raw: Env = process.env): WebConfig {
  const env = resolveSecretFiles(raw, SECRET_ENV);
  const profile = profileOf(env);
  const prod = profile === "production";
  const origin = need(env, "WEB_ORIGIN");
  const o = new URL(origin);
  if (o.origin !== origin) throw new Error("WEB_ORIGIN must be a bare origin (scheme, host, port)");
  const loopbackOrigin = LOOPBACK.has(o.hostname) && !prod;
  if (o.protocol !== "https:" && !loopbackOrigin) throw new Error("WEB_ORIGIN must be https unless it is loopback");

  const cookieSecure = bool(env, "COOKIE_SECURE", true);
  if (o.protocol === "https:" && !cookieSecure) throw new Error("COOKIE_SECURE=false is only allowed for a plain-http loopback origin");

  const issuer = need(env, "KEYCLOAK_ISSUER");
  const i = new URL(issuer);
  const loopbackIdp = LOOPBACK.has(i.hostname) && !prod;
  if (i.protocol !== "https:" && !loopbackIdp) throw new Error("KEYCLOAK_ISSUER must be https unless it is loopback");

  const api = new URL(need(env, "API_BASE_URL"));
  if (api.protocol !== "https:" && !(LOOPBACK.has(api.hostname) && !prod) && !(prod && env.API_INTERNAL_HTTP === "true")) throw new Error("API_BASE_URL must be https unless it is loopback (or, in production, API_INTERNAL_HTTP=true for a private network)");
  if (api.pathname !== "/" || api.search || api.hash) throw new Error("API_BASE_URL must be a bare origin");

  const databaseUrl = need(env, "WEB_DATABASE_URL");
  if (!/^postgres(ql)?:\/\//.test(databaseUrl)) throw new Error("WEB_DATABASE_URL must be a postgres:// URL");

  const managedCidrs = (env.MANAGED_CIDRS ?? "").split(",").map((x) => x.trim()).filter(Boolean);
  parseNetworks(managedCidrs); // throws on a typo
  const trustedProxySecret = env.TRUSTED_PROXY_SECRET || undefined;
  if (trustedProxySecret !== undefined && Buffer.byteLength(trustedProxySecret) < 32) throw new Error("TRUSTED_PROXY_SECRET must be at least 32 bytes");
  const zoneKeys = env.ZONE_SIGNING_KEYS || undefined;
  if (zoneKeys !== undefined) parseZoneKeys(zoneKeys);

  if (prod) {
    if (!trustedProxySecret) throw new Error("TRUSTED_PROXY_SECRET is required in production (without the proxy contract every client shares one rate-limit bucket and no one is managed)");
    if (!zoneKeys) throw new Error("ZONE_SIGNING_KEYS is required in production");
    if (!cookieSecure) throw new Error("COOKIE_SECURE must be true in production");
    assertStrongSecret("TRUSTED_PROXY_SECRET", trustedProxySecret);
    assertStrongSecret("CASEFILE_WEB_SECRET", need(env, "CASEFILE_WEB_SECRET"));
    assertStrongDbUrl("WEB_DATABASE_URL", databaseUrl);
    assertStrongKeyRing("SESSION_ENCRYPTION_KEYS", need(env, "SESSION_ENCRYPTION_KEYS"));
    assertStrongKeyRing("AUDIT_HMAC_KEYS", need(env, "AUDIT_HMAC_KEYS"));
    assertStrongKeyRing("ZONE_SIGNING_KEYS", zoneKeys);
  }

  return {
    profile,
    origin,
    issuer,
    clientId: env.OIDC_CLIENT_ID ?? "casefile-web",
    clientSecret: need(env, "CASEFILE_WEB_SECRET"),
    apiBase: api.origin,
    databaseUrl,
    keyRing: need(env, "SESSION_ENCRYPTION_KEYS"),
    auditKeys: need(env, "AUDIT_HMAC_KEYS"),
    cookieSecure,
    hsts: bool(env, "HSTS_ENABLED", o.protocol === "https:"),
    idleSeconds: int(env, "SESSION_IDLE_SECONDS", 1800, 60, 86_400),
    absoluteSeconds: int(env, "SESSION_ABSOLUTE_SECONDS", 28_800, 300, 604_800),
    maxSessionsPerUser: int(env, "MAX_SESSIONS_PER_USER", 5, 1, 50),
    refreshSkewSeconds: int(env, "REFRESH_SKEW_SECONDS", 30, 5, 120),
    managedCidrs,
    trustedProxySecret,
    zoneKeys,
    rateAuthPerMinute: int(env, "RATE_AUTH_PER_MINUTE", 20, 1, 10_000),
    rateUserPerMinute: int(env, "RATE_USER_PER_MINUTE", 300, 1, 100_000),
    rateIpPerMinute: int(env, "RATE_IP_PER_MINUTE", 600, 1, 100_000),
    allowInsecureIdp: i.protocol === "http:" && loopbackIdp,
  };
}

let cached: WebConfig | undefined;
/** lazily parsed so `next build` does not need runtime secrets */
export function config(): WebConfig {
  return (cached ??= loadWebConfig());
}
