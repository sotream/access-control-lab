// Runtime configuration of the BFF, parsed once on first use and validated. A bad value stops the request, never weakens a default.
export interface WebConfig {
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

export function loadWebConfig(env: Env = process.env): WebConfig {
  const origin = need(env, "WEB_ORIGIN");
  const o = new URL(origin);
  if (o.origin !== origin) throw new Error("WEB_ORIGIN must be a bare origin (scheme, host, port)");
  const loopbackOrigin = LOOPBACK.has(o.hostname);
  if (o.protocol !== "https:" && !loopbackOrigin) throw new Error("WEB_ORIGIN must be https unless it is loopback");

  const cookieSecure = bool(env, "COOKIE_SECURE", true);
  if (o.protocol === "https:" && !cookieSecure) throw new Error("COOKIE_SECURE=false is only allowed for a plain-http loopback origin");

  const issuer = need(env, "KEYCLOAK_ISSUER");
  const i = new URL(issuer);
  const loopbackIdp = LOOPBACK.has(i.hostname);
  if (i.protocol !== "https:" && !loopbackIdp) throw new Error("KEYCLOAK_ISSUER must be https unless it is loopback");

  const api = new URL(need(env, "API_BASE_URL"));
  if (api.protocol !== "https:" && !LOOPBACK.has(api.hostname)) throw new Error("API_BASE_URL must be https unless it is loopback");
  if (api.pathname !== "/" || api.search || api.hash) throw new Error("API_BASE_URL must be a bare origin");

  const databaseUrl = need(env, "WEB_DATABASE_URL");
  if (!/^postgres(ql)?:\/\//.test(databaseUrl)) throw new Error("WEB_DATABASE_URL must be a postgres:// URL");

  return {
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
    allowInsecureIdp: i.protocol === "http:" && loopbackIdp,
  };
}

let cached: WebConfig | undefined;
/** lazily parsed so `next build` does not need runtime secrets */
export function config(): WebConfig {
  return (cached ??= loadWebConfig());
}
