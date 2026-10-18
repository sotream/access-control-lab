// Servers and a scripted "browser" for the BFF tests: real Next.js (production build), real API, real Postgres, real Keycloak.
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import { fileURLToPath } from "node:url";
import { createApp } from "../../../apps/api/src/app.js";
import { loadConfig } from "../../../apps/api/src/config.js";
import { JsonLogger } from "../../../apps/api/src/http/logger.js";
import { decrypt, encrypt, parseKeyRing, sha256 } from "../../../apps/web/src/server/crypto";
import { Jar, formAction, nextOtp, PASSWORD, REALM_URL, step } from "../../identity/src/kc.js";
import { TEST_DB, adminPool, appUrl, withDb } from "../../api-db/src/db.js";

export const WEB = "http://127.0.0.1:3000";
export const API_PORT = 3001;
const WEB_DIR = fileURLToPath(new URL("../../../apps/web/", import.meta.url));

const env = (n: string) => {
  const v = process.env[n];
  if (!v) throw new Error(`missing env ${n} (copy .env.example to .env)`);
  return v;
};

/** a dev-only secret (>= 32 bytes) the "reverse proxy" of the tests proves itself with */
export const PROXY_SECRET = "dev-only-proxy-secret-0123456789abcdef";
export const MANAGED_NET = "10.1.0.0/16";
/** headers the real reverse proxy would add for a client at this address */
export const viaProxy = (ip: string): Record<string, string> => ({ "x-acl-proxy-secret": PROXY_SECRET, "x-acl-client-ip": ip });

export const SESSION_KEYS = () => env("SESSION_ENCRYPTION_KEYS");
export const adminDb = () => adminPool();

// ---------------------------------------------------------------- API

export async function startApi() {
  const logs: string[] = [];
  const cfg = loadConfig({ KEYCLOAK_ISSUER: REALM_URL, DATABASE_URL: appUrl(), AUDIT_HMAC_KEYS: env("AUDIT_HMAC_KEYS"), AUDIT_CHECKPOINT_SECONDS: "0", ZONE_SIGNING_KEYS: env("ZONE_SIGNING_KEYS"), ATTACHMENT_DIR: join(mkdtempSync(join(tmpdir(), "acl-bff-attachments-")), "store"), THROTTLE_LIMIT: "100000", AUTH_FAIL_LIMIT: "10000" });
  const app = await createApp(cfg, { logger: new JsonLogger((l) => logs.push(l)), clock: () => Date.UTC(2026, 9, 17, 12, 0, 0) });
  await app.listen(API_PORT, "127.0.0.1");
  return { logs, stop: () => app.close() };
}

// ---------------------------------------------------------------- web (next start)

export interface WebServer {
  url: string;
  logs: string[];
  stop(): Promise<void>;
}

export async function startWeb(over: Record<string, string> = {}): Promise<WebServer> {
  if (!existsSync(`${WEB_DIR}.next/BUILD_ID`)) throw new Error("apps/web is not built: run `pnpm --filter @acl/web build` first");
  const logs: string[] = [];
  const child: ChildProcess = spawn(process.execPath, [`${WEB_DIR}node_modules/next/dist/bin/next`, "start", "-H", "127.0.0.1", "-p", "3000"], {
    cwd: WEB_DIR,
    env: {
      ...process.env,
      NODE_ENV: "production",
      WEB_ORIGIN: WEB,
      KEYCLOAK_ISSUER: REALM_URL,
      API_BASE_URL: `http://127.0.0.1:${API_PORT}`,
      WEB_DATABASE_URL: withDb(env("WEB_DATABASE_URL"), TEST_DB),
      COOKIE_SECURE: "false",
      HSTS_ENABLED: "false",
      ZONE_SIGNING_KEYS: env("ZONE_SIGNING_KEYS"),
      MANAGED_CIDRS: MANAGED_NET,
      TRUSTED_PROXY_SECRET: PROXY_SECRET,
      // generous: the flows below log in dozens of times from one address; the limit tests start their own server with small values
      RATE_AUTH_PER_MINUTE: "10000",
      RATE_USER_PER_MINUTE: "100000",
      RATE_IP_PER_MINUTE: "100000",
      ...over,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout?.on("data", (d) => logs.push(String(d)));
  child.stderr?.on("data", (d) => logs.push(String(d)));
  let exited = false;
  child.on("exit", () => (exited = true));
  for (let i = 0; i < 100; i++) {
    if (exited) throw new Error(`next exited early:\n${logs.join("")}`);
    if (i === 99) child.kill("SIGKILL");
    try {
      if ((await fetch(`${WEB}/api/auth/session`)).status === 200) break;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 200));
    if (i === 99) throw new Error(`next did not start:\n${logs.join("")}`);
  }
  return {
    url: WEB,
    logs,
    stop: () =>
      new Promise<void>((resolve) => {
        if (exited) return resolve();
        child.on("exit", () => resolve());
        child.kill("SIGTERM");
        setTimeout(() => child.kill("SIGKILL"), 4000);
      }),
  };
}

// ---------------------------------------------------------------- stub upstream (records what the BFF sends)

export interface Seen {
  method: string;
  url: string;
  headers: IncomingHttpHeaders;
  body: string;
}

export async function startStubApi(handler: (seen: Seen) => { status: number; headers?: Record<string, string>; body?: string; delayMs?: number }) {
  const seen: Seen[] = [];
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const s = { method: req.method ?? "", url: req.url ?? "", headers: req.headers, body };
      seen.push(s);
      const r = handler(s);
      setTimeout(() => res.writeHead(r.status, { "content-type": "application/json", ...(r.headers ?? {}) }).end(r.body ?? "{}"), r.delayMs ?? 0);
    });
  });
  await new Promise<void>((r) => server.listen(API_PORT, "127.0.0.1", r));
  return { seen, stop: () => new Promise<void>((r) => server.close(() => r())) };
}

// ---------------------------------------------------------------- the scripted browser

export interface Resp {
  status: number;
  headers: Headers;
  text: string;
  location: string | null;
  setCookies: string[];
}

export class Browser {
  web = new Jar();
  kc = new Jar();

  /** one request to the web app with this browser's cookies; redirects are never followed */
  async req(path: string, init: { method?: string; headers?: Record<string, string>; body?: string | URLSearchParams } = {}): Promise<Resp> {
    const res = await fetch(`${WEB}${path}`, {
      method: init.method ?? "GET",
      redirect: "manual",
      headers: { ...(this.web.header() ? { cookie: this.web.header() } : {}), ...(init.headers ?? {}) },
      body: init.body,
    });
    this.web.absorb(res);
    return { status: res.status, headers: res.headers, text: await res.text(), location: res.headers.get("location"), setCookies: res.headers.getSetCookie() };
  }

  /** same-origin form POST as a browser would send it (Origin set by the browser) */
  post(path: string, fields: Record<string, string>, extra: Record<string, string> = {}): Promise<Resp> {
    return this.req(path, { method: "POST", headers: { origin: WEB, "sec-fetch-site": "same-origin", "content-type": "application/x-www-form-urlencoded", ...extra }, body: new URLSearchParams(fields) });
  }

  postJson(path: string, body: unknown, csrf: string, extra: Record<string, string> = {}): Promise<Resp> {
    return this.req(path, { method: "POST", headers: { origin: WEB, "sec-fetch-site": "same-origin", "content-type": "application/json", "x-csrf-token": csrf, ...extra }, body: JSON.stringify(body) });
  }

  /** plant a cookie as a script or a man in the middle might */
  setCookie(name: string, value: string): void {
    this.web.absorb(new Response(null, { headers: { "set-cookie": `${name}=${value}; Path=/` } }));
  }

  cookie(name: string): string | undefined {
    return this.web.header().split("; ").find((c) => c.startsWith(`${name}=`))?.slice(name.length + 1);
  }

  /** Sign in through the real flow. Returns the pieces so tests can attack individual steps. */
  async login(user: string, o: { returnTo?: string; acr?: string } = {}) {
    const q = new URLSearchParams();
    if (o.returnTo !== undefined) q.set("returnTo", o.returnTo);
    if (o.acr !== undefined) q.set("acr", o.acr);
    const start = await this.req(`/api/auth/login${q.size ? `?${q}` : ""}`);
    if (start.status !== 303 || !start.location) throw new Error(`login did not redirect: ${start.status}`);

    let r = await step(this.kc, start.location);
    if (r.status === 200) {
      const action = formAction(r.text);
      if (!action) throw new Error("no login form");
      r = await step(this.kc, action, { username: user, password: PASSWORD, credentialId: "" });
      if (r.status === 200 && r.text.includes('name="otp"')) r = await step(this.kc, formAction(r.text)!, { otp: await nextOtp(user) });
    }
    if (r.status !== 302 || !r.location?.startsWith(`${WEB}/api/auth/callback`)) throw new Error(`identity provider did not return to the app: ${r.status} ${r.location}`);
    const callbackUrl = r.location;
    const cb = await this.req(callbackUrl.slice(WEB.length));
    return { start, callbackUrl, callback: cb };
  }
}

/** parse the synchronizer token out of a page */
export const csrfOf = (html: string): string => {
  const m = /name="csrf" value="([^"]+)"/.exec(html);
  if (!m?.[1]) throw new Error("no csrf field in page");
  return m[1];
};

/** What the database holds for a browser's session cookie value (tokens decrypted with the dev key ring). */
export async function sessionRow(sid: string) {
  const pool = adminDb();
  try {
    const r = await pool.query("SELECT * FROM bff_sessions WHERE sid_hash = $1", [sha256(sid)]);
    const row = r.rows[0];
    if (!row) return undefined;
    const tokens = JSON.parse(decrypt(parseKeyRing(SESSION_KEYS()), row.key_id, row.tokens_enc, row.sid_hash).toString("utf8")) as { accessToken: string; refreshToken: string; idToken: string; accessExpiresAt: number };
    return { row, tokens };
  } finally {
    await pool.end();
  }
}

/** Make the stored access token look expired, as if time had passed, so the next request has to refresh. */
export async function forceExpire(sid: string): Promise<void> {
  const pool = adminDb();
  try {
    const cur = await sessionRow(sid);
    if (!cur) throw new Error("no such session");
    const ring = parseKeyRing(SESSION_KEYS());
    const sealed = encrypt(ring, Buffer.from(JSON.stringify({ ...cur.tokens, accessExpiresAt: Math.floor(Date.now() / 1000) - 10 })), cur.row.sid_hash);
    await pool.query("UPDATE bff_sessions SET tokens_enc = $2, key_id = $3 WHERE sid_hash = $1", [cur.row.sid_hash, sealed.data, sealed.keyId]);
  } finally {
    await pool.end();
  }
}

/** Overwrite stored tokens (for failure injection). */
export async function setTokens(sid: string, patch: Partial<{ accessToken: string; refreshToken: string; idToken: string; accessExpiresAt: number }>): Promise<void> {
  const pool = adminDb();
  try {
    const cur = await sessionRow(sid);
    if (!cur) throw new Error("no such session");
    const sealed = encrypt(parseKeyRing(SESSION_KEYS()), Buffer.from(JSON.stringify({ ...cur.tokens, ...patch })), cur.row.sid_hash);
    await pool.query("UPDATE bff_sessions SET tokens_enc = $2, key_id = $3 WHERE sid_hash = $1", [cur.row.sid_hash, sealed.data, sealed.keyId]);
  } finally {
    await pool.end();
  }
}

export { REALM_URL, Jar };
