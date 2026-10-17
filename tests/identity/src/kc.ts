// Scripted OIDC client for the Casefile realm. No browser: it drives the Keycloak login
// forms over HTTP, so the tests exercise the real authentication flow, not a shortcut grant.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash, createHmac, createPublicKey, createVerify, randomBytes } from "node:crypto";

try {
  process.loadEnvFile(new URL("../../../.env", import.meta.url));
} catch {
  // .env absent: variables must come from the environment
}

const need = (name: string): string => {
  const v = process.env[name];
  if (!v) throw new Error(`missing env ${name} (copy .env.example to .env)`);
  return v;
};

export const KC = process.env.KEYCLOAK_URL ?? "http://127.0.0.1:8080";
export const REALM_URL = `${KC}/realms/casefile`;
export const OIDC = `${REALM_URL}/protocol/openid-connect`;
export const CLIENT_ID = "casefile-web";
export const REDIRECT_URI = "http://127.0.0.1:3000/api/auth/callback";
export const CLIENT_SECRET = need("CASEFILE_WEB_SECRET");
export const PASSWORD = need("DEV_USER_PASSWORD");
export const TOTP_SECRET = need("DEV_TOTP_SECRET");

export type Claims = Record<string, unknown> & {
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  roles?: never;
  realm_access?: { roles: string[] };
  clearance?: string;
  unit?: string;
  compartments?: string[];
  acr?: string;
  amr?: string[];
  azp?: string;
};

const b64url = (b: Buffer) => b.toString("base64url");

export function pkce() {
  const verifier = b64url(randomBytes(32));
  return { verifier, challenge: b64url(createHash("sha256").update(verifier).digest()) };
}

/** RFC 6238 TOTP. Keycloak uses the UTF-8 bytes of the stored secret value as the HMAC key. */
export function totp(secret: string, at = Date.now(), offsetSteps = 0): string {
  const counter = Math.floor(at / 1000 / 30) + offsetSteps;
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", Buffer.from(secret, "utf8")).update(msg).digest();
  const o = h[h.length - 1]! & 0xf;
  const code = (h.readUInt32BE(o) & 0x7fffffff) % 1_000_000;
  return String(code).padStart(6, "0");
}

// persisted so that re-running the suite within a minute does not trip Keycloak's replay check
const STEP_DIR = new URL("../.cache/", import.meta.url); // gitignored, inside the package, not a shared temp dir
const STEP_FILE = new URL("otp-steps.json", STEP_DIR);
const lastStep = new Map<string, number>(
  (() => {
    try {
      return Object.entries(JSON.parse(readFileSync(STEP_FILE, "utf8")) as Record<string, number>);
    } catch {
      return [];
    }
  })(),
);

/**
 * Keycloak rejects a replayed TOTP (a step already used by that user) and accepts only the
 * current step +-1. So per user: use the first unused step, wait for the clock if none is left.
 */
export async function nextOtp(username: string): Promise<string> {
  for (;;) {
    const now = Math.floor(Date.now() / 1000 / 30);
    const step = Math.max(now, (lastStep.get(username) ?? 0) + 1);
    if (step <= now + 1) {
      lastStep.set(username, step);
      mkdirSync(STEP_DIR, { recursive: true });
      writeFileSync(STEP_FILE, JSON.stringify(Object.fromEntries(lastStep)));
      return totp(TOTP_SECRET, Date.now(), step - now);
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
}

export class Jar {
  private c = new Map<string, string>();
  absorb(res: Response) {
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const i = pair!.indexOf("=");
      const name = pair!.slice(0, i);
      const value = pair!.slice(i + 1);
      if (value === "" || /max-age=0/i.test(line)) this.c.delete(name);
      else this.c.set(name, value);
    }
  }
  header() {
    return [...this.c].map(([k, v]) => `${k}=${v}`).join("; ");
  }
}

export interface AuthParams {
  clientId?: string;
  redirectUri?: string;
  responseType?: string;
  challenge?: string | null; // null = omit code_challenge entirely
  method?: string;
  scope?: string;
  acrValues?: string;
}

export function authUrl(p: AuthParams = {}): string {
  const q = new URLSearchParams({
    client_id: p.clientId ?? CLIENT_ID,
    redirect_uri: p.redirectUri ?? REDIRECT_URI,
    response_type: p.responseType ?? "code",
    scope: p.scope ?? "openid",
    state: b64url(randomBytes(8)),
    nonce: b64url(randomBytes(8)),
  });
  if (p.challenge !== null) {
    q.set("code_challenge", p.challenge ?? pkce().challenge);
    q.set("code_challenge_method", p.method ?? "S256");
  }
  if (p.acrValues) q.set("acr_values", p.acrValues);
  return `${OIDC}/auth?${q}`;
}

/** One fetch, never follows redirects, keeps cookies. */
export async function step(jar: Jar, url: string, body?: Record<string, string>) {
  const res = await fetch(url, {
    method: body ? "POST" : "GET",
    redirect: "manual",
    headers: {
      cookie: jar.header(),
      ...(body ? { "content-type": "application/x-www-form-urlencoded" } : {}),
    },
    body: body ? new URLSearchParams(body) : undefined,
  });
  jar.absorb(res);
  const text = res.status === 200 || res.status >= 400 ? await res.text() : "";
  return { status: res.status, location: res.headers.get("location"), text };
}

export const formAction = (html: string): string | undefined =>
  /<form[^>]*action="([^"]+)"/.exec(html)?.[1]?.replaceAll("&amp;", "&");

export interface LoginResult {
  clientId: string;
  redirectUri: string;
  /** Keycloak demands TOTP enrolment (user has no authenticator yet) */
  enrolRequired?: boolean;
  /** form returned after the password step when a second factor is demanded */
  otpRequired: boolean;
  code?: string;
  verifier: string;
  jar: Jar;
  otpAction?: string;
}

/** Password step. Stops at the OTP form if Keycloak asks for one. */
export async function loginPassword(username: string, password = PASSWORD, p: AuthParams = {}): Promise<LoginResult> {
  const jar = new Jar();
  const { verifier, challenge } = pkce();
  const first = await step(jar, authUrl({ ...p, challenge }));
  const action = formAction(first.text);
  if (first.status !== 200 || !action) throw new Error(`no login form (status ${first.status})`);
  const second = await step(jar, action, { username, password, credentialId: "" });
  return finish(second, verifier, jar, p.clientId ?? CLIENT_ID, p.redirectUri ?? REDIRECT_URI);
}

function finish(
  r: { status: number; location: string | null; text: string },
  verifier: string,
  jar: Jar,
  clientId: string,
  redirectUri: string,
): LoginResult {
  const base = { clientId, redirectUri, verifier, jar };
  if (r.status === 302 && r.location?.startsWith(redirectUri)) {
    const code = new URL(r.location).searchParams.get("code");
    if (!code) throw new Error(`redirect without code: ${r.location}`);
    return { ...base, otpRequired: false, code };
  }
  if (r.status === 302 && r.location?.includes("execution=CONFIGURE_TOTP")) {
    return { ...base, otpRequired: false, enrolRequired: true };
  }
  if (r.status === 200 && r.text.includes('name="otp"')) {
    return { ...base, otpRequired: true, otpAction: formAction(r.text) };
  }
  throw new Error(`login did not complete: status ${r.status} location ${r.location}`);
}

export async function submitOtp(l: LoginResult, otp: string): Promise<{ result?: LoginResult; status: number; text: string }> {
  const r = await step(l.jar, l.otpAction!, { otp });
  if (r.status === 302) return { result: finish(r, l.verifier, l.jar, l.clientId, l.redirectUri), status: r.status, text: r.text };
  return { status: r.status, text: r.text };
}

export interface Tokens {
  access_token: string;
  refresh_token: string;
  id_token: string;
  expires_in: number;
}

export async function tokenRequest(form: Record<string, string>, opts: { public?: boolean } = {}) {
  const res = await fetch(`${OIDC}/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      ...(opts.public ? {} : { client_secret: CLIENT_SECRET }),
      ...form,
    }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

export async function exchange(l: LoginResult): Promise<Tokens> {
  const r = await tokenRequest({
    grant_type: "authorization_code",
    code: l.code!,
    redirect_uri: l.redirectUri,
    code_verifier: l.verifier,
    client_id: l.clientId,
  }, { public: l.clientId !== CLIENT_ID });
  if (r.status !== 200) throw new Error(`token exchange failed: ${JSON.stringify(r.body)}`);
  return r.body as unknown as Tokens;
}

/** Full login for any seed user, answering the OTP challenge when it appears. */
export async function login(username: string, p: AuthParams = {}): Promise<Tokens> {
  let l = await loginPassword(username, PASSWORD, p);
  if (l.otpRequired) {
    const o = await submitOtp(l, await nextOtp(username));
    if (!o.result) throw new Error(`otp rejected for ${username}`);
    l = o.result;
  }
  return exchange(l);
}

export function decode(jwt: string): { header: Record<string, unknown>; claims: Claims } {
  const [h, c] = jwt.split(".");
  return {
    header: JSON.parse(Buffer.from(h!, "base64url").toString()),
    claims: JSON.parse(Buffer.from(c!, "base64url").toString()),
  };
}

/** Signature check against the realm JWKS, RS256 only. Throws on mismatch. */
export async function verifySignature(jwt: string): Promise<void> {
  const [h, c, s] = jwt.split(".");
  const { header } = decode(jwt);
  if (header.alg !== "RS256") throw new Error(`unexpected alg ${String(header.alg)}`);
  const jwks = (await (await fetch(`${OIDC}/certs`)).json()) as { keys: (JsonWebKey & { kid: string })[] };
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("kid not in JWKS");
  const ok = createVerify("RSA-SHA256")
    .update(`${h}.${c}`)
    .verify(createPublicKey({ key: jwk, format: "jwk" }), Buffer.from(s!, "base64url"));
  if (!ok) throw new Error("bad signature");
}

export async function adminToken(): Promise<string> {
  const res = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "admin-cli",
      grant_type: "password",
      username: need("KEYCLOAK_ADMIN"),
      password: need("KEYCLOAK_ADMIN_PASSWORD"),
    }),
  });
  return ((await res.json()) as { access_token: string }).access_token;
}

export async function admin(path: string, init: RequestInit = {}) {
  const t = await adminToken();
  return fetch(`${KC}/admin/realms/casefile${path}`, {
    ...init,
    headers: { authorization: `Bearer ${t}`, "content-type": "application/json", ...(init.headers ?? {}) },
  });
}
