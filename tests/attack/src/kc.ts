// Scripted browser and OIDC client for the prod-like stack: the BFF login flow as a user would do it, and a plain authorization-code exchange
// (as the BFF itself does) to obtain real tokens that attacks can then tamper with, replay or misuse.
import { createHash, createHmac, randomBytes } from "node:crypto";
import { inject } from "vitest";
import { env } from "./stack.js";
import { FORM, form, idp, Jar, vault, type Resp } from "./http.js";

export const PASSWORD = env.DEV_USER_PASSWORD ?? "";
const TOTP_SECRET = env.DEV_TOTP_SECRET ?? "";
const CLIENT_SECRET = env.CASEFILE_WEB_SECRET ?? "";
export const CALLBACK = "https://vault.localhost/api/auth/callback";
export const ISSUER = "https://id.localhost/realms/casefile";
export const SEED_USERS = ["analyst-official", "analyst-secret-a", "analyst-secret-b", "reviewer", "unit-admin-alpha", "unit-admin-beta", "auditor", "platform-admin"] as const;
export type SeedUser = (typeof SEED_USERS)[number];

const b64url = (b: Buffer) => b.toString("base64url");
export const pkce = () => {
  const verifier = b64url(randomBytes(32));
  return { verifier, challenge: b64url(createHash("sha256").update(verifier).digest()) };
};

function totp(secret: string, at: number, offsetSteps: number): string {
  const counter = Math.floor(at / 1000 / 30) + offsetSteps;
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", Buffer.from(secret, "utf8")).update(msg).digest();
  const o = h[h.length - 1]! & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

// Keycloak refuses a TOTP step it has already seen for the user: take the first unused step, wait for the clock when none is left.
// Keycloak refuses a TOTP step it has already seen for the user: take the first unused step, wait for the clock when none is left. The state is per module instance;
// the sign-ins of the whole run are done once in global-setup.ts and the few later sign-ins of MFA users happen minutes after them in a single file.
const lastStep = new Map<string, number>();
let seeded = false;
/** the steps used so far, for the test runner to hand to the test files (global-setup.ts) */
export const otpSteps = (): Record<string, number> => Object.fromEntries(lastStep);
export async function nextOtp(user: string): Promise<string> {
  if (!seeded) {
    seeded = true;
    try {
      for (const [u, n] of Object.entries(inject("otpSteps"))) lastStep.set(u, Math.max(n, lastStep.get(u) ?? 0)); // inside a test file: continue after the sign-ins of the global setup
    } catch {
      /* the global setup itself: nothing to continue from */
    }
  }
  for (;;) {
    const now = Math.floor(Date.now() / 1000 / 30);
    const step = Math.max(now, (lastStep.get(user) ?? 0) + 1);
    if (step <= now + 1) {
      lastStep.set(user, step);
      return totp(TOTP_SECRET, Date.now(), step - now);
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
}

const formAction = (html: string): string | undefined => /<form[^>]*action="([^"]+)"/.exec(html)?.[1]?.replaceAll("&amp;", "&");
const local = (url: string) => {
  const u = new URL(url);
  return u.pathname + u.search;
};

/** Drives the Keycloak forms from an authorization URL until Keycloak redirects back (or refuses). Returns the final Location. */
export async function keycloakLogin(authorizeUrl: string, user: string, jar: Jar, o: { password?: string } = {}): Promise<{ location: string | null; resp: Resp }> {
  const first = await idp(local(authorizeUrl), { jar });
  const action = formAction(first.text);
  if (first.status !== 200 || !action) return { location: first.location, resp: first };
  let r = await idp(local(action), { method: "POST", jar, headers: FORM, body: form({ username: user, password: o.password ?? PASSWORD, credentialId: "" }) });
  if (r.status === 200 && r.text.includes('name="otp"')) r = await idp(local(formAction(r.text)!), { method: "POST", jar, headers: FORM, body: form({ otp: await nextOtp(user) }) });
  return { location: r.location, resp: r };
}

export interface BffSession {
  user: string;
  jar: Jar;
  csrf: string;
  cookie: string;
  sub: string;
}

const COOKIE = "__Host-casefile_session";

/** The whole browser flow through the proxy: BFF login, Keycloak form, callback. */
export async function bffLogin(user: string, o: { acr?: "mfa" | "pwd"; returnTo?: string } = {}): Promise<BffSession> {
  const jar = new Jar();
  const q = new URLSearchParams();
  if (o.acr) q.set("acr", o.acr);
  if (o.returnTo) q.set("returnTo", o.returnTo);
  const start = await vault(`/api/auth/login${q.size ? `?${q}` : ""}`, { jar });
  if (start.status !== 303 || !start.location) throw new Error(`login start: ${start.status}`);
  const kc = new Jar();
  const { location } = await keycloakLogin(start.location, user, kc);
  if (!location?.startsWith(CALLBACK)) throw new Error(`keycloak did not return to the callback for ${user}: ${location}`);
  const cb = await vault(local(location), { jar });
  if (cb.status !== 303) throw new Error(`callback for ${user}: ${cb.status} ${cb.text.slice(0, 120)}`);
  const sess = JSON.parse((await vault("/api/auth/session", { jar })).text) as { authenticated: boolean; sub: string; csrfToken: string };
  if (!sess.authenticated) throw new Error(`no session for ${user}`);
  return { user, jar, csrf: sess.csrfToken, cookie: jar.get(COOKIE) ?? "", sub: sess.sub };
}

export interface Tokens {
  access_token: string;
  refresh_token: string;
  id_token: string;
  expires_in: number;
}

/** A plain authorization-code login with our own PKCE pair, code intercepted at the redirect: real tokens, not the BFF's. */
export async function oidcTokens(user: string, o: { acr?: string } = {}): Promise<Tokens & { verifier: string; code: string; kcJar: Jar }> {
  const { verifier, challenge } = pkce();
  const q = new URLSearchParams({ client_id: "casefile-web", redirect_uri: CALLBACK, response_type: "code", scope: "openid", state: b64url(randomBytes(8)), nonce: b64url(randomBytes(8)), code_challenge: challenge, code_challenge_method: "S256" });
  if (o.acr) q.set("acr_values", o.acr);
  const kcJar = new Jar();
  const { location } = await keycloakLogin(`${ISSUER}/protocol/openid-connect/auth?${q}`, user, kcJar);
  const code = location ? new URL(location).searchParams.get("code") : null;
  if (!code) throw new Error(`no code for ${user}: ${location}`);
  const r = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: CALLBACK, code_verifier: verifier });
  if (r.status !== 200) throw new Error(`token exchange: ${r.text}`);
  return { ...(r.json as Tokens), verifier, code, kcJar };
}

export const tokenRequest = (fields: Record<string, string>, o: { secret?: boolean } = {}) =>
  idp("/realms/casefile/protocol/openid-connect/token", { method: "POST", headers: FORM, body: form({ client_id: "casefile-web", ...(o.secret === false ? {} : { client_secret: CLIENT_SECRET }), ...fields }) });

export const claimsOf = (jwt: string): Record<string, unknown> => JSON.parse(Buffer.from(jwt.split(".")[1]!, "base64url").toString("utf8"));
