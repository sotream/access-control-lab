// Login, callback hardening, session cookie, fixation, caps, expiry, refresh, replay, logout (T-02..T-06, T-21) against the real stack.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CLIENT_ID, CLIENT_SECRET, OIDC, REDIRECT_URI, step } from "../../identity/src/kc.js";
import { Browser, adminDb, csrfOf, forceExpire, sessionRow, setTokens, startApi, startWeb, WEB, type WebServer } from "./harness.js";

let web: WebServer;
let api: Awaited<ReturnType<typeof startApi>>;
const admin = adminDb();

beforeAll(async () => {
  api = await startApi();
  web = await startWeb();
});
afterAll(async () => {
  await web?.stop();
  await api?.stop();
  await admin.end();
});

const sidOf = (b: Browser) => b.cookie("casefile_session")!;
const refreshAtKeycloak = async (refreshToken: string) => {
  const r = await fetch(`${OIDC}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: CLIENT_ID, client_secret: CLIENT_SECRET }) });
  return { status: r.status, body: (await r.json()) as Record<string, unknown> };
};
const attrs = (cookie: string) => cookie.split(";").slice(1).map((a) => a.trim().toLowerCase());

describe("login redirect: Authorization Code + PKCE S256 (T-02)", () => {
  it("sends the browser to Keycloak with state, nonce, S256 challenge and the exact redirect URI; verifier stays server side", async () => {
    const b = new Browser();
    const r = await b.req("/api/auth/login");
    expect(r.status).toBe(303);
    const u = new URL(r.location!);
    expect(`${u.origin}${u.pathname}`).toBe(`${OIDC}/auth`);
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("client_id")).toBe("casefile-web");
    expect(u.searchParams.get("redirect_uri")).toBe(REDIRECT_URI);
    expect(u.searchParams.get("scope")).toBe("openid");
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(u.searchParams.get("state")).toMatch(/^[A-Za-z0-9_-]{20,}$/);
    expect(u.searchParams.get("nonce")).toMatch(/^[A-Za-z0-9_-]{20,}$/);
    expect(u.searchParams.has("code_verifier")).toBe(false);
    expect(u.searchParams.has("acr_values")).toBe(false);
    expect(r.headers.get("cache-control")).toBe("no-store");
  });

  it("state, nonce and challenge differ on every attempt", async () => {
    const a = new URL((await new Browser().req("/api/auth/login")).location!);
    const b = new URL((await new Browser().req("/api/auth/login")).location!);
    for (const k of ["state", "nonce", "code_challenge"]) expect(a.searchParams.get(k)).not.toBe(b.searchParams.get(k));
  });

  it("pre-auth cookie: httpOnly, SameSite=Lax, Path=/, no Domain, five minutes, and opaque", async () => {
    const r = await new Browser().req("/api/auth/login");
    const pre = r.setCookies.find((c) => c.startsWith("casefile_pre=") && !c.startsWith("casefile_pre=;"))!;
    expect(pre).toBeDefined();
    const a = attrs(pre);
    expect(a).toContain("httponly");
    expect(a).toContain("samesite=lax");
    expect(a).toContain("path=/");
    expect(a).toContain("max-age=300");
    expect(a.some((x) => x.startsWith("domain"))).toBe(false);
    const value = pre.split(";")[0]!.split("=")[1]!;
    const loc = new URL(r.location!);
    expect(value).not.toContain(loc.searchParams.get("state")!);
  });

  it("acr_values is passed on only as mfa", async () => {
    const mfa = new URL((await new Browser().req("/api/auth/login?acr=mfa")).location!);
    expect(mfa.searchParams.get("acr_values")).toBe("mfa");
    for (const bad of ["pwd", "0", "mfa,pwd", "silver", "%00"]) {
      const u = new URL((await new Browser().req(`/api/auth/login?acr=${bad}`)).location!);
      expect(u.searchParams.has("acr_values"), bad).toBe(false);
    }
  });
});

describe("login completes and sets a hardened session cookie (T-04, T-05)", () => {
  it("session cookie: opaque, httpOnly, SameSite=Lax, Path=/, host-only; no token anywhere in the response", async () => {
    const b = new Browser();
    const { callback } = await b.login("analyst-official", { returnTo: "/session" });
    expect(callback.status).toBe(303);
    expect(callback.location).toBe(`${WEB}/session`);
    const c = callback.setCookies.find((x) => x.startsWith("casefile_session=") && !x.startsWith("casefile_session=;"))!;
    const a = attrs(c);
    expect(a).toContain("httponly");
    expect(a).toContain("samesite=lax");
    expect(a).toContain("path=/");
    expect(a.some((x) => x.startsWith("domain"))).toBe(false);
    expect(a.some((x) => x.startsWith("max-age="))).toBe(true);
    expect(callback.setCookies.some((x) => x.startsWith("casefile_pre=;") && /max-age=0/i.test(x))).toBe(true); // single use
    const sid = sidOf(b);
    expect(sid).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const stored = await sessionRow(sid);
    expect(stored).toBeDefined();
    expect(stored!.tokens.accessToken.split(".")).toHaveLength(3);
    const everything = callback.text + JSON.stringify([...callback.headers]) + callback.setCookies.join("\n");
    for (const t of [stored!.tokens.accessToken, stored!.tokens.refreshToken, stored!.tokens.idToken]) expect(everything).not.toContain(t);
    expect(sid).not.toContain(".");
  });

  it("the session page shows what the API knows and no token; /api/auth/session offers only the CSRF token", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    const page = await b.req("/session");
    expect(page.status).toBe(200);
    expect(page.text).toContain("analyst");
    expect(page.text).toContain("OFFICIAL");
    const s = await b.req("/api/auth/session");
    const j = JSON.parse(s.text) as Record<string, unknown>;
    expect(Object.keys(j).sort()).toEqual(["authenticated", "csrfToken", "expiresAt", "sub"]);
    expect(j.authenticated).toBe(true);
    const anon = JSON.parse((await new Browser().req("/api/auth/session")).text);
    expect(anon).toEqual({ authenticated: false });
  });

  it("no JWT-shaped string and none of the stored tokens appear in any page, API response, header or cookie, nor any static bundle", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    const { tokens } = (await sessionRow(sidOf(b)))!;
    const secrets = [tokens.accessToken, tokens.refreshToken, tokens.idToken, ...[tokens.accessToken, tokens.refreshToken, tokens.idToken].map((t) => t.split(".")[2] ?? "")].filter((x) => x.length > 20);
    const paths = ["/", "/session", "/cases", "/cases/new", "/api/auth/session", "/bff/me", "/bff/case-files", "/nope"];
    const seen: string[] = [];
    const bundles = new Set<string>();
    for (const p of paths) {
      const r = await b.req(p);
      seen.push(r.text, JSON.stringify([...r.headers]), r.setCookies.join("\n"));
      for (const m of r.text.matchAll(/\/_next\/static\/[^"')\s]+/g)) bundles.add(m[0]);
    }
    expect(bundles.size).toBeGreaterThan(0);
    for (const u of bundles) seen.push(await (await fetch(`${WEB}${u}`)).text());
    const blob = seen.join("\n");
    for (const s of secrets) expect(blob).not.toContain(s);
    expect(blob).not.toMatch(/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/);
    expect(blob).not.toContain(process.env.CASEFILE_WEB_SECRET!);
    expect(blob).not.toContain(process.env.SESSION_ENCRYPTION_KEYS!.split(":")[1]!);
    // and the server logs
    expect(web.logs.join("\n")).not.toContain(tokens.refreshToken);
    expect(web.logs.join("\n")).not.toContain(sidOf(b));
  });

  it("returnTo: only application paths survive; attacker URLs end up at /", async () => {
    for (const [input, expected] of [
      ["/cases", "/cases"],
      ["https://evil.example/", "/"],
      ["//evil.example", "/"],
      ["/\\evil.example", "/"],
      ["/%2f%2fevil.example", "/"],
      ["javascript:alert(1)", "/"],
      ["/cases?next=https://evil.example", "/cases"],
    ] as const) {
      const b = new Browser();
      const { callback } = await b.login("analyst-official", { returnTo: input });
      expect(callback.location, input).toBe(`${WEB}${expected}`);
    }
  });
});

describe("callback hardening (T-02, T-03)", () => {
  async function start(b = new Browser()) {
    const r = await b.req("/api/auth/login");
    const kc = await step(b.kc, r.location!);
    const action = /<form[^>]*action="([^"]+)"/.exec(kc.text)![1]!.replaceAll("&amp;", "&");
    const done = await step(b.kc, action, { username: "analyst-official", password: process.env.DEV_USER_PASSWORD!, credentialId: "" });
    return { b, callbackUrl: done.location!, pre: b.cookie("casefile_pre")! };
  }
  const noSession = (b: Browser) => expect(b.cookie("casefile_session")).toBeUndefined();

  it("no pre-auth cookie", async () => {
    const { callbackUrl } = await start();
    const stranger = new Browser();
    const r = await stranger.req(callbackUrl.slice(WEB.length));
    expect(r.status).toBe(400);
    noSession(stranger);
  });

  it("tampered or foreign pre-auth cookie", async () => {
    const { callbackUrl, pre } = await start();
    for (const value of [pre.slice(0, -2) + (pre.endsWith("A") ? "BB" : "AA"), "x", pre.replace(/^[^.]+\./, "dev-9."), ""]) {
      const b = new Browser();
      b.setCookie("casefile_pre", value);
      const r = await b.req(callbackUrl.slice(WEB.length));
      expect(r.status, value.slice(0, 12)).toBe(400);
      noSession(b);
    }
  });

  it("state mismatch, missing state, error response, wrong or missing iss", async () => {
    const { b, callbackUrl } = await start();
    const u = new URL(callbackUrl);
    const variants: [string, (x: URL) => void][] = [
      ["state changed", (x) => x.searchParams.set("state", "attacker-state")],
      ["state removed", (x) => x.searchParams.delete("state")],
      ["code removed", (x) => x.searchParams.delete("code")],
      ["error instead of code", (x) => (x.searchParams.delete("code"), x.searchParams.set("error", "access_denied"))],
      ["wrong iss (RFC 9207)", (x) => x.searchParams.set("iss", "https://evil.example/realms/casefile")],
    ];
    for (const [name, f] of variants) {
      const x = new URL(u);
      f(x);
      const r = await b.req(x.pathname + x.search);
      expect(r.status, name).toBe(400);
      noSession(b);
      b.setCookie("casefile_pre", (await start(new Browser())).pre); // a failed attempt cleared it; restore any valid-looking one
    }
  });

  it("a callback cannot be replayed, even with a copy of the pre-auth cookie", async () => {
    const { b, callbackUrl, pre } = await start();
    const first = await b.req(callbackUrl.slice(WEB.length));
    expect(first.status).toBe(303);
    const attacker = new Browser();
    attacker.setCookie("casefile_pre", pre);
    const again = await attacker.req(callbackUrl.slice(WEB.length));
    expect(again.status).toBe(400); // the authorization code is single use
    noSession(attacker);
  });

  it("a code from one login cannot be redeemed with the pre-auth cookie of another (state binds them)", async () => {
    const a = await start();
    const other = await start();
    const victim = new Browser();
    victim.setCookie("casefile_pre", other.pre);
    const r = await victim.req(a.callbackUrl.slice(WEB.length));
    expect(r.status).toBe(400);
    noSession(victim);
  });
});

describe("session fixation (T-05)", () => {
  it("a cookie planted before login is neither adopted nor valid afterwards", async () => {
    const planted = "A".repeat(43);
    const b = new Browser();
    b.setCookie("casefile_session", planted);
    await b.login("analyst-official");
    expect(sidOf(b)).not.toBe(planted);
    const attacker = new Browser();
    attacker.setCookie("casefile_session", planted);
    expect((await attacker.req("/bff/me")).status).toBe(401);
  });

  it("logging in again in the same browser destroys the old session id", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    const first = sidOf(b);
    await b.login("analyst-official");
    expect(sidOf(b)).not.toBe(first);
    expect(await sessionRow(first)).toBeUndefined();
    const old = new Browser();
    old.setCookie("casefile_session", first);
    expect((await old.req("/bff/me")).status).toBe(401);
  });

  it("tampered, random and malformed session cookies are anonymous", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    const sid = sidOf(b);
    for (const v of [sid.slice(0, -1) + (sid.endsWith("A") ? "B" : "A"), "B".repeat(43), sid + sid, "x", "' OR 1=1 --", sid.toLowerCase() === sid ? sid.toUpperCase() : sid.toLowerCase()]) {
      const t = new Browser();
      t.setCookie("casefile_session", v);
      expect((await t.req("/bff/me")).status, v.slice(0, 12)).toBe(401);
      const page = await t.req("/cases");
      expect(page.status).toBe(307); // protected pages redirect to sign-in
    }
  });
});

describe("limits and expiry (T-21)", () => {
  it("at most five concurrent sessions per user; the oldest browser is signed out", async () => {
    const browsers: Browser[] = [];
    for (let i = 0; i < 6; i++) {
      const b = new Browser();
      await b.login("reviewer");
      browsers.push(b);
    }
    const sub = JSON.parse((await browsers[5]!.req("/api/auth/session")).text).sub as string;
    expect((await admin.query("SELECT count(*)::int AS n FROM bff_sessions WHERE user_sub = $1", [sub])).rows[0].n).toBe(5);
    expect((await browsers[0]!.req("/bff/me")).status).toBe(401);
    expect((await browsers[5]!.req("/bff/me")).status).toBe(200);
  });

  it("idle and absolute timeouts end the session", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    expect((await b.req("/bff/me")).status).toBe(200);
    await admin.query("UPDATE bff_sessions SET idle_expires_at = now() - interval '1 second' WHERE sid_hash = sha256($1::bytea)", [Buffer.from(sidOf(b))]);
    expect((await b.req("/bff/me")).status).toBe(401);

    const c = new Browser();
    await c.login("analyst-official");
    await admin.query("UPDATE bff_sessions SET expires_at = now() - interval '1 second' WHERE sid_hash = sha256($1::bytea)", [Buffer.from(sidOf(c))]);
    expect((await c.req("/bff/me")).status).toBe(401);
  });
});

describe("token refresh with rotation and reuse detection (T-21)", () => {
  it("an expiring access token is refreshed transparently and the refresh token rotates", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    const before = (await sessionRow(sidOf(b)))!.tokens;
    await forceExpire(sidOf(b));
    const r = await b.req("/bff/me");
    expect(r.status).toBe(200);
    const after = (await sessionRow(sidOf(b)))!.tokens;
    expect(after.refreshToken).not.toBe(before.refreshToken);
    expect(after.accessToken).not.toBe(before.accessToken);
    expect(after.accessExpiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000) + 60);
    expect((await refreshAtKeycloak(before.refreshToken)).status).toBe(400); // the old one is dead
  });

  it("parallel requests on an expired token refresh exactly once (no double-refresh race)", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    await forceExpire(sidOf(b));
    const rs = await Promise.all(Array.from({ length: 8 }, () => b.req("/bff/me")));
    expect(rs.map((r) => r.status)).toEqual(Array(8).fill(200));
    expect((await b.req("/bff/me")).status).toBe(200); // still signed in: nobody reused a rotated token
  });

  it("a refresh token replayed by an attacker ends the session at the next refresh", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    const r0 = (await sessionRow(sidOf(b)))!.tokens.refreshToken;
    await forceExpire(sidOf(b));
    expect((await b.req("/bff/me")).status).toBe(200); // r0 -> r1
    const replay = await refreshAtKeycloak(r0); // the stolen, already used token
    expect(replay.status).toBe(400);
    await forceExpire(sidOf(b));
    expect((await b.req("/bff/me")).status).toBe(401); // Keycloak revoked the chain; the BFF ends the session
    expect(await sessionRow(sidOf(b))).toBeUndefined();
  });

  it("a refused refresh (corrupted token) ends the session instead of limping on", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    await setTokens(sidOf(b), { refreshToken: "not-a-real-token", accessExpiresAt: 1 });
    expect((await b.req("/bff/me")).status).toBe(401);
    expect(await sessionRow(sidOf(b))).toBeUndefined();
  });
});

describe("logout (T-06)", () => {
  it("POST with the CSRF token destroys every session of the user, ends the Keycloak session and clears the cookie", async () => {
    const a = new Browser();
    const second = new Browser();
    await a.login("analyst-official");
    await second.login("analyst-official");
    const csrf = csrfOf((await a.req("/")).text);
    const stored = (await sessionRow(sidOf(a)))!.tokens;
    const sidA = sidOf(a);

    const out = await a.post("/api/auth/logout", { csrf });
    expect(out.status).toBe(303);
    const end = new URL(out.location!);
    expect(`${end.origin}${end.pathname}`).toBe(`${OIDC}/logout`);
    expect(end.searchParams.get("id_token_hint")).toBe(stored.idToken);
    expect(end.searchParams.get("post_logout_redirect_uri")).toBe(`${WEB}/`);
    expect(out.setCookies.some((c) => c.startsWith("casefile_session=;") && /max-age=0/i.test(c))).toBe(true);

    expect(await sessionRow(sidA)).toBeUndefined();
    expect((await a.req("/bff/me")).status).toBe(401);
    expect((await second.req("/bff/me")).status).toBe(401); // revoke-all

    const kc = await step(a.kc, out.location!); // the browser follows the end-session redirect
    expect(kc.status).toBe(302);
    expect(kc.location).toContain(`${WEB}/`);
    expect((await refreshAtKeycloak(stored.refreshToken)).status).toBe(400); // Keycloak session is gone

    const again = await a.req("/api/auth/login");
    const sso = await step(a.kc, again.location!);
    expect(sso.status).toBe(200); // login form again: no single sign-on left
    expect(sso.text).toContain("kc-form-login");
  });

  it("only POST works; a wrong CSRF token keeps the session", async () => {
    const b = new Browser();
    await b.login("analyst-official");
    expect((await b.req("/api/auth/logout")).status).toBe(405);
    expect((await b.post("/api/auth/logout", { csrf: "wrong" })).status).toBe(403);
    expect((await b.post("/api/auth/logout", {})).status).toBe(403);
    expect((await b.req("/bff/me")).status).toBe(200);
  });

  it("without a session logout just clears and redirects home", async () => {
    const r = await new Browser().post("/api/auth/logout", { csrf: "x" });
    expect(r.status).toBe(303);
    expect(r.location).toBe(`${WEB}/`);
  });
});
