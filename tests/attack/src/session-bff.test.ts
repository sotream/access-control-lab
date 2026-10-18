// A-10..A-17: sessions, cookies, CSRF, the login redirects and the OIDC callback, attacked through the proxy like a browser-borne attacker would.
import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { FORM, form, idp, Jar, vault } from "./http.js";
import { bffLogin, CALLBACK, ISSUER, keycloakLogin, oidcTokens, tokenRequest } from "./kc.js";
import { bff, session } from "./sessions.js";
import { psql } from "./stack.js";

const SESSION = "__Host-casefile_session";
const PRE = "__Host-casefile_pre";
const same = { origin: "https://vault.localhost", "sec-fetch-site": "same-origin" };
const who = (jar: Jar) => vault("/api/auth/session", { jar }).then((r) => (r.json as { authenticated: boolean }).authenticated);

describe("A-10 refresh token replay", () => {
  it("a refresh token used twice kills the whole chain: the newer token dies too", async () => {
    const t = await oidcTokens("reviewer");
    const first = await tokenRequest({ grant_type: "refresh_token", refresh_token: t.refresh_token });
    expect(first.status).toBe(200);
    const newer = (first.json as { refresh_token: string }).refresh_token;
    expect(newer).not.toBe(t.refresh_token);
    expect((await tokenRequest({ grant_type: "refresh_token", refresh_token: t.refresh_token })).status, "the replayed one").toBe(400);
    expect((await tokenRequest({ grant_type: "refresh_token", refresh_token: newer })).status, "the legitimate successor after the replay").toBe(400);
  });
});

describe("A-11 session fixation", () => {
  it("a session cookie the attacker planted before the login is never adopted, and is worthless afterwards", async () => {
    const planted = randomBytes(32).toString("base64url");
    const jar = new Jar();
    jar.cookies.set(SESSION, planted);
    const start = await vault("/api/auth/login", { jar });
    const { location } = await keycloakLogin(start.location!, "unit-admin-alpha", new Jar());
    const cb = await vault(new URL(location!).pathname + new URL(location!).search, { jar });
    expect(cb.status).toBe(303);
    expect(jar.get(SESSION), "a new id was issued").not.toBe(planted);
    expect(await who(jar)).toBe(true);
    const attacker = new Jar();
    attacker.cookies.set(SESSION, planted);
    expect(await who(attacker), "the planted value opens nothing").toBe(false);
  });
});

describe("A-12 cookie tampering", () => {
  it("altered, truncated, extended, empty, foreign, injected and duplicated session cookies are all anonymous", async () => {
    const s = await session("analyst-official");
    const c = s.cookie;
    const flip = c.slice(0, -1) + (c.endsWith("A") ? "B" : "A");
    const variants = [flip, c.slice(0, 20), c + "A", c + c, "", c.toUpperCase(), c.replace(/[A-Za-z]/, "!"), randomBytes(32).toString("base64url"), "' OR '1'='1", "a".repeat(5000), "../../etc/passwd"];
    for (const v of variants) {
      const j = new Jar();
      j.cookies.set(SESSION, v);
      const r = await vault("/api/auth/session", { jar: j });
      expect((r.json as { authenticated?: boolean } | undefined)?.authenticated, `variant #${variants.indexOf(v)} (${v.length} chars)`).not.toBe(true);
      expect(r.status).toBeLessThan(500);
    }
    // another name for the same value: only the __Host- cookie is read
    for (const name of ["casefile_session", "session", "__Secure-casefile_session"]) {
      const r = await vault("/api/auth/session", { headers: { cookie: `${name}=${c}` } });
      expect((r.json as { authenticated: boolean }).authenticated, name).toBe(false);
    }
    // two cookies of the same name, the attacker's first: the first one wins and it is not valid
    const r = await vault("/api/auth/session", { headers: { cookie: `${SESSION}=${randomBytes(32).toString("base64url")}; ${SESSION}=${c}` } });
    expect((r.json as { authenticated: boolean }).authenticated).toBe(false);
  });
  it("the session cookie is host-only, HttpOnly, Secure, SameSite=Lax and opaque", async () => {
    const jar = new Jar();
    const start = await vault("/api/auth/login", { jar });
    const set = ([] as string[]).concat(start.headers["set-cookie"] ?? []).join("\n");
    expect(set).toMatch(/__Host-casefile_pre=/);
    expect(set).toMatch(/HttpOnly/i);
    expect(set).toMatch(/Secure/i);
    expect(set).toMatch(/SameSite=Lax/i);
    expect(set).not.toMatch(/Domain=/i);
  });
});

describe("A-13 logout", () => {
  it("only a POST with the token and the origin logs out; afterwards the old cookie is dead everywhere", async () => {
    const s = await bffLogin("platform-admin");
    expect((await vault("/api/auth/logout", { jar: s.jar })).status, "GET").toBe(405);
    expect((await vault("/api/auth/logout", { method: "POST", jar: s.jar, headers: { ...FORM, origin: "https://evil.example" }, body: form({ csrf: s.csrf }) })).status).toBe(403);
    expect(await who(s.jar), "still signed in after the forged attempts").toBe(true);
    const copy = s.jar.clone();
    const out = await vault("/api/auth/logout", { method: "POST", jar: s.jar, headers: { ...FORM, ...same }, body: form({ csrf: s.csrf }) });
    expect(out.status).toBe(303);
    expect(await who(copy), "the copied cookie after logout").toBe(false);
    expect((await vault("/bff/me", { jar: copy })).status).toBe(401);
  });
});

describe("A-14 CSRF: forged cross-site requests change nothing", () => {
  const count = () => Number(psql("SELECT count(*) FROM case_files WHERE title LIKE 'csrf-attack%'"));
  const variants: [string, Record<string, string>, boolean][] = [
    ["no Origin header", { "sec-fetch-site": "same-origin" }, true],
    ["Origin of another site", { origin: "https://evil.example", "sec-fetch-site": "cross-site" }, true],
    ["Origin null", { origin: "null" }, true],
    ["Origin with the right host on http", { origin: "http://vault.localhost" }, true],
    ["Origin with a sub-domain", { origin: "https://evil.vault.localhost" }, true],
    ["right Origin, cross-site fetch metadata", { origin: "https://vault.localhost", "sec-fetch-site": "cross-site" }, true],
    ["right Origin, same-site (sibling) fetch metadata", { origin: "https://vault.localhost", "sec-fetch-site": "same-site" }, true],
    ["right Origin and metadata, no token", { origin: "https://vault.localhost", "sec-fetch-site": "same-origin" }, false],
  ];
  it("every state-changing endpoint refuses every forged variant", async () => {
    const s = await session("unit-admin-alpha");
    const before = count();
    const endpoints: [string, (h: Record<string, string>, token: boolean) => Promise<{ status: number }>][] = [
      ["create form", (h, tok) => vault("/actions/case-files/create", { method: "POST", jar: s.jar, headers: { ...FORM, ...h }, body: form({ ...(tok ? { csrf: s.csrf } : {}), title: "csrf-attack form", body: "x", classification: "OFFICIAL", compartments: "" }) })],
      ["create JSON via the proxy", (h, tok) => vault("/bff/case-files", { method: "POST", jar: s.jar, headers: { "content-type": "application/json", ...(tok ? { "x-csrf-token": s.csrf } : {}), ...h }, body: JSON.stringify({ title: "csrf-attack json", classification: "OFFICIAL", compartments: [] }) })],
      ["logout", (h, tok) => vault("/api/auth/logout", { method: "POST", jar: s.jar, headers: { ...FORM, ...h }, body: form(tok ? { csrf: s.csrf } : {}) })],
    ];
    for (const [name, call] of endpoints) {
      for (const [label, h, withToken] of variants) {
        const r = await call(h, withToken);
        expect(r.status, `${name}: ${label}`).toBe(name === "logout" || r.status === 403 ? r.status : 403);
        expect([401, 403], `${name}: ${label}`).toContain(r.status);
      }
      // the token in the query string only, and another user's token
      const other = await session("reviewer");
      expect([401, 403]).toContain((await call({ origin: "https://vault.localhost", "sec-fetch-site": "same-origin" }, false)).status);
      const wrong = await vault("/actions/case-files/create?csrf=" + s.csrf, { method: "POST", jar: s.jar, headers: { ...FORM, ...same }, body: form({ csrf: other.csrf, title: "csrf-attack wrong", body: "x", classification: "OFFICIAL", compartments: "" }) });
      expect(wrong.status).toBe(403);
    }
    expect(await who(s.jar), "the session survived the forged logouts").toBe(true);
    expect(count()).toBe(before);
  });
  it("GET is never a state change: forms and actions answer 405 to a GET", async () => {
    const s = await session("unit-admin-alpha");
    for (const p of ["/actions/case-files/create", "/api/auth/logout", "/actions/audit/export"]) expect((await vault(p, { jar: s.jar })).status, p).toBe(405);
  });
  it("no CORS grant to any origin, on any route", async () => {
    for (const p of ["/api/auth/session", "/bff/me", "/bff/case-files"]) {
      const r = await vault(p, { headers: { origin: "https://evil.example" } });
      expect(r.headers["access-control-allow-origin"], p).toBeUndefined();
      const pre = await vault(p, { method: "OPTIONS", headers: { origin: "https://evil.example", "access-control-request-method": "POST" } });
      expect(pre.headers["access-control-allow-origin"], `${p} preflight`).toBeUndefined();
    }
  });
});

describe("A-15 open redirects", () => {
  it("whatever returnTo says, the browser ends up on a path of this site", async () => {
    const hostile = ["//evil.example", "https://evil.example", "/\\evil.example", "/%2f%2fevil.example", "javascript:alert(1)", "\\\\evil.example", "/..//evil.example", "http:evil.example", "/\t/evil.example", "/%0d%0aLocation: https://evil.example", "https://vault.localhost@evil.example", "//vault.localhost.evil.example", "/".padEnd(3000, "a"), "data:text/html,x"];
    for (const rt of hostile) {
      const jar = new Jar();
      const start = await vault(`/api/auth/login?${new URLSearchParams({ returnTo: rt })}`, { jar });
      const { location } = await keycloakLogin(start.location!, "reviewer", new Jar());
      const cb = await vault(new URL(location!).pathname + new URL(location!).search, { jar });
      const to = cb.location ?? "";
      expect(cb.status, rt).toBe(303);
      expect(new URL(to, "https://vault.localhost").origin, `${rt} -> ${to}`).toBe("https://vault.localhost");
      expect(to.startsWith("//") || to.includes("evil.example") || /^\w+:/.test(to.replace("https://vault.localhost", "")), `${rt} -> ${to}`).toBe(false);
    }
  });
  it("the identity provider refuses a foreign redirect_uri and a foreign post-logout redirect", async () => {
    for (const ru of ["https://evil.example/cb", "https://vault.localhost.evil.example/api/auth/callback", `${CALLBACK}/../x`, `${CALLBACK}?x=1`, "https://vault.localhost/api/auth/callback#x", "https://vault.localhost:444/api/auth/callback", "http://vault.localhost/api/auth/callback"]) {
      const q = new URLSearchParams({ client_id: "casefile-web", redirect_uri: ru, response_type: "code", scope: "openid", code_challenge: "x".repeat(43), code_challenge_method: "S256" });
      const r = await idp(`/realms/casefile/protocol/openid-connect/auth?${q}`);
      expect(r.status, ru).toBeGreaterThanOrEqual(400);
      expect(r.location ?? "", ru).not.toMatch(/evil/);
    }
    const t = await oidcTokens("reviewer");
    const out = await idp(`/realms/casefile/protocol/openid-connect/logout?${new URLSearchParams({ id_token_hint: t.id_token, post_logout_redirect_uri: "https://evil.example/", client_id: "casefile-web" })}`);
    expect(out.location ?? "").not.toMatch(/evil/);
  });
});

describe("A-16 login and callback manipulation", () => {
  async function attempt(user = "reviewer") {
    const jar = new Jar();
    const start = await vault("/api/auth/login", { jar });
    const authorize = new URL(start.location!);
    const { location } = await keycloakLogin(start.location!, user, new Jar());
    const cb = new URL(location!);
    return { jar, state: authorize.searchParams.get("state")!, code: cb.searchParams.get("code")!, query: cb.search, path: cb.pathname, issuer: cb.searchParams.get("iss") };
  }
  it("a callback is single use: replaying the same URL (with or without the same cookie) gives no second session", async () => {
    const a = await attempt();
    const jar2 = a.jar.clone();
    expect((await vault(a.path + a.query, { jar: a.jar })).status).toBe(303);
    expect(await who(a.jar)).toBe(true);
    const replay = await vault(a.path + a.query, { jar: jar2 });
    expect(replay.status).not.toBe(303);
    expect(await who(jar2)).toBe(false);
    expect((await vault(a.path + a.query, { jar: new Jar() })).status).not.toBe(303);
  });
  it("swapped state, missing state, missing code, foreign code, error parameter, wrong issuer: no session each time", async () => {
    const a = await attempt();
    const b = await attempt();
    const qs = (o: Record<string, string | undefined>) => "?" + new URLSearchParams(Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as Record<string, string>);
    const variants: [string, string][] = [
      ["state of another attempt", qs({ code: a.code, state: b.state, iss: ISSUER })],
      ["no state", qs({ code: a.code, iss: ISSUER })],
      ["no code", qs({ state: a.state, iss: ISSUER })],
      ["code of another attempt", qs({ code: b.code, state: a.state, iss: ISSUER })],
      ["garbage code", qs({ code: "x".repeat(40), state: a.state, iss: ISSUER })],
      ["error from the provider", qs({ error: "access_denied", state: a.state, iss: ISSUER })],
      ["wrong issuer", qs({ code: a.code, state: a.state, iss: "https://evil.example/realms/casefile" })],
      ["duplicate parameters", `?code=${a.code}&code=${b.code}&state=${a.state}&state=${b.state}&iss=${encodeURIComponent(ISSUER)}`],
      ["huge state", qs({ code: a.code, state: "s".repeat(10_000), iss: ISSUER })],
    ];
    for (const [label, q] of variants) {
      const j = a.jar.clone();
      const r = await vault(`/api/auth/callback${q}`, { jar: j });
      expect(r.status, label).toBeLessThan(500);
      expect(r.status, label).not.toBe(303);
      expect(await who(j), label).toBe(false);
    }
  });
  it("login CSRF: an attacker's callback URL delivered to a victim browser (no pre-auth cookie) logs nobody in", async () => {
    const attackerFlow = await attempt("unit-admin-beta");
    const victim = new Jar();
    const r = await vault(attackerFlow.path + attackerFlow.query, { jar: victim });
    expect(r.status).not.toBe(303);
    expect(await who(victim)).toBe(false);
    expect(victim.get(SESSION)).toBeUndefined();
  });
  it("tampered pre-auth cookie (state, nonce and verifier live in it) fails; so does a pre-auth cookie of another attempt", async () => {
    const a = await attempt();
    const b = await attempt();
    const pre = a.jar.get(PRE)!;
    for (const v of [pre.slice(0, -2) + (pre.endsWith("AA") ? "BB" : "AA"), pre.slice(0, 30), pre + "x", "x".repeat(300), b.jar.get(PRE)!]) {
      const j = new Jar();
      j.cookies.set(PRE, v);
      const r = await vault(a.path + a.query, { jar: j });
      expect(r.status).not.toBe(303);
      expect(await who(j)).toBe(false);
    }
  });
  it("the authorization request carries S256 PKCE, state and nonce, a fixed redirect URI, and no secrets", async () => {
    const start = await vault("/api/auth/login");
    const u = new URL(start.location!);
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("code_challenge")!.length).toBeGreaterThanOrEqual(43);
    expect(u.searchParams.get("state")!.length).toBeGreaterThanOrEqual(16);
    expect(u.searchParams.get("nonce")!.length).toBeGreaterThanOrEqual(16);
    expect(u.searchParams.get("redirect_uri")).toBe(CALLBACK);
    expect(u.searchParams.get("client_secret")).toBeNull();
    expect(start.location).not.toMatch(/code_verifier/);
  });
});

describe("A-17 the proxy to the API is not an open proxy", () => {
  it("paths that are not on the allow-list never reach the API, whatever the encoding", async () => {
    const s = await session("analyst-official");
    const paths = ["/me/../health", "/%2e%2e/health", "/..%2fhealth", "//evil.example/me", "/http://evil.example/", "/case-files/../audit-log", "/case-files/%2e%2e%2faudit-log", "/case-files/00000000-0000-4000-8000-000000000000/../../audit-log", "/audit-log%00", "/me%0d%0aX-Injected:1", "/me;/../health", "/case-files/not-a-uuid", "/@evil.example", "/health", "/__api/me", "/.env", "/actuator/env"];
    for (const p of paths) {
      const r = await bff(s, "GET", p);
      expect([308, 400, 403, 404], p).toContain(r.status); // 403: the path normalised onto an allowed route, where the role check refused it
      if (r.status === 308) expect(r.location ?? "", `${p}: a normalising redirect stays on this site`).toMatch(/^\/(?!\/)/);
      expect(r.text, p).not.toMatch(/stack|node_modules/);
    }
    for (const m of ["PUT", "TRACE", "PROPFIND", "PURGE", "BREW"]) {
      const r = await vault("/bff/me", { method: m, jar: s.jar, headers: same }).catch(() => ({ status: 0 }));
      expect([0, 400, 404, 405, 501], m).toContain(r.status);
    }
  });
  it("CRLF in a path or a header never splits a response", async () => {
    const r = await vault("/bff/me%0d%0aSet-Cookie:%20evil=1");
    expect(r.headers["set-cookie"]).toBeUndefined();
    const r2 = await vault("/api/auth/login?returnTo=/%0d%0aSet-Cookie:%20evil=1");
    expect(([] as string[]).concat(r2.headers["set-cookie"] ?? []).some((c) => c.startsWith("evil="))).toBe(false);
  });
});
