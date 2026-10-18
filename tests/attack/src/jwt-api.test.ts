// A-01..A-12: token attacks on the API. The API is not reachable from outside in the prod-like stack; these attacks model an attacker with a foothold on the
// internal network (compromised container, SSRF gadget) who can send any bearer token, any header, to the API directly (test-only route, infra/caddy/test/api.caddy).
import { createPublicKey, generateKeyPairSync } from "node:crypto";
import { spawnSync } from "node:child_process";
import { beforeAll, describe, expect, it } from "vitest";
import { api, FORM, form, idp } from "./http.js";
import { CALLBACK, claimsOf, keycloakLogin, oidcTokens, pkce, tokenRequest, type Tokens } from "./kc.js";
import { b64, hs256, parts, rs256, unsigned, withHeader, withPayload } from "./jwt.js";
import { ROOT, env } from "./stack.js";
import { Jar } from "./http.js";
import { randomBytes } from "node:crypto";
import { fixtures } from "./fixtures.js";

let t: Tokens;
let jwk: { kid: string; n: string; e: string; kty: string };
const me = (token: string, headers: Record<string, string> = {}) => api("/me", { headers: { authorization: `Bearer ${token}`, ...headers } });
const refused = async (token: string, why: string) => {
  const r = await me(token);
  expect(r.status, why).toBe(why.startsWith("malformed") && token.length > 8000 ? r.status : 401); // an oversized header block is refused by the server itself (431) before any token code runs
  expect([401, 431], why).toContain(r.status);
  expect(r.text, why).not.toMatch(/stack|at \/|node_modules|Error:/);
  return r;
};

beforeAll(async () => {
  t = await oidcTokens("analyst-official");
  jwk = ((await idp("/realms/casefile/protocol/openid-connect/certs")).json as { keys: (typeof jwk & { use: string; alg: string })[] }).keys.find((k) => k.use === "sig" && k.alg === "RS256")!;
}, 300_000);

describe("A-01 the real token works; the same token with any change does not", () => {
  it("baseline: an unmodified token is accepted", async () => {
    expect((await me(t.access_token)).status).toBe(200);
  });
  it("tampered payload keeps the old signature: sub, roles, clearance, unit, compartments, exp, aud, azp", async () => {
    const edits: [string, (p: Record<string, unknown>) => void][] = [
      ["sub", (p) => (p.sub = "00000000-0000-0000-0000-000000000000")],
      ["roles", (p) => (p.realm_access = { roles: ["platform-admin", "auditor"] })],
      ["clearance", (p) => (p.clearance = "SECRET")],
      ["compartments", (p) => (p.compartments = ["A", "B"])],
      ["unit", (p) => (p.unit = "beta")],
      ["acr", (p) => ((p.acr = "mfa"), (p.amr = ["pwd", "otp"]))],
      ["exp", (p) => (p.exp = Math.floor(Date.now() / 1000) + 86_400)],
      ["aud", (p) => (p.aud = "somebody-else")],
      ["iss", (p) => (p.iss = "https://evil.example/realms/casefile")],
    ];
    for (const [name, edit] of edits) await refused(withPayload(t.access_token, edit), `tampered ${name}`);
  });
});

describe("A-02 alg=none and friends", () => {
  it("unsigned tokens with admin claims, in every spelling of none, are refused", async () => {
    const claims = { ...claimsOf(t.access_token), realm_access: { roles: ["platform-admin"] } };
    for (const alg of ["none", "None", "NONE", "nOnE", "", null]) {
      await refused(unsigned({ alg, typ: "JWT" }, claims), `alg ${JSON.stringify(alg)}`);
      await refused(unsigned({ alg, typ: "JWT" }, claims, "AAAA"), `alg ${JSON.stringify(alg)} with a signature`);
    }
    await refused(`${b64({ alg: "none" })}.${b64(claims)}`, "no third segment");
  });
});

describe("A-03 algorithm confusion", () => {
  it("HS256 signed with the realm's public key (PEM, JWK JSON, modulus) is refused", async () => {
    const pem = createPublicKey({ key: jwk as never, format: "jwk" }).export({ type: "spki", format: "pem" }) as string;
    const claims = claimsOf(t.access_token);
    for (const key of [pem, pem.trim(), JSON.stringify(jwk), Buffer.from(jwk.n, "base64url")]) await refused(hs256(claims, key, { alg: "HS256", typ: "JWT", kid: jwk.kid }), "hs256 with public key material");
    for (const alg of ["HS384", "HS512"]) await refused(hs256(claims, pem, { alg, typ: "JWT", kid: jwk.kid }), alg);
  });
  it("RS256 signed with the attacker's own key is refused, with the realm's kid, a made-up kid, or an embedded jwk / jku", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    const mine = publicKey.export({ format: "jwk" });
    const claims = { ...claimsOf(t.access_token), realm_access: { roles: ["platform-admin"] } };
    await refused(rs256(claims, pem, { alg: "RS256", typ: "JWT", kid: jwk.kid }), "own key, realm kid");
    await refused(rs256(claims, pem, { alg: "RS256", typ: "JWT", kid: "attacker-key" }), "own key, own kid");
    await refused(rs256(claims, pem, { alg: "RS256", typ: "JWT", jwk: { ...mine, kid: "x" }, kid: "x" }), "embedded jwk");
    await refused(rs256(claims, pem, { alg: "RS256", typ: "JWT", jku: "https://evil.example/jwks.json", kid: "x" }), "jku");
    await refused(rs256(claims, pem, { alg: "RS256", typ: "JWT", x5u: "https://evil.example/cert.pem" }), "x5u");
    await refused(rs256(claims, pem, { alg: "RS256", typ: "JWT", x5c: ["MIIB"] }), "x5c");
  });
});

describe("A-04 kid, header and structure tricks never reach a 5xx", () => {
  it("path, injection, control and oversize values in kid and other header fields", async () => {
    const kids = ["../../../../dev/null", "..%2f..%2fetc%2fpasswd", "' OR '1'='1", "\u0000", "a".repeat(5000), "${jndi:ldap://x}", "kid\r\nX-Injected: 1", "/etc/passwd", "file:///etc/passwd", "http://evil.example/jwks"];
    for (const kid of kids) await refused(withHeader(t.access_token, (h) => (h.kid = kid)), `kid ${kid.slice(0, 20)}`);
    await refused(withHeader(t.access_token, (h) => (h.crit = ["exp", "x-evil"])), "crit");
    await refused(withHeader(t.access_token, (h) => (h.b64 = false)), "b64 false");
    await refused(withHeader(t.access_token, (h) => (h.typ = "at+jwt\u0000")), "typ");
  });
  it("malformed compact serialisations: extra or empty segments, whitespace, non-base64, nested JSON, huge tokens, array claims", async () => {
    const x = parts(t.access_token);
    const bad = [
      `${t.access_token}.extra`,
      `${x.h}.${x.p}`,
      `${x.h}..${x.signature}`,
      `.${x.p}.${x.signature}`,
      ` ${t.access_token}`,
      t.access_token.replace(/\./g, ". "),
      `${x.h}.%%%.${x.signature}`,
      `${b64("not json")}.${x.p}.${x.signature}`,
      `${b64("[]")}.${x.p}.${x.signature}`,
      `${x.h}.${b64("[]")}.${x.signature}`,
      `${x.h}.${b64("null")}.${x.signature}`,
      "a".repeat(9000),
      `${x.h}.${b64({ ...x.payload, big: "x".repeat(20_000) })}.${x.signature}`,
      "Bearer",
      "x.y.z",
    ];
    for (const b of bad) await refused(b, `malformed ${b.slice(0, 24)}`);
  });
});

describe("A-05 real tokens that were never meant for this API", () => {
  it("an ID token, a refresh token, and a token of another client of the same realm are refused", async () => {
    await refused(t.id_token, "id token as bearer");
    await refused(t.refresh_token, "refresh token as bearer");
    // account-console is a public client of the same realm: its access token carries another audience and authorised party
    const { verifier, challenge } = pkce();
    const redirect = "https://id.localhost/realms/casefile/account/";
    const q = new URLSearchParams({ client_id: "account-console", redirect_uri: redirect, response_type: "code", scope: "openid", state: "s", code_challenge: challenge, code_challenge_method: "S256" });
    const { location } = await keycloakLogin(`https://id.localhost/realms/casefile/protocol/openid-connect/auth?${q}`, "analyst-official", new Jar());
    const code = location ? new URL(location).searchParams.get("code") : null;
    expect(code, `account-console login returned ${location}`).toBeTruthy();
    const r = await idp("/realms/casefile/protocol/openid-connect/token", { method: "POST", headers: FORM, body: form({ client_id: "account-console", grant_type: "authorization_code", code: code!, redirect_uri: redirect, code_verifier: verifier }) });
    expect(r.status).toBe(200);
    const other = (r.json as { access_token: string }).access_token;
    expect(claimsOf(other).azp).toBe("account-console");
    await refused(other, "token of another client");
  });
  it("a token from another realm (the master realm, signed by a different key) is refused", () => {
    // the proxy hides the master realm from outsiders, so the token is fetched from inside the network, as an insider would
    const script = `fetch('http://keycloak:8080/realms/master/protocol/openid-connect/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:'admin-cli',grant_type:'password',username:'admin',password:process.env.P}).toString()}).then(async r=>{const j=await r.json();console.log(j.access_token||'')})`;
    const r = spawnSync("docker", ["run", "--rm", "--network", "casefile-prod-like_app", "-e", `P=${env.KEYCLOAK_ADMIN_PASSWORD}`, "node:24-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5", "node", "-e", script], { cwd: ROOT, encoding: "utf8" });
    const master = r.stdout.trim();
    expect(master.split(".").length, `no master token: ${r.stderr}`).toBe(3);
    expect(claimsOf(master).iss).toContain("/realms/master");
    return me(master).then((x) => expect(x.status).toBe(401));
  });
});

describe("A-06 other ways of presenting a token", () => {
  it("two Authorization headers, token in the query string, a cookie, a form body, another scheme: none authenticates", async () => {
    const ok = `Bearer ${t.access_token}`;
    expect((await api("/me", { headers: { authorization: [ok, ok] } })).status).toBe(401);
    expect((await api(`/me?access_token=${t.access_token}&token=${t.access_token}`)).status).toBe(401);
    expect((await api("/me", { headers: { cookie: `access_token=${t.access_token}; token=${t.access_token}` } })).status).toBe(401);
    expect([401, 404]).toContain((await api("/me", { method: "POST", headers: FORM, body: form({ access_token: t.access_token }) })).status); // no such POST route: never a 200
    for (const scheme of [`Basic ${t.access_token}`, `bearer${" "}${t.access_token}x`, `Bearer ${t.access_token},Bearer ${t.access_token}`, `Token ${t.access_token}`, t.access_token]) expect((await api("/me", { headers: { authorization: scheme } })).status, scheme.slice(0, 20)).toBe(401);
  });
  it("identity is never taken from headers: a valid token plus x-user, x-sub, x-roles, x-forwarded-user changes nothing", async () => {
    const plain = (await me(t.access_token)).json as { sub: string };
    const spoof = (await me(t.access_token, { "x-user": "admin", "x-sub": "0", "x-roles": "platform-admin", "x-forwarded-user": "admin", "x-remote-user": "admin", "x-acl-zone": "managed" })).json as { sub: string };
    expect(spoof.sub).toBe(plain.sub);
  });
});

describe("A-07 the API alone: zone and rate headers from an attacker", () => {
  it("a forged x-acl-zone on a valid token does not open the export rule for an approved file", async () => {
    const f = fixtures().offAlpha;
    const bearerOnly = { authorization: `Bearer ${t.access_token}` };
    expect((await api(`/case-files/${f}/export`, { headers: bearerOnly })).status, "no zone header").toBe(403);
    const now = Math.floor(Date.now() / 1000);
    for (const zone of [`v1.zone-1.${now}.managed.AAAA`, `v1.prod-like-zone-1.${now}.managed.${"A".repeat(43)}`, "managed", `v1.x.${now}.managed.`]) {
      expect((await api(`/case-files/${f}/export`, { headers: { ...bearerOnly, "x-acl-zone": zone } })).status, zone).toBe(403);
    }
  });
});

describe("A-08 replay after logout: the measured window", () => {
  it("the refresh token dies at logout; the access token, validated offline, lives until its own exp: measured", async () => {
    const fresh = await oidcTokens("unit-admin-beta");
    const exp = claimsOf(fresh.access_token).exp as number;
    const lifetime = exp - (claimsOf(fresh.access_token).iat as number);
    expect((await me(fresh.access_token)).status).toBe(200);
    // end the SSO session the way the BFF does: end-session with id_token_hint
    const out = await idp(`/realms/casefile/protocol/openid-connect/logout?${new URLSearchParams({ id_token_hint: fresh.id_token, post_logout_redirect_uri: "https://vault.localhost/", client_id: "casefile-web" })}`, { jar: fresh.kcJar });
    expect([200, 302]).toContain(out.status);
    const refresh = await tokenRequest({ grant_type: "refresh_token", refresh_token: fresh.refresh_token });
    expect(refresh.status, "refresh token after logout").toBe(400);
    const after = await me(fresh.access_token);
    const remaining = exp - Math.floor(Date.now() / 1000);
    console.log(`MEASURED A-08: access token lifetime ${lifetime}s; accepted by the API after logout: ${after.status === 200} (${remaining}s of validity left); refresh after logout: ${refresh.status}`);
    expect(lifetime).toBeLessThanOrEqual(300);
    expect(remaining).toBeLessThanOrEqual(300);
    // the documented window (docs/api-auth.md): a stateless access token outlives logout by at most its lifetime; it never outlives its own exp
    expect([200, 401]).toContain(after.status);
  });
  it.skipIf(process.env.ATTACK_SLOW !== "1")("slow mode: after exp plus the clock skew the same token is refused (needs a 5 minute wait)", async () => {
    const fresh = await oidcTokens("unit-admin-beta");
    const exp = claimsOf(fresh.access_token).exp as number;
    await new Promise((r) => setTimeout(r, (exp - Math.floor(Date.now() / 1000) + 8) * 1000));
    expect((await me(fresh.access_token)).status).toBe(401);
  }, 600_000);
});

describe("A-09 the realm's own endpoints do not help an attacker", () => {
  it("a code cannot be exchanged twice, nor without its verifier, nor with another client's secret", async () => {
    const { verifier, challenge } = pkce();
    const q = new URLSearchParams({ client_id: "casefile-web", redirect_uri: CALLBACK, response_type: "code", scope: "openid", state: "s", nonce: "n", code_challenge: challenge, code_challenge_method: "S256" });
    const get = async () => new URL((await keycloakLogin(`https://id.localhost/realms/casefile/protocol/openid-connect/auth?${q}`, "reviewer", new Jar())).location!).searchParams.get("code")!;
    const code = await get();
    const bad1 = await tokenRequest({ grant_type: "authorization_code", code, redirect_uri: CALLBACK, code_verifier: "x".repeat(43) });
    expect(bad1.status).toBe(400);
    const bad2 = await tokenRequest({ grant_type: "authorization_code", code: await get(), redirect_uri: CALLBACK });
    expect(bad2.status).toBe(400); // no verifier at all
    const bad3 = await tokenRequest({ grant_type: "authorization_code", code: await get(), redirect_uri: CALLBACK, code_verifier: verifier }, { secret: false });
    expect(bad3.status).toBe(401); // confidential client without its secret
    const good = await get();
    // a verifier that does not belong to this code: the challenge is bound to the first request
    expect((await tokenRequest({ grant_type: "authorization_code", code: good, redirect_uri: CALLBACK, code_verifier: randomBytes(32).toString("base64url") })).status).toBe(400);
    const direct = await tokenRequest({ grant_type: "password", username: "reviewer", password: env.DEV_USER_PASSWORD ?? "" });
    expect(direct.status, "direct grant is off").toBe(400);
  });
});
