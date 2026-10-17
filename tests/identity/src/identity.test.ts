/* eslint-disable @typescript-eslint/no-explicit-any -- untyped Keycloak admin REST payloads, test code only */
// Stage 2 identity evidence. Needs the compose stack running with the dev realm imported.
// Each describe names the threat IDs from docs/threat-model.md it covers.
import { beforeAll, describe, expect, it } from "vitest";
import {
  CLIENT_ID,
  OIDC,
  PASSWORD,
  REALM_URL,
  REDIRECT_URI,
  admin,
  authUrl,
  decode,
  Jar,
  exchange,
  formAction,
  login,
  loginPassword,
  nextOtp,
  pkce,
  step,
  submitOtp,
  tokenRequest,
  verifySignature,
  type Claims,
  type Tokens,
} from "./kc.js";

const SEED = {
  "analyst-official": { role: "analyst", clearance: "OFFICIAL", unit: "alpha", compartments: undefined },
  "analyst-secret-a": { role: "analyst", clearance: "SECRET", unit: "alpha", compartments: ["A"] },
  "analyst-secret-b": { role: "analyst", clearance: "SECRET", unit: "alpha", compartments: ["B"] },
  reviewer: { role: "reviewer", clearance: "CONFIDENTIAL", unit: "alpha", compartments: ["A"] },
  "unit-admin-alpha": { role: "unit-admin", clearance: "CONFIDENTIAL", unit: "alpha", compartments: undefined },
  "unit-admin-beta": { role: "unit-admin", clearance: "CONFIDENTIAL", unit: "beta", compartments: undefined },
  auditor: { role: "auditor", clearance: "OFFICIAL", unit: "hq", compartments: undefined },
  "platform-admin": { role: "platform-admin", clearance: "OFFICIAL", unit: "hq", compartments: undefined },
} as const;

const tokens = new Map<string, Tokens>();
const claimsOf = (u: string): Claims => decode(tokens.get(u)!.access_token).claims;
const APP_ROLES = ["analyst", "reviewer", "unit-admin", "auditor", "platform-admin"];

beforeAll(async () => {
  for (const u of Object.keys(SEED)) tokens.set(u, await login(u));
}, 240_000);

describe("access token claims (T-08, T-09, T-19)", () => {
  it.each(Object.entries(SEED))("%s carries role, clearance, unit, compartments, aud, iss, exp", (user, want) => {
    const c = claimsOf(user);
    expect(c.iss).toBe(REALM_URL);
    expect([c.aud].flat()).toContain("casefile-api");
    expect(c.azp).toBe(CLIENT_ID);
    expect(c.exp - c.iat).toBeLessThanOrEqual(300);
    expect(c.exp * 1000).toBeGreaterThan(Date.now());
    // exactly the one application role, nothing else from the app role set
    expect(c.realm_access?.roles.filter((r) => APP_ROLES.includes(r))).toEqual([want.role]);
    expect(c.clearance).toBe(want.clearance);
    expect(c.unit).toBe(want.unit);
    expect(c.compartments).toEqual(want.compartments);
  });

  it("is RS256 and verifies against the realm JWKS; a flipped payload byte does not", async () => {
    const jwt = tokens.get("reviewer")!.access_token;
    expect(decode(jwt).header.alg).toBe("RS256");
    await verifySignature(jwt);
    const [h, p, s] = jwt.split(".");
    const forged = Buffer.from(JSON.stringify({ ...decode(jwt).claims, clearance: "SECRET" })).toString("base64url");
    await expect(verifySignature(`${h}.${forged}.${s}`)).rejects.toThrow();
    await expect(verifySignature(`${h}.${p}.`)).rejects.toThrow();
  });

  it("does not leak identity claims the API does not need", () => {
    const c = claimsOf("reviewer");
    for (const k of ["email", "name", "preferred_username", "given_name", "family_name"]) expect(c).not.toHaveProperty(k);
  });
});

describe("MFA: TOTP for SECRET, acr/amr exposure (T-17, T-21)", () => {
  it("non-SECRET users reach a code with the password alone; acr=pwd, amr=[pwd]", () => {
    const c = claimsOf("analyst-official");
    expect(c.acr).toBe("pwd");
    expect(c.amr).toEqual(["pwd"]);
  });

  it("SECRET users get acr=mfa and amr contains pwd and otp", () => {
    for (const u of ["analyst-secret-a", "analyst-secret-b"]) {
      expect(claimsOf(u).acr).toBe("mfa");
      expect(claimsOf(u).amr).toEqual(["pwd", "otp"]);
    }
  });

  it("SECRET user cannot get a code with the password alone", async () => {
    const l = await loginPassword("analyst-secret-a");
    expect(l.otpRequired).toBe(true);
    expect(l.code).toBeUndefined();
  });

  it("a wrong TOTP is rejected", async () => {
    const l = await loginPassword("analyst-secret-b");
    const r = await submitOtp(l, "000000");
    expect(r.result).toBeUndefined();
    expect(r.status).toBe(200); // form shown again, no redirect
  });

  it("acr_values=pwd cannot downgrade the forced TOTP", async () => {
    const l = await loginPassword("analyst-secret-b", PASSWORD, { acrValues: "pwd" });
    expect(l.otpRequired).toBe(true);
    const o = await submitOtp(l, await nextOtp("analyst-secret-b"));
    const c = decode((await exchange(o.result!)).access_token).claims;
    expect(c.amr).toContain("otp");
  });

  it("step-up: acr_values=mfa asks a non-SECRET user for a second factor", async () => {
    const l = await loginPassword("reviewer", PASSWORD, { acrValues: "mfa" });
    // reviewer has no TOTP enrolled: Keycloak must force enrolment, never grant acr=mfa on the password
    expect(l.code).toBeUndefined();
    expect(l.otpRequired || l.enrolRequired).toBe(true);
  });
});

describe("clients (T-02, T-03, T-09)", () => {
  it("authorization request without PKCE is rejected", async () => {
    const r = await step(new Jar(), authUrl({ challenge: null }));
    expect(r.status).toBe(302);
    const loc = new URL(r.location!);
    expect(loc.searchParams.get("error")).toBe("invalid_request");
    expect(loc.searchParams.get("code")).toBeNull();
  });

  it("PKCE method plain is rejected", async () => {
    const r = await step(new Jar(), authUrl({ method: "plain", challenge: "x".repeat(43) }));
    expect(r.status).toBe(302);
    expect(new URL(r.location!).searchParams.get("error")).toBe("invalid_request");
  });

  it.each([
    ["other host", "http://evil.example/api/auth/callback"],
    ["path suffix", `${REDIRECT_URI}/evil`],
    ["path prefix", "http://127.0.0.1:3000/api/auth"],
    ["wildcard-ish query", `${REDIRECT_URI}/..%2Fevil`],
    ["other port", "http://127.0.0.1:3999/api/auth/callback"],
  ])("redirect URI %s is rejected without redirecting", async (_n, uri) => {
    const r = await step(new Jar(), authUrl({ redirectUri: uri }));
    expect(r.status).toBe(400);
    expect(r.location).toBeNull();
  });

  it("wrong PKCE verifier cannot redeem a code", async () => {
    const l = await loginPassword("analyst-official");
    const r = await tokenRequest({
      grant_type: "authorization_code",
      code: l.code!,
      redirect_uri: REDIRECT_URI,
      code_verifier: pkce().verifier,
    });
    expect(r.status).toBe(400);
    expect(r.body.error).toBe("invalid_grant");
  });

  it("an authorization code is single use", async () => {
    const l = await loginPassword("analyst-official");
    await exchange(l);
    const again = await tokenRequest({
      grant_type: "authorization_code",
      code: l.code!,
      redirect_uri: REDIRECT_URI,
      code_verifier: l.verifier,
    });
    expect(again.status).toBe(400);
  });

  it("implicit flow (response_type=token) is rejected", async () => {
    const r = await step(new Jar(), authUrl({ responseType: "token" }));
    // Keycloak answers with an error in the fragment (or a 400 page); never with a token
    expect(r.location ?? "").not.toContain("access_token");
    expect(r.status === 400 || (r.location ?? "").includes("error=")).toBe(true);
  });

  it("direct grant (password) is disabled on casefile-web", async () => {
    const r = await tokenRequest({ grant_type: "password", username: "reviewer", password: PASSWORD });
    expect(r.status).toBe(400);
    expect(r.body.error).toBe("unauthorized_client");
  });

  it("casefile-api has no login flow at all", async () => {
    const r = await step(new Jar(), authUrl({ clientId: "casefile-api" }));
    expect(r.location ?? "").not.toMatch(/[?&]code=/);
    expect(r.status).toBeGreaterThanOrEqual(400);
  });

  it("client credentials grant is disabled on casefile-web", async () => {
    const r = await tokenRequest({ grant_type: "client_credentials" });
    expect(r.status).toBeGreaterThanOrEqual(400);
    expect(r.body).not.toHaveProperty("access_token");
  });
});

describe("refresh token rotation and reuse detection (T-21)", () => {
  it("rotates on use; the old refresh token is dead; reuse kills the new one too", async () => {
    const t0 = await login("analyst-official");
    const first = await tokenRequest({ grant_type: "refresh_token", refresh_token: t0.refresh_token });
    expect(first.status).toBe(200);
    const t1 = first.body as unknown as Tokens;
    expect(t1.refresh_token).not.toBe(t0.refresh_token);

    const replay = await tokenRequest({ grant_type: "refresh_token", refresh_token: t0.refresh_token });
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");

    // after detected reuse the legitimate holder's chain is also revoked
    const afterReplay = await tokenRequest({ grant_type: "refresh_token", refresh_token: t1.refresh_token });
    expect(afterReplay.status).toBe(400);
  });
});

describe("attributes are admin-only (T-19)", () => {
  const ACCOUNT = { clientId: "account-console", redirectUri: `${REALM_URL}/account/` };

  // one attribute per request: a combined request would be rejected as a whole for the first
  // read-only field, which would hide a misconfiguration of the others
  it.each([
    ["clearance", ["SECRET"]],
    ["unit", ["hq"]],
    ["compartments", ["A", "B"]],
  ])("a user cannot change own %s through the Account API", async (attr, value) => {
    // real self-service path: the user logs in to the account console client and calls the Account API
    const t = await exchange(await loginPassword("analyst-official", PASSWORD, ACCOUNT));
    const auth = { authorization: `Bearer ${t.access_token}`, "content-type": "application/json", accept: "application/json" };
    const me = await fetch(`${REALM_URL}/account/`, { headers: auth });
    expect(me.status).toBe(200); // the token is accepted by the Account API, so the next call is a fair test
    const attempt = await fetch(`${REALM_URL}/account/`, {
      method: "POST",
      headers: auth,
      body: JSON.stringify({
        username: "analyst-official",
        email: "analyst-official@casefile.invalid",
        firstName: "analyst-official",
        lastName: "Dev",
        attributes: { [attr]: value },
      }),
    });
    expect([200, 204, 400, 403]).toContain(attempt.status);
    const [u] = await admin(`/users?username=analyst-official&exact=true`).then((r) => r.json() as Promise<Record<string, any>[]>);
    const want = SEED["analyst-official"] as Record<string, unknown>;
    expect(u!.attributes[attr]).toEqual(want[attr] === undefined ? undefined : [want[attr]]);
  });

  it("a user token does not open the admin API", async () => {
    const t = tokens.get("analyst-official")!;
    const r = await fetch(KC_ADMIN_USERS, { headers: { authorization: `Bearer ${t.access_token}` } });
    expect([401, 403]).toContain(r.status);
  });
});

describe("realm hardening as configured (T-18, T-20, T-22)", () => {
  it("brute-force protection locks an account after repeated failures", async () => {
    const [u] = (await admin(`/users?username=lockout-victim&exact=true`).then((r) => r.json())) as { id: string }[];
    await admin(`/attack-detection/brute-force/users/${u!.id}`, { method: "DELETE" });
    for (let i = 0; i < 6; i++) await loginPasswordRaw("lockout-victim", "wrong-password-" + i);
    // correct password is now refused too
    const res = await loginPasswordRaw("lockout-victim", PASSWORD);
    expect(res.status).toBe(200); // login form re-rendered, no redirect
    expect(res.location).toBeNull();
    await admin(`/attack-detection/brute-force/users/${u!.id}`, { method: "DELETE" });
  });

  it("realm settings match the intended baseline", async () => {
    const r = (await (await admin("")).json()) as Record<string, any>;
    expect(r.bruteForceProtected).toBe(true);
    expect(r.registrationAllowed).toBe(false);
    expect(r.sslRequired).toBe("external");
    expect(r.accessTokenLifespan).toBeLessThanOrEqual(300);
    expect(r.revokeRefreshToken).toBe(true);
    expect(r.refreshTokenMaxReuse).toBe(0);
    expect(r.passwordPolicy).toMatch(/length\((\d+)\)/);
    expect(Number(/length\((\d+)\)/.exec(r.passwordPolicy)![1])).toBeGreaterThanOrEqual(12);
    expect(r.browserFlow).toBe("browser-casefile");
  });

  it("casefile-web is confidential, standard flow only, PKCE S256 required, exact redirect", async () => {
    const [c] = (await (await admin("/clients?clientId=casefile-web")).json()) as Record<string, any>[];
    expect(c!.publicClient).toBe(false);
    expect(c!.standardFlowEnabled).toBe(true);
    expect(c!.implicitFlowEnabled).toBe(false);
    expect(c!.directAccessGrantsEnabled).toBe(false);
    expect(c!.serviceAccountsEnabled).toBe(false);
    expect(c!.attributes["pkce.code.challenge.method"]).toBe("S256");
    expect(c!.redirectUris).toEqual([REDIRECT_URI]);
    expect(c!.redirectUris.join()).not.toContain("*");
    expect(c!.webOrigins).toEqual([]);
  });

  it("no client in the realm allows the password grant", async () => {
    const all = (await (await admin("/clients")).json()) as { clientId: string; enabled: boolean; directAccessGrantsEnabled: boolean; implicitFlowEnabled: boolean }[];
    for (const c of all.filter((x) => x.enabled)) {
      expect(c.directAccessGrantsEnabled, `${c.clientId} direct grant`).toBe(false);
      expect(c.implicitFlowEnabled, `${c.clientId} implicit`).toBe(false);
    }
  });

  it("OIDC discovery advertises only the issuer we pin", async () => {
    const d = (await (await fetch(`${REALM_URL}/.well-known/openid-configuration`)).json()) as Record<string, any>;
    expect(d.issuer).toBe(REALM_URL);
    expect(d.code_challenge_methods_supported).toContain("S256");
    expect(d.id_token_signing_alg_values_supported).not.toContain("none");
  });
});

// helpers kept at the bottom: they only exist for the tests above
const KC_ADMIN_USERS = `${OIDC.split("/realms/")[0]}/admin/realms/casefile/users`;

async function loginPasswordRaw(username: string, password: string) {
  const jar = new Jar();
  const first = await step(jar, authUrl({ challenge: pkce().challenge }));
  return step(jar, formAction(first.text)!, { username, password, credentialId: "" });
}
