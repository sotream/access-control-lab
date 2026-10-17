// The API as a resource server, against the real Keycloak realm (T-08, T-09, T-17, T-19).
// Reuses the login helpers and seed expectations of the identity suite.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../../../apps/api/src/app.js";
import { loadConfig } from "../../../apps/api/src/config.js";
import { JsonLogger } from "../../../apps/api/src/http/logger.js";
import { adminToken, decode, login, loginPassword, exchange, REALM_URL, type Tokens, KC } from "./kc.js";
import { SEED } from "./seed.js";

let url = "";
let close: () => Promise<void>;
const logs: string[] = [];
const tokens = new Map<string, Tokens>();

const me = async (token: string | undefined) => {
  const res = await fetch(`${url}/me`, { headers: token ? { authorization: `Bearer ${token}` } : {} });
  return { status: res.status, body: (await res.json()) as Record<string, unknown>, www: res.headers.get("www-authenticate") };
};

beforeAll(async () => {
  const cfg = loadConfig({
    KEYCLOAK_ISSUER: REALM_URL, // JWKS from the live realm, default URI
    THROTTLE_LIMIT: "100000",
    AUTH_FAIL_LIMIT: "10000",
  });
  const app = await createApp(cfg, { logger: new JsonLogger((l) => logs.push(l)) });
  await app.listen(0, "127.0.0.1");
  url = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}`;
  close = () => app.close();
  for (const u of Object.keys(SEED)) tokens.set(u, await login(u));
}, 240_000);
afterAll(() => close?.());

describe("real Keycloak access tokens are accepted and parsed (T-08, T-09)", () => {
  it.each(Object.entries(SEED))("%s", async (user, want) => {
    const r = await me(tokens.get(user)!.access_token);
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({
      roles: [want.role],
      clearance: want.clearance,
      unit: want.unit,
      compartments: want.compartments ?? [],
    });
    expect(typeof r.body.authTime).toBe("number");
    expect(r.body.sub).toBe(decode(tokens.get(user)!.access_token).claims.sub);
  });

  it("SECRET users surface acr=mfa and amr with otp; others do not (T-17)", async () => {
    expect((await me(tokens.get("analyst-secret-a")!.access_token)).body).toMatchObject({ acr: "mfa", amr: ["pwd", "otp"] });
    expect((await me(tokens.get("reviewer")!.access_token)).body).toMatchObject({ acr: "pwd", amr: ["pwd"] });
  });
});

describe("real tokens that must not work as API credentials (T-09)", () => {
  it("ID token", async () => {
    const t = tokens.get("analyst-official")!;
    expect(decode(t.id_token).claims.typ).toBe("ID");
    expect((await me(t.id_token)).status).toBe(401);
  });

  it("refresh token", async () => {
    expect((await me(tokens.get("analyst-official")!.refresh_token)).status).toBe(401);
  });

  it("access token issued to another client (account-console), valid signature and issuer", async () => {
    const l = await loginPassword("analyst-official", undefined, { clientId: "account-console", redirectUri: `${REALM_URL}/account/` });
    const t = await exchange(l);
    const c = decode(t.access_token).claims;
    expect(c.azp).toBe("account-console");
    expect((await me(t.access_token)).status).toBe(401);
  });

  it("admin token from the master realm", async () => {
    const t = await adminToken();
    expect(decode(t).claims.iss).toBe(`${KC}/realms/master`);
    expect((await me(t)).status).toBe(401);
  });

  it("real token with one payload byte changed", async () => {
    const [h, p, s] = tokens.get("analyst-official")!.access_token.split(".") as [string, string, string];
    const claims = JSON.parse(Buffer.from(p, "base64url").toString());
    claims.clearance = "SECRET";
    const forged = `${h}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${s}`;
    expect((await me(forged)).status).toBe(401);
  });

  it("real token re-labelled alg=none", async () => {
    const [, p] = tokens.get("analyst-official")!.access_token.split(".");
    const none = `${Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url")}.${p}.`;
    expect((await me(none)).status).toBe(401);
  });

  it("no token, and the challenge is RFC 6750 shaped", async () => {
    const r = await me(undefined);
    expect(r.status).toBe(401);
    expect(r.www).toBe('Bearer realm="casefile-api"');
  });
});

describe("hygiene with real tokens (T-24)", () => {
  it("no real token or signature reached the logs", () => {
    const all = logs.join("\n");
    for (const t of tokens.values()) {
      expect(all).not.toContain(t.access_token);
      expect(all).not.toContain(t.access_token.split(".")[2]!);
      expect(all).not.toContain(t.refresh_token);
      expect(all).not.toContain(t.id_token);
    }
  });
});
