import { createSecretKey } from "node:crypto";
import { exportSPKI } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type Booted,
  JwksServer,
  type TestKey,
  b64,
  bearer,
  boot,
  get,
  goodClaims,
  makeKey,
  now,
  sign,
} from "../test/harness.js";

let jwks: JwksServer;
let api: Booted;
let key: TestKey;
let es: TestKey;

beforeAll(async () => {
  key = await makeKey("k1");
  es = await makeKey("k-es", "ES256");
  jwks = await new JwksServer().start();
  jwks.keys = [key.publicJwk, es.publicJwk];
  api = await boot(jwks.url);
});
afterAll(async () => {
  await api.close();
  await jwks.stop();
});

const me = (token: string) => get(api.url, "/me", bearer(token));
const reasonOf = (reqIndex = -1) => {
  const lines = api.logs.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.msg === "request");
  return lines.at(reqIndex)?.authFailure;
};

describe("accepts a correct token (T-08, T-09)", () => {
  it("RS256", async () => {
    const r = await me(await sign(goodClaims(), key));
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ clearance: "OFFICIAL", unit: "alpha", roles: ["analyst"], compartments: [] });
  });

  it("ES256", async () => {
    expect((await me(await sign(goodClaims(), es))).status).toBe(200);
  });

  it("tolerates small clock skew in both directions", async () => {
    expect((await me(await sign(goodClaims({ exp: now() - 2 }), key))).status).toBe(200);
    expect((await me(await sign(goodClaims({ nbf: now() + 2 }), key))).status).toBe(200);
  });
});

describe("rejects forged and tampered tokens (T-08)", () => {
  it("payload edited after signing", async () => {
    const [h, , s] = (await sign(goodClaims(), key)).split(".");
    const forged = `${h}.${b64(goodClaims({ clearance: "SECRET", realm_access: { roles: ["platform-admin"] } }))}.${s}`;
    expect((await me(forged)).status).toBe(401);
    expect(reasonOf()).toBe("bad_signature");
  });

  it("alg=none, with and without signature part", async () => {
    const unsigned = `${b64({ alg: "none", typ: "JWT", kid: "k1" })}.${b64(goodClaims())}.`;
    expect((await me(unsigned)).status).toBe(401);
    expect(reasonOf()).toBe("alg_not_allowed");
    expect((await me(`${b64({ alg: "None", kid: "k1" })}.${b64(goodClaims())}.AAAA`)).status).toBe(401);
  });

  it("HS256 signed with the RSA public key as the secret (key confusion)", async () => {
    const pem = await exportSPKI(key.publicKey as never);
    const t = await sign(goodClaims(), { ...key, alg: "RS256", privateKey: createSecretKey(Buffer.from(pem)) }, { alg: "HS256" });
    expect((await me(t)).status).toBe(401);
    expect(reasonOf()).toBe("alg_not_allowed");
  });

  it("HS256 / HS512 with an arbitrary secret", async () => {
    for (const alg of ["HS256", "HS512"]) {
      const t = await sign(goodClaims(), { ...key, privateKey: createSecretKey(Buffer.from("x".repeat(64))) }, { alg });
      expect((await me(t)).status).toBe(401);
    }
  });

  it("algorithms outside the allow-list even with a valid key (PS256, RS512)", async () => {
    for (const alg of ["PS256", "RS512"] as const) {
      const k = await makeKey(`k-${alg}`, alg);
      jwks.keys = [key.publicJwk, es.publicJwk, k.publicJwk];
      expect((await me(await sign(goodClaims(), k))).status).toBe(401);
      expect(reasonOf()).toBe("alg_not_allowed");
    }
    jwks.keys = [key.publicJwk, es.publicJwk];
  });

  it("token signed by a key Keycloak never published, reusing a real kid", async () => {
    const evil = await makeKey("k1");
    expect((await me(await sign(goodClaims(), evil))).status).toBe(401);
    expect(reasonOf()).toBe("bad_signature");
  });

  it("token from another realm (different issuer, unknown key)", async () => {
    const other = await makeKey("other-realm-key");
    const t = await sign(goodClaims({ iss: "http://127.0.0.1:8080/realms/other" }), other);
    expect((await me(t)).status).toBe(401);
  });
});

describe("key id handling (T-10)", () => {
  it("missing kid is refused even when only one key is published", async () => {
    jwks.keys = [key.publicJwk];
    const t = await sign(goodClaims(), key, { kid: undefined });
    expect((await me(t)).status).toBe(401);
    expect(reasonOf()).toBe("missing_kid");
    jwks.keys = [key.publicJwk, es.publicJwk];
  });

  it("unknown kid", async () => {
    const ghost = await makeKey("ghost");
    expect((await me(await sign(goodClaims(), ghost))).status).toBe(401);
    expect(reasonOf()).toBe("unknown_key");
  });
});

describe("claim validation (T-09)", () => {
  it.each([
    ["wrong audience", { aud: "casefile-web" }, "bad_audience"],
    ["audience list without casefile-api", { aud: ["account", "casefile-web"] }, "bad_audience"],
    ["wrong issuer", { iss: "http://127.0.0.1:8080/realms/other" }, "bad_issuer"],
    ["issuer with trailing slash", { iss: `${"http://127.0.0.1:8080/realms/casefile"}/` }, "bad_issuer"],
    ["expired beyond skew", { exp: now() - 30 }, "expired"],
    ["not yet valid", { nbf: now() + 60 }, "not_yet_valid"],
    ["ID token used as bearer", { typ: "ID" }, "wrong_token_type"],
    ["refresh token used as bearer", { typ: "Refresh" }, "wrong_token_type"],
    ["missing typ", { typ: undefined }, "wrong_token_type"],
    ["azp of another client", { azp: "account-console" }, "bad_azp"],
    ["missing azp", { azp: undefined }, "bad_azp"],
    ["missing exp", { exp: undefined }, "bad_claims"],
    ["missing sub", { sub: undefined }, "bad_claims"],
  ])("%s", async (_n, over, reason) => {
    expect((await me(await sign(goodClaims(over), key))).status).toBe(401);
    expect(reasonOf()).toBe(reason);
  });

  it("aud may be a list that contains casefile-api", async () => {
    expect((await me(await sign(goodClaims({ aud: ["account", "casefile-api"] }), key))).status).toBe(200);
  });
});

describe("strict principal parsing fails closed (T-19)", () => {
  it.each([
    ["unknown clearance", { clearance: "TOPSECRET" }],
    ["lower-case clearance", { clearance: "secret" }],
    ["clearance wrong type", { clearance: 3 }],
    ["clearance missing", { clearance: undefined }],
    ["unit missing", { unit: undefined }],
    ["unit wrong type", { unit: ["alpha"] }],
    ["unit with odd characters", { unit: "alpha; DROP" }],
    ["compartments as string", { compartments: "A" }],
    ["compartments with non-string", { compartments: ["A", 1] }],
    ["realm_access missing", { realm_access: undefined }],
    ["roles not an array", { realm_access: { roles: "analyst" } }],
    ["amr not an array", { amr: "pwd" }],
    ["acr missing", { acr: undefined }],
    ["auth_time missing", { auth_time: undefined }],
    ["auth_time as string", { auth_time: "1" }],
  ])("%s -> 401 bad_claims", async (_n, over) => {
    expect((await me(await sign(goodClaims(over), key))).status).toBe(401);
    expect(reasonOf()).toBe("bad_claims");
  });

  it("drops roles outside the application set and keeps the rest", async () => {
    const r = await me(await sign(goodClaims({ realm_access: { roles: ["reviewer", "offline_access", "made-up"] } }), key));
    expect((r.body as { roles: string[] }).roles).toEqual(["reviewer"]);
  });

  it("does not take identity from headers", async () => {
    const t = await sign(goodClaims(), key);
    const r = await get(api.url, "/me", { ...bearer(t), "x-user": "attacker", "x-clearance": "SECRET", "x-roles": "platform-admin" });
    expect(r.body).toMatchObject({ clearance: "OFFICIAL", roles: ["analyst"] });
  });
});

describe("header handling", () => {
  it("no Authorization header: 401 without error code", async () => {
    const r = await get(api.url, "/me");
    expect(r.status).toBe(401);
    expect(r.headers.get("www-authenticate")).toBe('Bearer realm="casefile-api"');
  });

  it("refused token: 401 with invalid_token (RFC 6750)", async () => {
    const r = await me("garbage");
    expect(r.status).toBe(401);
    expect(r.headers.get("www-authenticate")).toBe('Bearer realm="casefile-api", error="invalid_token"');
  });

  it.each([
    ["Basic scheme", "Basic dXNlcjpwYXNz"],
    ["empty token", "Bearer "],
    ["two tokens", "Bearer a b"],
    ["no scheme", "abc.def.ghi"],
    ["token with illegal characters", "Bearer a<b>c"],
    ["oversized token", `Bearer ${"a".repeat(9000)}`],
  ])("malformed Authorization: %s", async (_n, value) => {
    const r = await get(api.url, "/me", { authorization: value });
    expect(r.status).toBe(401);
  });

  it("token in the query string is ignored", async () => {
    const t = await sign(goodClaims(), key);
    expect((await get(api.url, `/me?access_token=${t}`)).status).toBe(401);
  });

  it("two Authorization headers are refused even if both are valid", async () => {
    const t = await sign(goodClaims(), key);
    const { Socket } = await import("node:net");
    const port = new URL(api.url).port;
    const raw = await new Promise<string>((resolve, reject) => {
      const s = new Socket();
      let data = "";
      s.connect(Number(port), "127.0.0.1", () =>
        s.write(`GET /me HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${t}\r\nAuthorization: Bearer ${t}\r\nConnection: close\r\n\r\n`),
      );
      s.on("data", (d) => (data += d));
      s.on("end", () => resolve(data));
      s.on("error", reject);
    });
    expect(raw.startsWith("HTTP/1.1 401")).toBe(true);
  });
});

describe("fail closed when Keycloak is unreachable (T-10)", () => {
  it("JWKS endpoint down: 401, not 500, not allow", async () => {
    const fresh = await new JwksServer().start();
    fresh.keys = [key.publicJwk];
    fresh.down = true;
    const a = await boot(fresh.url);
    const r = await get(a.url, "/me", bearer(await sign(goodClaims(), key)));
    expect(r.status).toBe(401);
    await a.close();
    await fresh.stop();
  });
});
