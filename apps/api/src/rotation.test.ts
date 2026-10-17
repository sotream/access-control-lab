import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { JwksServer, bearer, boot, get, goodClaims, makeKey, sign } from "../test/harness.js";

const COOLDOWN = 400;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("JWKS rotation with bounded refetch (T-10)", () => {
  let jwks: JwksServer;
  let a: Awaited<ReturnType<typeof boot>>;

  beforeAll(async () => {
    jwks = await new JwksServer().start();
    a = await boot(jwks.url, { JWKS_COOLDOWN_MS: String(COOLDOWN) });
  });
  afterAll(async () => {
    await a.close();
    await jwks.stop();
  });

  it("new kid works after the refetch window, old kid stops once the set is refreshed, no storm", async () => {
    const oldKey = await makeKey("old");
    const newKey = await makeKey("new");
    jwks.keys = [oldKey.publicJwk];

    const oldTok = await sign(goodClaims(), oldKey);
    expect((await get(a.url, "/me", bearer(oldTok))).status).toBe(200);
    expect(jwks.fetches).toBe(1);

    // Keycloak rotates: only the new key is published now
    jwks.keys = [newKey.publicJwk];
    const newTok = await sign(goodClaims(), newKey);

    // inside the cooldown an unknown kid must not cause a refetch: refused, fetch count unchanged
    expect((await get(a.url, "/me", bearer(newTok))).status).toBe(401);
    expect(jwks.fetches).toBe(1);

    await sleep(COOLDOWN + 50);
    expect((await get(a.url, "/me", bearer(newTok))).status).toBe(200);
    expect(jwks.fetches).toBe(2);

    // the cached set was replaced: the retired key no longer verifies
    expect((await get(a.url, "/me", bearer(oldTok))).status).toBe(401);
  });

  it("a flood of tokens with random kids causes at most one refetch per cooldown", async () => {
    const k = await makeKey("flood-known");
    jwks.keys = [k.publicJwk];
    await sleep(COOLDOWN + 50);
    const before = jwks.fetches;
    const ghost = await makeKey("ghost");
    for (let i = 0; i < 60; i++) {
      const t = await sign(goodClaims(), { ...ghost, kid: `random-${i}` }, { kid: `random-${i}` });
      expect((await get(a.url, "/me", bearer(t))).status).toBe(401);
    }
    expect(jwks.fetches - before).toBeLessThanOrEqual(2);
  });
});
