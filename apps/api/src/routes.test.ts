import { Controller, Get, RequestMethod } from "@nestjs/common";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { JwksServer, bearer, boot, get, goodClaims, makeKey, sign, type TestKey } from "../test/harness.js";
import { FIXTURE } from "../test/casefile-fixture.js";
import { enumerate } from "../test/inventory.js";
import { Policy } from "./auth/access.js";

// A route someone "forgot" to declare access on. The suite must see it and the guard must deny it.
@Controller("forgotten")
class ForgottenController {
  @Get()
  get() {
    return { leaked: true };
  }
}

describe("default deny and route inventory (T-11)", () => {
  let jwks: JwksServer;
  let key: TestKey;

  beforeAll(async () => {
    key = await makeKey("k1");
    jwks = await new JwksServer().start();
    jwks.keys = [key.publicJwk];
  });
  afterAll(() => jwks.stop());

  it("every route of the production app declares its access", async () => {
    const a = await boot(jwks.url);
    const routes = enumerate(a.app);
    await a.close();
    expect(routes.length).toBeGreaterThan(0);
    const undeclared = routes.filter((r) => !r.access).map((r) => r.path);
    expect(undeclared, `routes without access metadata: ${undeclared.join(", ")}`).toEqual([]);
  });

  it("only GET /health is public", async () => {
    const a = await boot(jwks.url);
    const pub = enumerate(a.app).filter((r) => r.access?.kind === "public");
    await a.close();
    expect(pub.map((r) => r.path)).toEqual(["/health"]);
  });

  it("the inventory check actually catches an undeclared route", async () => {
    const a = await boot(jwks.url, {}, [ForgottenController]);
    const undeclared = enumerate(a.app).filter((r) => !r.access).map((r) => r.path);
    expect(undeclared).toEqual(["/forgotten"]);

    // and the runtime guard backs it up: unauthenticated -> 401, authenticated -> 403, body never reached
    expect((await get(a.url, "/forgotten")).status).toBe(401);
    const r = await get(a.url, "/forgotten", bearer(await sign(goodClaims(), key)));
    expect(r.status).toBe(403);
    expect(r.text).not.toContain("leaked");
    await a.close();
  });

  it("every declared non-public route answers 401 without a token", async () => {
    const a = await boot(jwks.url);
    for (const r of enumerate(a.app).filter((x) => x.access?.kind !== "public")) {
      expect((await get(a.url, r.path)).status, r.path).toBe(401);
    }
    await a.close();
  });

  it("unknown paths and methods give a generic 404 without detail", async () => {
    const a = await boot(jwks.url);
    const r = await get(a.url, "/nope");
    expect(r.status).toBe(404);
    expect(r.body).toEqual({ statusCode: 404, error: "Not Found" });
    await a.close();
  });

  it("fixture routes with @Policy are all declared; each answers 401 without a token", async () => {
    const a = await boot(jwks.url, {}, FIXTURE.controllers, { providers: FIXTURE.providers });
    const routes = enumerate(a.app).filter((r) => r.access?.kind === "policy");
    expect(routes.length).toBeGreaterThanOrEqual(9);
    expect(enumerate(a.app).filter((r) => !r.access)).toEqual([]);
    for (const r of routes) {
      const res = await fetch(`${a.url}${r.path.replace(":id", "x")}`, { method: RequestMethod[r.method] });
      expect(res.status, `${RequestMethod[r.method]} ${r.path}`).toBe(401);
    }
    await a.close();
  });

  it("@Policy refuses a role-only declaration for actions that touch a case file", () => {
    for (const action of ["create", "update", "submit", "approve", "delete", "export"] as const) {
      expect(() => Policy({ action, resource: null }), action).toThrow(/ResourceLoader/);
    }
    for (const action of ["read", "readAudit", "manageUsers"] as const) expect(() => Policy({ action, resource: null })).not.toThrow();
  });
});
