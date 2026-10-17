import { Controller, Get, type Type } from "@nestjs/common";
import { PATH_METADATA, METHOD_METADATA } from "@nestjs/common/constants";
import { ModulesContainer, Reflector } from "@nestjs/core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { JwksServer, bearer, boot, get, goodClaims, makeKey, sign, type Booted, type TestKey } from "../test/harness.js";
import { ACCESS_KEY, type Access } from "./auth/access.js";

// A route someone "forgot" to declare access on. The suite must see it and the guard must deny it.
@Controller("forgotten")
class ForgottenController {
  @Get()
  get() {
    return { leaked: true };
  }
}

interface RouteInfo {
  method: number;
  path: string;
  access: Access | undefined;
}

/** Walks every controller method that carries a route and reads its declared access. */
function enumerate(app: Booted["app"]): RouteInfo[] {
  const reflector = new Reflector();
  const out: RouteInfo[] = [];
  for (const mod of app.get(ModulesContainer).values()) {
    for (const wrapper of mod.controllers.values()) {
      const ctor = wrapper.metatype as Type | null;
      if (!ctor) continue;
      const base = Reflect.getMetadata(PATH_METADATA, ctor) as string;
      for (const name of Object.getOwnPropertyNames(ctor.prototype).filter((n) => n !== "constructor")) {
        const handler = ctor.prototype[name] as (...a: never[]) => unknown;
        const path = Reflect.getMetadata(PATH_METADATA, handler) as string | undefined;
        if (typeof handler !== "function" || path === undefined) continue;
        out.push({
          method: Reflect.getMetadata(METHOD_METADATA, handler) as number,
          path: `/${base}/${path}`.replace(/\/+/g, "/").replace(/\/$/, "") || "/",
          access: reflector.getAllAndOverride<Access | undefined>(ACCESS_KEY, [handler, ctor]),
        });
      }
    }
  }
  return out;
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
});
