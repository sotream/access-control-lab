import { Body, Controller, Post } from "@nestjs/common";
import { IsInt, IsString, Max, MaxLength, Min } from "class-validator";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { JwksServer, bearer, boot, get, goodClaims, makeKey, sign, type TestKey } from "../test/harness.js";
import { Authenticated } from "./auth/access.js";
import { redact } from "./http/logger.js";

class EchoDto {
  @IsString()
  @MaxLength(20)
  name!: string;

  @IsInt()
  @Min(0)
  @Max(10)
  n!: number;
}

@Controller("echo")
class EchoController {
  @Authenticated()
  @Post()
  post(@Body() dto: EchoDto) {
    return { name: dto.name, n: dto.n, nType: typeof dto.n, isInstance: dto instanceof EchoDto };
  }
}

let jwks: JwksServer;
let key: TestKey;
let token: string;

beforeAll(async () => {
  key = await makeKey("k1");
  jwks = await new JwksServer().start();
  jwks.keys = [key.publicJwk];
  token = await sign(goodClaims(), key);
});
afterAll(() => jwks.stop());

const post = (url: string, path: string, body: unknown, headers: Record<string, string> = {}, raw = false) =>
  fetch(`${url}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: raw ? (body as string) : JSON.stringify(body),
  });

describe("security headers (T-07, T-34)", () => {
  it("helmet defaults, deny-all CSP, no fingerprint", async () => {
    const a = await boot(jwks.url);
    const r = await get(a.url, "/health");
    expect(r.headers.get("x-powered-by")).toBeNull();
    expect(r.headers.get("x-content-type-options")).toBe("nosniff");
    expect(r.headers.get("content-security-policy")).toBe("default-src 'none';frame-ancestors 'none';base-uri 'none';form-action 'none'");
    expect(r.headers.get("referrer-policy")).toBe("no-referrer");
    expect(r.headers.get("strict-transport-security")).toBeTruthy();
    expect(r.headers.get("cross-origin-resource-policy")).toBe("same-origin");
    // error responses carry them too
    expect((await get(a.url, "/me")).headers.get("x-content-type-options")).toBe("nosniff");
    await a.close();
  });
});

describe("CORS is an allow-list (T-12)", () => {
  it("no origins configured: nothing is allowed, preflight included", async () => {
    const a = await boot(jwks.url);
    const r = await get(a.url, "/health", { origin: "https://evil.example" });
    expect(r.headers.get("access-control-allow-origin")).toBeNull();
    const pre = await fetch(`${a.url}/me`, {
      method: "OPTIONS",
      headers: { origin: "https://evil.example", "access-control-request-method": "GET" },
    });
    expect(pre.headers.get("access-control-allow-origin")).toBeNull();
    await a.close();
  });

  it("only the exact configured origin is echoed; never a wildcard, never credentials", async () => {
    const a = await boot(jwks.url, { CORS_ORIGINS: "https://bff.example" });
    const ok = await get(a.url, "/health", { origin: "https://bff.example" });
    expect(ok.headers.get("access-control-allow-origin")).toBe("https://bff.example");
    expect(ok.headers.get("access-control-allow-credentials")).toBeNull();
    for (const o of ["https://bff.example.evil.com", "http://bff.example", "https://evil.example", "null"]) {
      expect((await get(a.url, "/health", { origin: o })).headers.get("access-control-allow-origin"), o).toBeNull();
    }
    await a.close();
  });
});

describe("input limits and validation (T-13, T-27)", () => {
  it("body over the limit -> 413 with a fixed body", async () => {
    const a = await boot(jwks.url, {}, [EchoController]);
    const r = await post(a.url, "/echo", { name: "x".repeat(100_000), n: 1 }, bearer(token));
    expect(r.status).toBe(413);
    expect(await r.json()).toEqual({ statusCode: 413, error: "Payload Too Large" });
    await a.close();
  });

  it("unauthenticated oversized body is still refused before the handler", async () => {
    const a = await boot(jwks.url, {}, [EchoController]);
    expect((await post(a.url, "/echo", { name: "x".repeat(100_000), n: 1 })).status).toBe(413);
    await a.close();
  });

  it("malformed JSON -> 400 without parser internals", async () => {
    const a = await boot(jwks.url, {}, [EchoController]);
    const r = await post(a.url, "/echo", "{not json", bearer(token), true);
    expect(r.status).toBe(400);
    expect(await r.json()).toEqual({ statusCode: 400, error: "Bad Request" });
    await a.close();
  });

  it("unknown properties are rejected, not silently dropped (forbidNonWhitelisted)", async () => {
    const a = await boot(jwks.url, {}, [EchoController]);
    const r = await post(a.url, "/echo", { name: "a", n: 1, classification: "SECRET", role: "platform-admin" }, bearer(token));
    expect(r.status).toBe(400);
    const body = (await r.json()) as { message: string[] };
    expect(body.message.join()).toContain("classification should not exist");
    await a.close();
  });

  it.each([
    ["wrong type", { name: "a", n: "1" }],
    ["out of range", { name: "a", n: 11 }],
    ["too long", { name: "x".repeat(21), n: 1 }],
    ["missing field", { name: "a" }],
    ["array body", [1, 2]],
    ["null body", null],
  ])("invalid body: %s -> 400", async (_n, body) => {
    const a = await boot(jwks.url, {}, [EchoController]);
    expect((await post(a.url, "/echo", body, bearer(token))).status).toBe(400);
    await a.close();
  });

  it("transform is off: the handler gets the plain parsed body, not a coerced class instance", async () => {
    const a = await boot(jwks.url, {}, [EchoController]);
    const r = await post(a.url, "/echo", { name: "a", n: 1 }, bearer(token));
    expect(await r.json()).toEqual({ name: "a", n: 1, nType: "number", isInstance: false });
    await a.close();
  });
});

describe("rate limiting (T-22, T-27)", () => {
  it("public routes: limit per client address, 429 with Retry-After", async () => {
    const a = await boot(jwks.url, { THROTTLE_LIMIT: "5" });
    const codes: number[] = [];
    for (let i = 0; i < 8; i++) codes.push((await get(a.url, "/health")).status);
    expect(codes.slice(0, 5).every((c) => c === 200)).toBe(true);
    expect(codes.slice(5).every((c) => c === 429)).toBe(true);
    await a.close();
  });

  it("repeated failed authentication is cut off earlier, then 429 even for a valid token", async () => {
    const a = await boot(jwks.url, { AUTH_FAIL_LIMIT: "3" });
    for (let i = 0; i < 3; i++) expect((await get(a.url, "/me", bearer("bad"))).status).toBe(401);
    const blocked = await get(a.url, "/me", bearer(token));
    expect(blocked.status).toBe(429);
    expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
    // public routes are unaffected by the authentication failure budget
    expect((await get(a.url, "/health")).status).toBe(200);
    await a.close();
  });

  it("successful requests do not consume the failure budget", async () => {
    const a = await boot(jwks.url, { AUTH_FAIL_LIMIT: "3" });
    for (let i = 0; i < 20; i++) expect((await get(a.url, "/me", bearer(token))).status).toBe(200);
    await a.close();
  });

  it("authenticated traffic is limited per subject, not per address: one noisy user does not starve another", async () => {
    const a = await boot(jwks.url, { THROTTLE_LIMIT: "5" });
    const other = await sign(goodClaims({ sub: "someone-else" }), key);
    const codes: number[] = [];
    for (let i = 0; i < 8; i++) codes.push((await get(a.url, "/me", bearer(token))).status);
    expect(codes.slice(0, 5).every((c) => c === 200)).toBe(true);
    expect(codes.slice(5)).toEqual([429, 429, 429]);
    expect((await get(a.url, "/me", bearer(other))).status).toBe(200);
    await a.close();
  });

  it("X-Forwarded-For cannot be used to dodge the limit", async () => {
    const a = await boot(jwks.url, { AUTH_FAIL_LIMIT: "3" });
    for (let i = 0; i < 3; i++) await get(a.url, "/me", { ...bearer("bad"), "x-forwarded-for": `10.0.0.${i}` });
    expect((await get(a.url, "/me", { ...bearer(token), "x-forwarded-for": "10.9.9.9" })).status).toBe(429);
    await a.close();
  });
});

describe("errors and logs never leak tokens or claims (T-24, T-07)", () => {
  it("fixed error bodies for 401 and 403", async () => {
    const a = await boot(jwks.url);
    expect((await get(a.url, "/me")).body).toEqual({ statusCode: 401, error: "Unauthorized" });
    expect((await get(a.url, "/me", bearer("x.y.z"))).body).toEqual({ statusCode: 401, error: "Unauthorized" });
    await a.close();
  });

  it("logs carry request id and reason but no token, header or claim value", async () => {
    const a = await boot(jwks.url);
    const good = await sign(goodClaims({ unit: "secretunitname", sub: "sub-should-appear-only-as-sub" }), key);
    const tampered = `${good.split(".")[0]}.${Buffer.from(JSON.stringify(goodClaims({ unit: "forgedunit" }))).toString("base64url")}.${good.split(".")[2]}`;
    await get(a.url, "/me", bearer(good));
    await get(a.url, "/me", bearer(tampered));
    await get(a.url, "/me?access_token=" + good, { cookie: "session=supersecretcookie" });
    const all = a.logs.join("\n");
    for (const needle of [good, tampered, good.split(".")[2]!, "supersecretcookie", "forgedunit", "secretunitname", "Bearer"]) {
      expect(all, needle.slice(0, 20)).not.toContain(needle);
    }
    const lines = a.logs.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.msg === "request");
    expect(lines).toHaveLength(3);
    for (const l of lines) {
      expect(l.reqId).toMatch(/^[0-9a-f-]{36}$/);
      expect(l.path).toBe("/me"); // query string stripped
    }
    expect(lines[1]!.authFailure).toBe("bad_signature");
    expect(lines[0]!.sub).toBe("sub-should-appear-only-as-sub");
    await a.close();
  });

  it("request id is generated by the server, a client supplied one is not trusted", async () => {
    const a = await boot(jwks.url);
    const r = await get(a.url, "/health", { "x-request-id": "attacker-chosen-id" });
    expect(r.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/);
    await a.close();
  });

  it("unexpected errors become a generic 500 and log only the error class", async () => {
    // an authenticated route that throws: CurrentPrincipal on a route the guard lets through is impossible, so
    // force the filter directly with a controller that throws a message containing a secret
    @Controller("boom")
    class Boom {
      @Authenticated()
      @Post()
      boom(): never {
        throw new Error(`db password=hunter2 token=${token}`);
      }
    }
    const a = await boot(jwks.url, {}, [Boom]);
    const r = await post(a.url, "/boom", {}, bearer(token));
    expect(r.status).toBe(500);
    expect(await r.json()).toEqual({ statusCode: 500, error: "Internal Server Error" });
    expect(a.logs.join("\n")).not.toContain("hunter2");
    expect(a.logs.join("\n")).not.toContain(token);
    await a.close();
  });
});

describe("redact()", () => {
  it("masks sensitive keys at any depth and JWT-shaped strings", () => {
    const out = redact({
      headers: { authorization: "Bearer abc", cookie: "a=b", accept: "json" },
      nested: { password: "p", list: [{ refresh_token: "r" }, "eyJhbGciOi.eyJzdWIiOi.c2ln"] },
      ok: "fine",
    }) as { headers: Record<string, string>; nested: { password: string; list: [{ refresh_token: string }, string] }; ok: string };
    expect(out.headers.authorization).toBe("[REDACTED]");
    expect(out.headers.cookie).toBe("[REDACTED]");
    expect(out.headers.accept).toBe("json");
    expect(out.nested.password).toBe("[REDACTED]");
    expect(out.nested.list[0].refresh_token).toBe("[REDACTED]");
    expect(out.nested.list[1]).toBe("[REDACTED_JWT]");
    expect(out.ok).toBe("fine");
  });

  it("survives cycles and huge input", () => {
    const a: Record<string, unknown> = { x: "y".repeat(10_000) };
    a.self = a;
    expect(() => JSON.stringify(redact(a))).not.toThrow();
  });
});

describe("prototype-pollution keys are refused like any unknown field (A-24)", () => {
  it.each([
    ["__proto__", '{"__proto__":{"status":"approved"}}'],
    ["constructor", '{"constructor":{"prototype":{"status":"approved"}}}'],
    ["prototype", '{"prototype":{"x":1}}'],
    ["empty key", '{"":1}'],
    ["toString", '{"toString":1}'],
    ["hasOwnProperty", '{"title":"x","hasOwnProperty":null}'],
    ["valueOf nested", '{"a":{"valueOf":{}}}'],
    ["__defineGetter__", '{"__defineGetter__":0}'],
    ["nested empty key", '{"a":[{"":{}}]}'],
    ["nested", '{"a":{"b":[{"c":{"__proto__":{}}}]}}'],
  ])("%s in a JSON body is a 400 before any handler runs", async (_n, body) => {
    const a = await boot(jwks.url);
    const r = await fetch(`${a.url}/me`, { method: "POST", headers: { ...bearer(token), "content-type": "application/json" }, body });
    expect(r.status).toBe(400);
    await a.close();
  });
  it("absurd nesting is refused, ordinary bodies pass the filter", async () => {
    const deep = `${'{"a":'.repeat(40)}1${"}".repeat(40)}`;
    const a = await boot(jwks.url);
    expect((await fetch(`${a.url}/me`, { method: "POST", headers: { ...bearer(token), "content-type": "application/json" }, body: deep })).status).toBe(400);
    expect((await fetch(`${a.url}/me`, { method: "POST", headers: { ...bearer(token), "content-type": "application/json" }, body: '{"title":"fine"}' })).status).toBe(404); // no POST /me: reaches routing
    await a.close();
  });
});
