// Test fixtures: locally generated keys, a fake JWKS endpoint that counts fetches, token signing, and a booted app.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Type } from "@nestjs/common";
import type { NestExpressApplication } from "@nestjs/platform-express";
import {
  exportJWK,
  generateKeyPair,
  SignJWT,
  type CryptoKey,
  type JWK,
  type JWTHeaderParameters,
  type JWTPayload,
  type KeyObject,
} from "jose";
import { createApp } from "../src/app.js";
import { loadConfig, type AppConfig } from "../src/config.js";
import { JsonLogger } from "../src/http/logger.js";

export const ISSUER = "http://127.0.0.1:8080/realms/casefile";

export interface TestKey {
  kid: string;
  alg: "RS256" | "ES256" | "RS512" | "PS256";
  privateKey: CryptoKey | KeyObject;
  publicKey: CryptoKey | KeyObject;
  publicJwk: JWK;
}

export async function makeKey(kid: string, alg: TestKey["alg"] = "RS256"): Promise<TestKey> {
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg, use: "sig" };
  return { kid, alg, privateKey, publicKey, publicJwk };
}

/** Fake Keycloak certs endpoint. `keys` can be swapped at any time; `fetches` counts requests. */
export class JwksServer {
  keys: JWK[] = [];
  fetches = 0;
  down = false;
  private server!: Server;
  url = "";

  async start(): Promise<this> {
    this.server = createServer((req, res) => {
      this.fetches++;
      if (this.down) {
        res.writeHead(503).end();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ keys: this.keys }));
    });
    await new Promise<void>((r) => this.server.listen(0, "127.0.0.1", r));
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}/certs`;
    return this;
  }

  stop(): Promise<void> {
    return new Promise((r) => this.server.close(() => r()));
  }
}

export const now = () => Math.floor(Date.now() / 1000);

/** A token that passes every check; tests override one thing at a time. */
export function goodClaims(over: Record<string, unknown> = {}): JWTPayload {
  const t = now();
  return {
    iss: ISSUER,
    aud: "casefile-api",
    sub: "11111111-2222-3333-4444-555555555555",
    azp: "casefile-web",
    typ: "Bearer",
    exp: t + 300,
    iat: t,
    auth_time: t,
    sid: "session-1",
    acr: "pwd",
    amr: ["pwd"],
    realm_access: { roles: ["analyst", "default-roles-casefile"] },
    clearance: "OFFICIAL",
    unit: "alpha",
    ...over,
  };
}

export async function sign(
  claims: JWTPayload,
  key: TestKey,
  header: Partial<JWTHeaderParameters> = {},
): Promise<string> {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: key.alg, kid: key.kid, typ: "JWT", ...header } as JWTHeaderParameters)
    .sign(key.privateKey);
}

export const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");

export interface Booted {
  app: NestExpressApplication;
  url: string;
  cfg: AppConfig;
  logs: string[];
  close(): Promise<void>;
}

export async function boot(
  jwksUri: string,
  env: Record<string, string> = {},
  extraControllers: Type[] = [],
): Promise<Booted> {
  const cfg = loadConfig({
    KEYCLOAK_ISSUER: ISSUER,
    KEYCLOAK_JWKS_URI: jwksUri,
    // generous by default; dedicated tests lower them
    THROTTLE_LIMIT: "100000",
    AUTH_FAIL_LIMIT: "10000",
    JWKS_COOLDOWN_MS: "0",
    ...env,
  });
  const logs: string[] = [];
  const app = await createApp(cfg, { logger: new JsonLogger((l) => logs.push(l)), extraControllers });
  await app.listen(0, "127.0.0.1");
  const url = `http://127.0.0.1:${(app.getHttpServer().address() as AddressInfo).port}`;
  return { app, url, cfg, logs, close: () => app.close() };
}

export async function get(url: string, path: string, headers: Record<string, string> = {}) {
  const res = await fetch(`${url}${path}`, { headers, redirect: "manual" });
  const text = await res.text();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: res.status, headers: res.headers, body, text };
}

export const bearer = (t: string) => ({ authorization: `Bearer ${t}` });
