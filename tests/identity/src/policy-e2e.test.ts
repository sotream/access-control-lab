// Guard + policy engine + in-memory fixture, driven by REAL Keycloak tokens of the seed users (T-11, T-15, T-16, T-17, T-25).
import { parseZoneKeys, signZone } from "@acl/netguard";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../../../apps/api/src/app.js";
import { loadConfig } from "../../../apps/api/src/config.js";
import { JsonLogger } from "../../../apps/api/src/http/logger.js";
import { CaseFileStore, FIXTURE } from "../../../apps/api/test/casefile-fixture.js";
import { decode, login, REALM_URL, type Tokens } from "./kc.js";
import { SEED } from "./seed.js";

type User = keyof typeof SEED;

let url = "";
let close: () => Promise<void>;
let store: CaseFileStore;
const logs: string[] = [];
const tokens = new Map<string, Tokens>();
let pwdOnlySecretA: Tokens; // SECRET user whose token says acr=pwd (client asked for acr_values=pwd)

const NOON = Date.UTC(2026, 9, 17, 12, 0, 0);

/** what the BFF would send: the managed zone, signed for the token's subject (the API accepts a zone from nobody else) */
const zoneHeader = (accessToken: string) => ({ "x-acl-zone": signZone(parseZoneKeys(process.env.ZONE_SIGNING_KEYS!), "managed", JSON.parse(Buffer.from(accessToken.split(".")[1]!, "base64url").toString()).sub as string, Math.floor(Date.now() / 1000)) });

async function call(user: User | "secretAPwd", method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const t = user === "secretAPwd" ? pwdOnlySecretA : tokens.get(user)!;
  const res = await fetch(`${url}${path}`, {
    method,
    headers: { authorization: `Bearer ${t.access_token}`, ...zoneHeader(t.access_token), ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json: Record<string, unknown> & unknown[] = [] as never;
  try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, body: json, www: res.headers.get("www-authenticate") };
}
const sub = (u: User) => decode(tokens.get(u)!.access_token).claims.sub as string;

beforeAll(async () => {
  const cfg = loadConfig({ KEYCLOAK_ISSUER: REALM_URL, THROTTLE_LIMIT: "100000", AUTH_FAIL_LIMIT: "10000", ZONE_SIGNING_KEYS: process.env.ZONE_SIGNING_KEYS! });
  const app = await createApp(cfg, { logger: new JsonLogger((l) => logs.push(l)), extraControllers: FIXTURE.controllers, extraProviders: FIXTURE.providers, clock: () => NOON });
  await app.listen(0, "127.0.0.1");
  url = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}`;
  close = () => app.close();
  store = app.get(CaseFileStore);
  for (const u of Object.keys(SEED)) tokens.set(u, await login(u));
  pwdOnlySecretA = await login("analyst-secret-a", { acrValues: "pwd" });
}, 300_000);
afterAll(() => close?.());

describe("clearance and compartments with real identities (T-15)", () => {
  it("analyst-official cannot read SECRET or compartmented files: 404, same as a missing id", async () => {
    expect((await call("analyst-official", "GET", "/files/official-alpha")).status).toBe(200);
    const secret = await call("analyst-official", "GET", "/files/secret-alpha-a");
    const comp = await call("analyst-official", "GET", "/files/conf-alpha-a");
    const missing = await call("analyst-official", "GET", "/files/nope");
    expect([secret.status, comp.status, missing.status]).toEqual([404, 404, 404]);
    expect(secret.body).toEqual(missing.body);
  });

  it("compartment A vs B", async () => {
    expect((await call("analyst-secret-a", "GET", "/files/secret-alpha-a")).status).toBe(200);
    expect((await call("analyst-secret-a", "GET", "/files/secret-alpha-b")).status).toBe(404);
    expect((await call("analyst-secret-b", "GET", "/files/secret-alpha-b")).status).toBe(200);
    expect((await call("analyst-secret-b", "GET", "/files/secret-alpha-a")).status).toBe(404);
  });

  it("list shows only what read would allow", async () => {
    const ids = async (u: User) => ((await call(u, "GET", "/files")).body as { id: string }[]).map((x) => x.id);
    expect(await ids("analyst-official")).not.toContain("secret-alpha-a");
    expect(await ids("analyst-official")).not.toContain("conf-alpha-a");
    expect(await ids("analyst-secret-a")).toContain("secret-alpha-a");
    expect(await ids("analyst-secret-a")).not.toContain("secret-alpha-b");
    expect(await ids("reviewer")).toContain("conf-alpha-a");
  });
});

describe("step-up with a real SECRET token that says acr=pwd (T-17)", () => {
  it("token facts: acr=pwd, amr has otp", () => {
    const c = decode(pwdOnlySecretA.access_token).claims;
    expect(c.acr).toBe("pwd");
    expect(c.amr).toEqual(["pwd", "otp"]);
  });

  it("403 with an RFC 9470 challenge, not 404 (the user is cleared for it)", async () => {
    const r = await call("secretAPwd", "GET", "/files/secret-alpha-a");
    expect(r.status).toBe(403);
    expect(r.www).toContain('acr_values="mfa"');
    expect(r.body).toMatchObject({ code: "STEP_UP_REQUIRED" });
  });

  it("the same token still reads what is not SECRET, and sees no SECRET rows", async () => {
    expect((await call("secretAPwd", "GET", "/files/conf-alpha-a")).status).toBe(200);
    expect(((await call("secretAPwd", "GET", "/files")).body as { id: string }[]).map((x) => x.id)).not.toContain("secret-alpha-a");
  });

  it("a full MFA token of the same user reads it", async () => {
    expect((await call("analyst-secret-a", "GET", "/files/secret-alpha-a")).status).toBe(200);
  });
});

describe("units and roles (T-11, T-15)", () => {
  it("unit-admin of another unit: IDOR gives 404 where hiding applies, 403 where the file is readable", async () => {
    expect((await call("unit-admin-beta", "GET", "/files/conf-alpha-a-draft")).status).toBe(404);
    expect((await call("unit-admin-beta", "PATCH", "/files/conf-alpha-a-draft", { title: "x" })).status).toBe(404);
    expect((await call("unit-admin-beta", "DELETE", "/files/conf-alpha-a-draft")).status).toBe(404);
    expect((await call("unit-admin-beta", "PATCH", "/files/official-alpha-draft", { title: "x" })).status).toBe(403);
    expect((await call("unit-admin-alpha", "PATCH", "/files/official-alpha-draft", { title: "ok" })).status).toBe(200);
  });

  it("auditor is read-only on the audit log and sees no case content", async () => {
    expect((await call("auditor", "GET", "/audit")).status).toBe(200);
    expect((await call("auditor", "GET", "/files/official-alpha")).status).toBe(404);
    expect((await call("auditor", "GET", "/files")).status).toBe(403);
    expect((await call("auditor", "POST", "/files", { title: "t", classification: "OFFICIAL", compartments: [] })).status).toBe(403);
    expect((await call("auditor", "DELETE", "/files/official-alpha-draft")).status).toBe(404);
  });

  it("platform-admin manages users but has no implicit case access", async () => {
    expect((await call("platform-admin", "GET", "/admin/users")).status).toBe(200);
    expect((await call("platform-admin", "GET", "/files/official-alpha")).status).toBe(404);
    expect((await call("platform-admin", "GET", "/audit")).status).toBe(403);
  });

  it("analyst cannot create above clearance and mass assignment is rejected", async () => {
    expect((await call("analyst-official", "POST", "/files", { title: "t", classification: "SECRET", compartments: [] })).status).toBe(403);
    expect((await call("analyst-official", "POST", "/files", { title: "t", classification: "OFFICIAL", compartments: [], authorId: "x", ownerUnit: "beta" })).status).toBe(400);
  });
});

describe("separation of duties (T-16)", () => {
  it("unit-admin cannot approve their own submission; the reviewer can", async () => {
    const made = await call("unit-admin-alpha", "POST", "/files", { title: "case", classification: "OFFICIAL", compartments: [] });
    expect(made.status).toBe(201);
    const id = (made.body as unknown as { id: string }).id;
    expect(store.files.get(id)!.authorId).toBe(sub("unit-admin-alpha"));
    expect((await call("unit-admin-alpha", "POST", `/files/${id}/submit`)).status).toBe(201);
    expect((await call("unit-admin-alpha", "POST", `/files/${id}/approve`)).status).toBe(403);
    expect((await call("reviewer", "POST", `/files/${id}/approve`)).status).toBe(201);
    expect((await call("unit-admin-alpha", "PATCH", `/files/${id}`, { title: "late" })).status).toBe(403);
  });
});

describe("export conditions (managed address, window)", () => {
  it("analyst exports an approved file from the managed address inside the window", async () => {
    expect((await call("analyst-official", "GET", "/files/official-alpha/export")).status).toBe(200);
    expect((await call("analyst-official", "GET", "/files/official-alpha-draft/export")).status).toBe(403); // not approved
  });
});

describe("break-glass with a real unit-admin (T-25)", () => {
  it("allowed with a justification, alert logged with the real subject; refused without", async () => {
    expect((await call("unit-admin-beta", "GET", "/files/conf-alpha-a")).status).toBe(404);
    expect((await call("unit-admin-beta", "GET", "/files/conf-alpha-a", undefined, { "x-break-glass-justification": "incident 99" })).status).toBe(200);
    const alert = logs.map((l) => JSON.parse(l) as Record<string, unknown>).find((l) => l.msg === "break_glass_alert");
    expect(alert).toMatchObject({ sub: sub("unit-admin-beta"), resourceId: "conf-alpha-a", justification: "incident 99" });
    expect((await call("unit-admin-beta", "GET", "/files/official-alpha", undefined, { "x-break-glass-justification": "  " })).status).toBe(403);
    expect((await call("analyst-official", "GET", "/files/conf-alpha-a", undefined, { "x-break-glass-justification": "incident 99" })).status).toBe(404);
    expect((await call("unit-admin-beta", "GET", "/files/secret-alpha-a", undefined, { "x-break-glass-justification": "incident 99" })).status).toBe(404); // clearance floor
  });
});

describe("decision log with real tokens (T-24)", () => {
  it("has the real subject and no token or claim values", () => {
    const decisions = logs.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.msg === "decision");
    expect(decisions.length).toBeGreaterThan(20);
    expect(decisions.some((d) => d.sub === sub("analyst-official") && d.effect === "deny" && d.reason === "CLEARANCE_TOO_LOW")).toBe(true);
    const all = logs.join("\n");
    for (const t of [...tokens.values(), pwdOnlySecretA]) {
      expect(all).not.toContain(t.access_token);
      expect(all).not.toContain(t.access_token.split(".")[2]!);
    }
  });
});
