// The guard and the policy engine together, with signed tokens and the in-memory fixture (T-11, T-15, T-16, T-17, T-25).
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseZoneKeys, signZone, type Zone } from "@acl/netguard";
import { CaseFileStore, FIXTURE } from "../test/casefile-fixture.js";
import { JwksServer, bearer, boot, goodClaims, makeKey, sign, type Booted, type TestKey } from "../test/harness.js";

const ACR_HIGH = { acr: "mfa", amr: ["pwd", "otp"] };
const USERS = {
  analystOfficial: { sub: "u-analyst-official", roles: ["analyst"], clearance: "OFFICIAL", unit: "alpha" },
  analystSecretA: { sub: "u-analyst-secret-a", roles: ["analyst"], clearance: "SECRET", unit: "alpha", compartments: ["A"], ...ACR_HIGH },
  analystSecretB: { sub: "u-analyst-secret-b", roles: ["analyst"], clearance: "SECRET", unit: "alpha", compartments: ["B"], ...ACR_HIGH },
  reviewer: { sub: "u-reviewer", roles: ["reviewer"], clearance: "CONFIDENTIAL", unit: "alpha", compartments: ["A"] },
  adminAlpha: { sub: "u-admin-alpha", roles: ["unit-admin"], clearance: "CONFIDENTIAL", unit: "alpha" },
  adminBeta: { sub: "u-admin-beta", roles: ["unit-admin"], clearance: "CONFIDENTIAL", unit: "beta" },
  auditor: { sub: "u-auditor", roles: ["auditor"], clearance: "OFFICIAL", unit: "hq" },
  platformAdmin: { sub: "u-platform-admin", roles: ["platform-admin"], clearance: "OFFICIAL", unit: "hq" },
} as const;
type User = keyof typeof USERS;

let jwks: JwksServer;
let key: TestKey;
let api: Booted;
let store: CaseFileStore;
const NOON = Date.UTC(2026, 9, 17, 12, 0, 0);
const ZONE_KEYS = `z1:${Buffer.alloc(32, 7).toString("base64")}`;
/** what the BFF sends: the zone, signed for this subject at the current time (freshness uses real time, the policy clock is fixed in this fixture) */
const zoneFor = (sub: string, zone: Zone = "managed", at = Date.now(), keys = ZONE_KEYS) => ({ "x-acl-zone": signZone(parseZoneKeys(keys), zone, sub, Math.floor(at / 1000)) });

async function tokenFor(u: User | (typeof USERS)[User], over: Record<string, unknown> = {}) {
  const x = (typeof u === "string" ? USERS[u] : u) as Record<string, unknown> & { roles: readonly string[] };
  const { roles, ...rest } = x;
  return sign(goodClaims({ ...rest, realm_access: { roles: [...roles, "default-roles-casefile"] }, ...over }), key);
}

async function call(b: Booted, who: User | (typeof USERS)[User], method: string, path: string, body?: unknown, headers: Record<string, string> = {}, over: Record<string, unknown> = {}, zone: Zone | "none" = "managed", at = Date.now()) {
  const res = await fetch(`${b.url}${path}`, {
    method,
    headers: { ...bearer(await tokenFor(who, over)), ...(zone !== "none" ? zoneFor((typeof who === "string" ? USERS[who] : who).sub, zone, at) : {}), ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json: unknown;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, body: json as Record<string, unknown> & unknown[], www: res.headers.get("www-authenticate"), text };
}
const c = (...a: Parameters<typeof call> extends [Booted, ...infer R] ? R : never) => call(api, ...a);

beforeAll(async () => {
  key = await makeKey("k1");
  jwks = await new JwksServer().start();
  jwks.keys = [key.publicJwk];
  api = await boot(jwks.url, { ZONE_SIGNING_KEYS: ZONE_KEYS }, FIXTURE.controllers, { providers: FIXTURE.providers, clock: () => NOON });
  store = api.app.get(CaseFileStore);
});
afterAll(async () => {
  await api.close();
  await jwks.stop();
});

describe("reading: clearance, compartments, existence hiding (T-15)", () => {
  it("OFFICIAL analyst: OFFICIAL yes; SECRET, compartmented and nonexistent look identical (404)", async () => {
    expect((await c("analystOfficial", "GET", "/files/official-alpha")).status).toBe(200);
    const hidden = await c("analystOfficial", "GET", "/files/secret-alpha-a");
    const compart = await c("analystOfficial", "GET", "/files/conf-alpha-a");
    const missing = await c("analystOfficial", "GET", "/files/does-not-exist");
    expect([hidden.status, compart.status, missing.status]).toEqual([404, 404, 404]);
    expect(hidden.body).toEqual(missing.body);
    expect(compart.body).toEqual(missing.body);
    expect(hidden.www).toBeNull(); // nothing that distinguishes them
  });

  it("odd ids are 404, never an error that reveals the loader", async () => {
    for (const id of ["..%2F..%2Fetc", "a b", "x".repeat(200), "%00", "constructor", "__proto__"]) {
      expect((await c("analystOfficial", "GET", `/files/${id}`)).status, id).toBe(404);
    }
  });

  it("compartment A vs B on SECRET files", async () => {
    expect((await c("analystSecretA", "GET", "/files/secret-alpha-a")).status).toBe(200);
    expect((await c("analystSecretA", "GET", "/files/secret-alpha-b")).status).toBe(404);
    expect((await c("analystSecretB", "GET", "/files/secret-alpha-b")).status).toBe(200);
    expect((await c("analystSecretB", "GET", "/files/secret-alpha-a")).status).toBe(404);
    expect((await c("analystSecretB", "GET", "/files/conf-alpha-a")).status).toBe(404); // lacks compartment A
  });

  it("unauthenticated callers cannot probe ids at all", async () => {
    const r = await fetch(`${api.url}/files/secret-alpha-a`);
    expect(r.status).toBe(401);
  });

  it("list returns only readable rows, same rule as read", async () => {
    const ids = async (u: User, over = {}) => ((await c(u, "GET", "/files", undefined, {}, over)).body as { id: string }[]).map((x) => x.id).sort();
    expect(await ids("analystOfficial")).toEqual(["official-alpha", "official-alpha-draft", "official-beta"]);
    expect(await ids("analystSecretA")).toEqual(["conf-alpha-a", "conf-alpha-a-draft", "conf-alpha-a-submitted", "official-alpha", "official-alpha-draft", "official-beta", "secret-alpha-a"]);
    // same user, password-only session: SECRET rows disappear from the list
    expect(await ids("analystSecretA", { acr: "pwd", amr: ["pwd"] })).not.toContain("secret-alpha-a");
    expect(await ids("reviewer")).toEqual(["conf-alpha-a", "conf-alpha-a-draft", "conf-alpha-a-submitted", "official-alpha", "official-alpha-draft", "official-beta"]);
  });
});

describe("step-up for SECRET (T-17)", () => {
  it("cleared user without ACR_HIGH: 403 with an RFC 9470 challenge and a machine code", async () => {
    const r = await c("analystSecretA", "GET", "/files/secret-alpha-a", undefined, {}, { acr: "pwd", amr: ["pwd"] });
    expect(r.status).toBe(403);
    expect(r.www).toContain('error="insufficient_user_authentication"');
    expect(r.www).toContain('acr_values="mfa"');
    expect(r.body).toEqual({ statusCode: 403, error: "Forbidden", code: "STEP_UP_REQUIRED" });
  });

  it("acr_values=pwd downgrade (otp in amr, acr pwd) is still step-up required", async () => {
    const r = await c("analystSecretA", "GET", "/files/secret-alpha-a", undefined, {}, { acr: "pwd", amr: ["pwd", "otp"] });
    expect(r.status).toBe(403);
    expect(r.body.code).toBe("STEP_UP_REQUIRED");
  });

  it("acr=mfa without otp in amr is not enough either", async () => {
    const r = await c("analystSecretA", "GET", "/files/secret-alpha-a", undefined, {}, { acr: "mfa", amr: ["pwd"] });
    expect(r.status).toBe(403);
    expect(r.body.code).toBe("STEP_UP_REQUIRED");
  });

  it("an uncleared user is not told to step up: 404, the challenge would confirm the file exists", async () => {
    const r = await c("analystSecretB", "GET", "/files/secret-alpha-a", undefined, {}, { acr: "pwd", amr: ["pwd"] });
    expect(r.status).toBe(404);
    expect(r.www).toBeNull();
  });

  it("other 403s carry no code", async () => {
    const r = await c("auditor", "POST", "/files", { title: "t", classification: "OFFICIAL", compartments: [] });
    expect(r.status).toBe(403);
    expect(r.body).toEqual({ statusCode: 403, error: "Forbidden" });
  });
});

describe("roles outside the matrix (T-11)", () => {
  it("auditor: audit yes; case files hidden (404); cannot create or manage users", async () => {
    expect((await c("auditor", "GET", "/audit")).status).toBe(200);
    expect((await c("auditor", "GET", "/files/official-alpha")).status).toBe(404);
    expect((await c("auditor", "GET", "/files")).status).toBe(403);
    expect((await c("auditor", "POST", "/files", { title: "t", classification: "OFFICIAL", compartments: [] })).status).toBe(403);
    expect((await c("auditor", "GET", "/admin/users")).status).toBe(403);
  });

  it("platform-admin: users yes; no implicit case access", async () => {
    expect((await c("platformAdmin", "GET", "/admin/users")).status).toBe(200);
    expect((await c("platformAdmin", "GET", "/audit")).status).toBe(403);
    expect((await c("platformAdmin", "GET", "/files/official-alpha")).status).toBe(404);
    expect((await c("platformAdmin", "DELETE", "/files/official-alpha-draft")).status).toBe(404);
  });

  it("a token with no application role is denied everywhere", async () => {
    const ghost = { sub: "u-none", roles: [] as string[], clearance: "SECRET", unit: "alpha", compartments: ["A"], ...ACR_HIGH };
    for (const [m, p] of [["GET", "/files"], ["GET", "/files/official-alpha"], ["GET", "/audit"], ["GET", "/admin/users"]] as const) {
      const r = await c(ghost as never, m, p);
      expect([403, 404], `${m} ${p}`).toContain(r.status);
    }
  });
});

describe("writes: unit scope, ownership, mass assignment (T-13, T-15)", () => {
  it("other unit's admin cannot change a file in the unit; a file they cannot read is 404 (IDOR)", async () => {
    expect((await c("adminBeta", "PATCH", "/files/conf-alpha-a-draft", { title: "x" })).status).toBe(404); // compartment A missing
    expect((await c("adminBeta", "PATCH", "/files/official-alpha-draft", { title: "x" })).status).toBe(403); // readable, wrong unit
    expect((await c("adminBeta", "DELETE", "/files/official-alpha-draft")).status).toBe(403);
    expect(store.files.get("official-alpha-draft")!.title).toBe("title of official-alpha-draft");
    expect((await c("adminAlpha", "PATCH", "/files/official-alpha-draft", { title: "changed" })).status).toBe(200);
  });

  it("analyst changes only own drafts", async () => {
    const made = await c("analystOfficial", "POST", "/files", { title: "mine", classification: "OFFICIAL", compartments: [] });
    expect(made.status).toBe(201);
    const id = (made.body as unknown as { id: string }).id;
    expect(store.files.get(id)).toMatchObject({ authorId: "u-analyst-official", ownerUnit: "alpha", status: "draft" });
    expect((await c("analystSecretA", "PATCH", `/files/${id}`, { title: "hijack" })).status).toBe(403);
    expect((await c("analystSecretA", "DELETE", `/files/${id}`)).status).toBe(403);
    expect((await c("analystOfficial", "PATCH", `/files/${id}`, { title: "renamed" })).status).toBe(200);
    expect((await c("analystOfficial", "DELETE", `/files/${id}`)).status).toBe(200);
  });

  it("cannot create above clearance or with compartments one lacks; nothing is stored", async () => {
    const before = store.files.size;
    expect((await c("analystOfficial", "POST", "/files", { title: "t", classification: "SECRET", compartments: [] })).status).toBe(403);
    expect((await c("analystOfficial", "POST", "/files", { title: "t", classification: "OFFICIAL", compartments: ["A"] })).status).toBe(403);
    expect((await c("analystSecretA", "POST", "/files", { title: "t", classification: "SECRET", compartments: ["A"] }, {}, { acr: "pwd", amr: ["pwd"] })).status).toBe(403);
    expect(store.files.size).toBe(before);
  });

  it("mass assignment is rejected, not ignored", async () => {
    const r = await c("analystOfficial", "POST", "/files", { title: "t", classification: "OFFICIAL", compartments: [], ownerUnit: "beta", status: "approved", authorId: "someone" });
    expect(r.status).toBe(400);
    const r2 = await c("adminAlpha", "PATCH", "/files/official-alpha-draft", { title: "t", classification: "SECRET" });
    expect(r2.status).toBe(400);
  });

  it("invalid enum or shape fails validation after policy has run", async () => {
    expect((await c("analystOfficial", "POST", "/files", { title: "t", classification: "TOPSECRET", compartments: [] })).status).toBe(403); // policy: invalid input denies first
    expect((await c("analystOfficial", "POST", "/files", { title: "t", classification: "OFFICIAL", compartments: "A" })).status).toBe(403);
  });
});

describe("lifecycle and separation of duties (T-16)", () => {
  it("draft -> submit -> approve by someone else; no edit after approval; no delete after submit", async () => {
    const made = await c("adminAlpha", "POST", "/files", { title: "case", classification: "OFFICIAL", compartments: [] });
    const id = (made.body as unknown as { id: string }).id;
    expect((await c("adminAlpha", "POST", `/files/${id}/approve`)).status).toBe(403); // still a draft
    expect((await c("adminAlpha", "POST", `/files/${id}/submit`)).status).toBe(201);
    expect((await c("adminAlpha", "DELETE", `/files/${id}`)).status).toBe(403); // submitted
    expect((await c("adminAlpha", "POST", `/files/${id}/approve`)).status).toBe(403); // own file: separation of duties
    expect(store.files.get(id)!.status).toBe("submitted");
    expect((await c("analystOfficial", "POST", `/files/${id}/approve`)).status).toBe(403); // analyst has no approve
    expect((await c("reviewer", "POST", `/files/${id}/approve`)).status).toBe(201);
    expect(store.files.get(id)!.status).toBe("approved");
    expect((await c("adminAlpha", "PATCH", `/files/${id}`, { title: "late edit" })).status).toBe(403);
    expect((await c("adminAlpha", "DELETE", `/files/${id}`)).status).toBe(403);
  });

  it("the submitter cannot approve either", async () => {
    // seed file authored by someone else, submitted by the reviewer
    store.files.set("sub-by-reviewer", { ...store.files.get("conf-alpha-a-submitted")!, id: "sub-by-reviewer", submittedById: "u-reviewer" });
    expect((await c("reviewer", "POST", "/files/sub-by-reviewer/approve")).status).toBe(403);
    expect((await c("adminAlpha", "POST", "/files/sub-by-reviewer/approve")).status).toBe(404); // admin alpha lacks compartment A: cannot even see it
  });
});

describe("export: network zone and time window", () => {
  it("managed address inside the window is allowed", async () => {
    expect((await c("analystOfficial", "GET", "/files/official-alpha/export")).status).toBe(200);
  });

  it("outside the window", async () => {
    const at = Date.UTC(2026, 9, 17, 3, 0, 0);
    const night = await boot(jwks.url, { ZONE_SIGNING_KEYS: ZONE_KEYS }, FIXTURE.controllers, { providers: FIXTURE.providers, clock: () => at });
    expect((await call(night, "analystOfficial", "GET", "/files/official-alpha/export", undefined, {}, {}, "managed")).status).toBe(403);
    await night.close();
  });

  it("no zone header, or the BFF says unmanaged: refused", async () => {
    expect((await c("analystOfficial", "GET", "/files/official-alpha/export", undefined, {}, {}, "none")).status).toBe(403);
    expect((await c("analystOfficial", "GET", "/files/official-alpha/export", undefined, {}, {}, "unmanaged")).status).toBe(403);
  });

  it("a zone claim from anyone but the BFF is ignored: plain headers, forged MAC, other subject, other key, stale, replay on another user", async () => {
    const sub = USERS.analystOfficial.sub;
    const forged = signZone(parseZoneKeys(ZONE_KEYS), "managed", sub, Math.floor(Date.now() / 1000)).replace(/.$/, (ch) => (ch === "A" ? "B" : "A"));
    const bad: Record<string, string>[] = [
      { "x-forwarded-for": "10.1.2.3", "x-real-ip": "10.1.2.3", "x-acl-zone": "managed" },
      { "x-acl-zone": "v1.z1.0.managed.AAAA" },
      { "x-acl-zone": forged },
      zoneFor("u-somebody-else"), // signed for somebody else
      zoneFor(sub, "managed", Date.now(), `z1:${Buffer.alloc(32, 8).toString("base64")}`), // another key
      zoneFor(sub, "managed", Date.now() - 120_000), // stale
    ];
    for (const h of bad) {
      const r = await c("analystOfficial", "GET", "/files/official-alpha/export", undefined, h, {}, "none");
      expect(r.status, JSON.stringify(h)).toBe(403);
    }
    expect(api.logs.some((l) => l.includes("zone_header_rejected"))).toBe(true);
  });

  it("without a configured key ring even a well-formed header changes nothing", async () => {
    const bare = await boot(jwks.url, {}, FIXTURE.controllers, { providers: FIXTURE.providers, clock: () => NOON });
    expect((await call(bare, "analystOfficial", "GET", "/files/official-alpha/export")).status).toBe(403);
    await bare.close();
  });
});

describe("break-glass (T-25)", () => {
  const BG = "x-break-glass-justification";

  it("unit-admin of another unit reads a compartmented file with a justification; an alert is logged", async () => {
    expect((await c("adminBeta", "GET", "/files/conf-alpha-a")).status).toBe(404);
    const r = await c("adminBeta", "GET", "/files/conf-alpha-a", undefined, { [BG]: "incident 4711" });
    expect(r.status).toBe(200);
    const alert = api.logs.map((l) => JSON.parse(l) as Record<string, unknown>).find((l) => l.msg === "break_glass_alert");
    expect(alert).toMatchObject({ sub: "u-admin-beta", action: "read", resourceId: "conf-alpha-a", effect: "allow", reason: "ALLOWED_BREAK_GLASS", justification: "incident 4711" });
  });

  it("a justification in any script travels percent-encoded and is logged as written; plain text with a literal % still works", async () => {
    const r = await c("adminBeta", "GET", "/files/conf-alpha-a", undefined, { [BG]: encodeURIComponent("інцидент 4711 \u{1F600}") });
    expect(r.status).toBe(200);
    const alerts = api.logs.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.msg === "break_glass_alert");
    expect(alerts.at(-1)).toMatchObject({ justification: "інцидент 4711 \u{1F600}" });
    expect((await c("adminBeta", "GET", "/files/conf-alpha-a", undefined, { [BG]: "100% sure, incident 7" })).status).toBe(200); // not valid percent-encoding: used as it is
    expect((await c("adminBeta", "GET", "/files/conf-alpha-a", undefined, { [BG]: encodeURIComponent("\u0007\u202e") })).status, "only control and bidi characters: blank after cleaning").toBe(404);
  });

  it("empty justification: refused", async () => {
    expect((await c("adminBeta", "GET", "/files/official-alpha", undefined, { [BG]: " " })).status).toBe(403);
    expect((await c("adminBeta", "GET", "/files/conf-alpha-a", undefined, { [BG]: "" })).status).toBe(404);
  });

  it("roles without the grant gain nothing", async () => {
    for (const u of ["analystOfficial", "reviewer", "auditor"] as const) {
      expect((await c(u, "GET", "/files/secret-alpha-b", undefined, { [BG]: "incident" })).status, u).toBe(404);
    }
    expect((await c("analystOfficial", "GET", "/files/conf-alpha-a", undefined, { [BG]: "incident" })).status).toBe(404);
  });

  it("never beats the clearance floor", async () => {
    expect((await c("adminBeta", "GET", "/files/secret-alpha-a", undefined, { [BG]: "incident" })).status).toBe(404);
  });

  it("break-glass is for reading: writes ignore it", async () => {
    expect((await c("adminBeta", "PATCH", "/files/conf-alpha-a-draft", { title: "x" }, { [BG]: "incident" })).status).toBe(404);
  });
});

describe("decision log (T-24)", () => {
  it("one structured line per decision: sub, action, resource, effect, reason; no token, no claim dump", async () => {
    api.logs.length = 0;
    const token = await tokenFor("analystOfficial");
    await fetch(`${api.url}/files/secret-alpha-a`, { headers: bearer(token) });
    await fetch(`${api.url}/files/official-alpha`, { headers: bearer(token) });
    const lines = api.logs.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.msg === "decision");
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatchObject({ sub: "u-analyst-official", action: "read", resourceId: "secret-alpha-a", effect: "deny", reason: "CLEARANCE_TOO_LOW" });
    expect(lines[1]).toMatchObject({ resourceId: "official-alpha", effect: "allow", reason: "ALLOWED", obligations: ["audit"] });
    expect(Object.keys(lines[0]!).sort()).toEqual(["action", "effect", "level", "msg", "obligations", "reason", "reqId", "resourceId", "rules", "sub", "time"]);
    const all = api.logs.join("\n");
    expect(all).not.toContain(token);
    for (const claim of ['"clearance"', '"compartments"', '"realm_access"', '"unit"']) expect(all).not.toContain(claim);
  });

  it("a nonexistent id is logged as RESOURCE_NOT_FOUND, answered like a hidden one", async () => {
    api.logs.length = 0;
    await c("analystOfficial", "GET", "/files/does-not-exist");
    const l = api.logs.map((x) => JSON.parse(x) as Record<string, unknown>).find((x) => x.msg === "decision");
    expect(l).toMatchObject({ reason: "RESOURCE_NOT_FOUND", effect: "deny" });
  });
});
