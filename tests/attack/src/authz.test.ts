// A-20..A-29: broken object-level and function-level authorisation, every seed user against every class of resource, through the BFF like a user would.
import { beforeAll, describe, expect, it } from "vitest";
import { fixtures, type Fixtures } from "./fixtures.js";
import { SEED_USERS, type SeedUser } from "./kc.js";
import { bff, session } from "./sessions.js";
import { vault } from "./http.js";

let f: Fixtures;
beforeAll(() => {
  f = fixtures();
}, 120_000);

// ground truth from the access model (docs/policy.md): role may read, clearance floor, every compartment held, SECRET needs MFA (the secret users logged in with it)
const CAN_READ: Record<keyof Fixtures, SeedUser[]> = {
  offAlpha: ["analyst-official", "analyst-secret-a", "analyst-secret-b", "reviewer", "unit-admin-alpha", "unit-admin-beta"],
  offBeta: ["analyst-official", "analyst-secret-a", "analyst-secret-b", "reviewer", "unit-admin-alpha", "unit-admin-beta"],
  confAlphaA: ["analyst-secret-a", "reviewer"],
  secAlphaA: ["analyst-secret-a"],
  secAlphaB: ["analyst-secret-b"],
  submittedAlpha: ["analyst-official", "analyst-secret-a", "analyst-secret-b", "reviewer", "unit-admin-alpha", "unit-admin-beta"],
};

describe("A-20 object-level access: every user against every class of case file", () => {
  it("each pair is exactly what the access model says: 200 for the entitled, the same 404 for everyone else", async () => {
    const bodies404 = new Set<string>();
    for (const user of SEED_USERS) {
      const s = await session(user);
      for (const [name, id] of Object.entries(f) as [keyof Fixtures, string][]) {
        const r = await bff(s, "GET", `/case-files/${id}`);
        const should = CAN_READ[name].includes(user);
        expect(r.status, `${user} reading ${name}`).toBe(should ? 200 : 404);
        if (!should) bodies404.add(r.text);
      }
    }
    expect(bodies404.size, "every refusal looks the same (hidden = not found)").toBe(1);
  });
});

describe("A-21 listing: a list never contains a file the user could not open", () => {
  it("the list of each user equals the files they can read", async () => {
    for (const user of SEED_USERS) {
      const s = await session(user);
      const r = await bff(s, "GET", "/case-files");
      if (user === "auditor" || user === "platform-admin") {
        expect(r.status, user).toBe(403); // no read right on case files at all: a list needs the role
        continue;
      }
      expect(r.status, user).toBe(200);
      const ids = new Set((r.json as { id: string }[]).map((x) => x.id));
      for (const [name, id] of Object.entries(f) as [keyof Fixtures, string][]) expect(ids.has(id), `${user} list contains ${name}`).toBe(CAN_READ[name].includes(user));
    }
  });
});

describe("A-22 function-level: roles cannot perform actions their role lacks", () => {
  it("analyst cannot approve, reviewer cannot create or edit, auditor and platform admin cannot touch case files", async () => {
    const analyst = await session("analyst-official");
    const reviewer = await session("reviewer");
    expect([403, 404]).toContain((await bff(analyst, "POST", `/case-files/${f.submittedAlpha}/approve`, {})).status);
    expect((await bff(reviewer, "POST", "/case-files", { title: "x", classification: "OFFICIAL", compartments: [] })).status).toBe(403);
    expect((await bff(reviewer, "PATCH", `/case-files/${f.offAlpha}`, { title: "x", version: 1 })).status).toBe(403);
    for (const user of ["auditor", "platform-admin"] as const) {
      const s = await session(user);
      expect((await bff(s, "POST", "/case-files", { title: "x", classification: "OFFICIAL", compartments: [] })).status, user).toBe(403);
      expect((await bff(s, "PATCH", `/case-files/${f.offAlpha}`, { title: "x", version: 1 })).status, user).toBe(404);
      expect((await bff(s, "DELETE", `/case-files/${f.offAlpha}`)).status, user).toBe(404);
    }
  });
  it("cross-unit write: a unit admin of another unit cannot change or approve a file of unit alpha, an analyst cannot edit what she did not write", async () => {
    const beta = await session("unit-admin-beta");
    const analyst = await session("analyst-official");
    expect([403, 404]).toContain((await bff(beta, "PATCH", `/case-files/${f.submittedAlpha}`, { title: "x", version: 1 })).status);
    expect([403, 404]).toContain((await bff(beta, "POST", `/case-files/${f.submittedAlpha}/approve`, {})).status);
    expect([403, 404]).toContain((await bff(analyst, "PATCH", `/case-files/${f.offAlpha}`, { title: "x", version: 1 })).status);
    expect([403, 404]).toContain((await bff(analyst, "DELETE", `/case-files/${f.offAlpha}`)).status);
  });
});

describe("A-23 separation of duties and the status machine", () => {
  it("an author cannot approve what she submitted; nobody approves a draft; a frozen file cannot be edited", async () => {
    const admin = await session("unit-admin-alpha");
    const made = await bff(admin, "POST", "/case-files", { title: "attack: own submission", classification: "OFFICIAL", compartments: [] });
    expect(made.status).toBe(201);
    const id = (made.json as { id: string }).id;
    expect((await bff(admin, "POST", `/case-files/${id}/approve`, {})).status).toBe(403); // a draft
    expect((await bff(admin, "POST", `/case-files/${id}/submit`, {})).status).toBe(201);
    expect((await bff(admin, "POST", `/case-files/${id}/approve`, {})).status).toBe(403); // her own submission
    expect((await bff(admin, "PATCH", `/case-files/${id}`, { title: "late edit", version: 3 })).status).toBe(403); // frozen
    const reviewer = await session("reviewer");
    expect((await bff(reviewer, "POST", `/case-files/${id}/approve`, {})).status).toBe(201); // somebody else may
    expect((await bff(reviewer, "POST", `/case-files/${id}/approve`, {})).status).toBe(403); // not twice
  });
});

describe("A-24 mass assignment: fields the client must not control", () => {
  const base = { title: "attack: mass", classification: "OFFICIAL", compartments: [] };
  it.each([
    ["author_id", { author_id: "someone-else" }],
    ["authorId", { authorId: "someone-else" }],
    ["unit", { unit: "beta" }],
    ["status", { status: "approved" }],
    ["roles", { roles: ["platform-admin"] }],
    ["submitted_by_id", { submitted_by_id: "x" }],
    ["version", { version: 99 }],
    ["id", { id: "00000000-0000-4000-8000-000000000001" }],
    ["__proto__", JSON.parse('{"__proto__": {"classification": "SECRET"}}')],
    ["constructor", { constructor: { prototype: { status: "approved" } } }],
  ])("create with an extra %s is refused", async (_n, extra) => {
    const s = await session("analyst-official");
    const r = await vault("/bff/case-files", { method: "POST", jar: s.jar, headers: { origin: "https://vault.localhost", "x-csrf-token": s.csrf, "content-type": "application/json" }, body: JSON.stringify({ ...base, ...extra }).replace(/^\{/, "{") });
    expect(r.status).toBe(400);
  });
  it("update with extra fields, and a classification change, is refused; nothing changed", async () => {
    const s = await session("unit-admin-alpha");
    const id = ((await bff(s, "POST", "/case-files", { ...base, title: "attack: edit target" })).json as { id: string }).id;
    for (const extra of [{ classification: "SECRET" }, { unit: "beta" }, { status: "approved" }, { author_id: "x" }, { compartments: ["A"] }]) {
      expect((await bff(s, "PATCH", `/case-files/${id}`, { title: "t", version: 1, ...extra })).status, JSON.stringify(extra)).toBe(400);
    }
    const now = (await bff(s, "GET", `/case-files/${id}`)).json as { classification: string; unit: string; status: string; version: number };
    expect(now).toMatchObject({ classification: "OFFICIAL", unit: "alpha", status: "draft", version: 1 });
  });
  it("create above the user's own clearance, or in compartments she does not hold, is refused", async () => {
    const s = await session("analyst-official");
    expect((await bff(s, "POST", "/case-files", { ...base, classification: "SECRET" })).status).toBe(403);
    expect((await bff(s, "POST", "/case-files", { ...base, compartments: ["A"] })).status).toBe(403);
  });
});

describe("A-25 the audit trail is for auditors only", () => {
  it("everyone else gets nothing from the audit endpoints and the export, and the auditor does", async () => {
    for (const user of SEED_USERS) {
      const s = await session(user);
      for (const path of ["/audit-log", "/audit-log/checkpoints", "/audit-log/verify", "/audit-log/export"]) {
        const r = await bff(s, "GET", path);
        expect(r.status, `${user} ${path}`).toBe(user === "auditor" ? 200 : 403);
      }
      const page = await vault("/audit", { jar: s.jar });
      expect([200, 403, 404], `${user} page`).toContain(page.status);
      if (user !== "auditor") expect(page.text).not.toMatch(/audit\.|actor_sub|reason_code/);
    }
  });
  it("the auditor cannot read case files, attachments or exports", async () => {
    const a = await session("auditor");
    expect((await bff(a, "GET", `/case-files/${f.offAlpha}`)).status).toBe(404);
    expect((await bff(a, "GET", `/case-files/${f.offAlpha}/export`)).status).toBe(404);
    expect((await bff(a, "GET", `/case-files/${f.offAlpha}/attachments`)).status).toBe(404);
  });
});

describe("A-26 export needs the managed zone: an attacker cannot talk her way in", () => {
  it("an approved file cannot be exported from here, whatever the request says about the client address or zone", async () => {
    const s = await session("analyst-official");
    const spoof = { "x-acl-zone": "managed", "x-acl-client-ip": "10.1.2.3", "x-forwarded-for": "10.1.2.3", "x-real-ip": "10.1.2.3", forwarded: "for=10.1.2.3", "x-acl-proxy-secret": "guess" };
    expect((await bff(s, "GET", `/case-files/${f.offAlpha}/export`)).status).toBe(403);
    expect((await bff(s, "GET", `/case-files/${f.offAlpha}/export`, undefined, spoof)).status).toBe(403);
  });
});
