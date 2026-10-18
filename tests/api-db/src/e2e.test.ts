// API + Postgres + real Keycloak tokens, end to end (T-11, T-13, T-14, T-15, T-16, T-17, T-25, T-29).
import { randomUUID } from "node:crypto";
import { Controller, Get, Inject } from "@nestjs/common";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type pg from "pg";
import { createApp } from "../../../apps/api/src/app.js";
import { Authenticated } from "../../../apps/api/src/auth/access.js";
import { loadConfig } from "../../../apps/api/src/config.js";
import { toDbContext, withContext } from "../../../apps/api/src/db/context.js";
import { JsonLogger } from "../../../apps/api/src/http/logger.js";
import { sql } from "../../../apps/api/src/db/sql.js";
import { CurrentPrincipal } from "../../../apps/api/src/http/request.js";
import type { Principal } from "../../../apps/api/src/auth/principal.js";
import { DB_POOL } from "../../../apps/api/src/casefiles/case-file.service.js";
import { decode, login, REALM_URL, type Tokens } from "../../identity/src/kc.js";
import { SEED } from "../../identity/src/seed.js";
import { adminPool, appUrl, clearRows, insertRow } from "./db.js";

type User = keyof typeof SEED;
const NOON = Date.UTC(2026, 9, 17, 12, 0, 0);

/** A deliberately BUGGY handler: no policy, no filter. Used to show that the database still protects the data. */
@Controller("buggy")
class BuggyController {
  constructor(@Inject(DB_POOL) private readonly pool: pg.Pool) {}

  @Authenticated()
  @Get("with-context")
  async withCtx(@CurrentPrincipal() p: Principal) {
    const ctx = toDbContext({ id: p.sub, roles: p.roles, clearance: p.clearance, unit: p.unit, compartments: p.compartments }, { acr: p.acr, amr: p.amr, now: 0, networkZone: "x" }, "read");
    return withContext(this.pool, ctx, async (tx) => (await tx.query<{ title: string }>(sql`SELECT title FROM case_files`)).rows.map((r) => r.title));
  }

  @Authenticated()
  @Get("forgot-context")
  async forgot() {
    return (await this.pool.query<{ title: string }>(sql`SELECT title FROM case_files`)).rows.map((r) => r.title); // no transaction context at all
  }
}

const admin = adminPool();
const logs: string[] = [];
const tokens = new Map<string, Tokens>();
let pwdOnlySecretA: Tokens;
let url = "";
let close: () => Promise<void>;
const ids: Record<string, string> = {};

async function call(user: User | "secretAPwd", method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const t = user === "secretAPwd" ? pwdOnlySecretA : tokens.get(user)!;
  const res = await fetch(`${url}${path}`, {
    method,
    headers: { authorization: `Bearer ${t.access_token}`, ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json: Record<string, unknown> & unknown[] = {} as never;
  try {
    json = JSON.parse(text);
  } catch {
    /* not json */
  }
  return { status: res.status, body: json, www: res.headers.get("www-authenticate"), text };
}
const sub = (u: User) => decode(tokens.get(u)!.access_token).claims.sub as string;
const listIds = async (u: User) => ((await call(u, "GET", "/case-files")).body as unknown as { id: string }[]).map((x) => x.id);

beforeAll(async () => {
  await clearRows(admin);
  const mk = async (key: string, r: Parameters<typeof insertRow>[1]) => (ids[key] = await insertRow(admin, { title: key, status: "approved", ...r }));
  await mk("official-alpha", {});
  await mk("official-beta", { unit: "beta" });
  await mk("official-alpha-draft", { status: "draft", authorId: "seed-author" });
  await mk("conf-a", { classification: "CONFIDENTIAL", compartments: ["A"] });
  await mk("conf-a-draft", { classification: "CONFIDENTIAL", compartments: ["A"], status: "draft" });
  await mk("secret-a", { classification: "SECRET", compartments: ["A"] });
  await mk("secret-b", { classification: "SECRET", compartments: ["B"] });

  const cfg = loadConfig({ KEYCLOAK_ISSUER: REALM_URL, DATABASE_URL: appUrl(), THROTTLE_LIMIT: "100000", AUTH_FAIL_LIMIT: "10000", MANAGED_ADDRESSES: "127.0.0.1" });
  const app = await createApp(cfg, { logger: new JsonLogger((l) => logs.push(l)), clock: () => NOON, extraControllers: [BuggyController] });
  await app.listen(0, "127.0.0.1");
  url = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}`;
  close = () => app.close();
  for (const u of Object.keys(SEED)) tokens.set(u, await login(u));
  pwdOnlySecretA = await login("analyst-secret-a", { acrValues: "pwd" });
}, 300_000);
afterAll(async () => {
  await close?.();
  await clearRows(admin);
  await admin.end();
});

describe("reading with real identities (T-15)", () => {
  it("analyst-official: OFFICIAL yes; SECRET, compartmented and nonexistent look identical (404)", async () => {
    const ok = await call("analyst-official", "GET", `/case-files/${ids["official-alpha"]}`);
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ title: "official-alpha", classification: "OFFICIAL", status: "approved", version: 1 });
    const a = await call("analyst-official", "GET", `/case-files/${ids["secret-a"]}`);
    const b = await call("analyst-official", "GET", `/case-files/${ids["conf-a"]}`);
    const c = await call("analyst-official", "GET", `/case-files/${randomUUID()}`);
    expect([a.status, b.status, c.status]).toEqual([404, 404, 404]);
    expect(a.body).toEqual(c.body);
    expect(b.body).toEqual(c.body);
  });

  it("compartment A vs B, with MFA", async () => {
    expect((await call("analyst-secret-a", "GET", `/case-files/${ids["secret-a"]}`)).status).toBe(200);
    expect((await call("analyst-secret-a", "GET", `/case-files/${ids["secret-b"]}`)).status).toBe(404);
    expect((await call("analyst-secret-b", "GET", `/case-files/${ids["secret-b"]}`)).status).toBe(200);
    expect((await call("analyst-secret-b", "GET", `/case-files/${ids["secret-a"]}`)).status).toBe(404);
  });

  it("list = what the read rule allows; no body in lists", async () => {
    const off = await listIds("analyst-official");
    expect(off.sort()).toEqual([ids["official-alpha"], ids["official-beta"], ids["official-alpha-draft"]].sort());
    const sa = await listIds("analyst-secret-a");
    expect(sa).toContain(ids["secret-a"]);
    expect(sa).not.toContain(ids["secret-b"]);
    const row0 = ((await call("analyst-official", "GET", "/case-files")).body as unknown as Record<string, unknown>[])[0]!;
    expect(row0.body).toBeUndefined();
  });

  it("unauthenticated callers get 401 and cannot probe ids", async () => {
    expect((await fetch(`${url}/case-files/${ids["secret-a"]}`)).status).toBe(401);
  });

  it("odd ids are 404, never a database error", async () => {
    for (const id of ["not-a-uuid", "1' OR '1'='1", "x;DROP TABLE case_files", "%00", "00000000-0000-0000-0000-000000000000", "..%2F..", "a".repeat(300)]) {
      expect((await call("analyst-official", "GET", `/case-files/${id}`)).status, id).toBe(404);
    }
  });
});

describe("step-up with a real SECRET token that says acr=pwd (T-17)", () => {
  it("403 with a challenge, not 404; list hides SECRET; uncleared users are not challenged", async () => {
    const r = await call("secretAPwd", "GET", `/case-files/${ids["secret-a"]}`);
    expect(r.status).toBe(403);
    expect(r.www).toContain('acr_values="mfa"');
    expect(r.body).toMatchObject({ code: "STEP_UP_REQUIRED" });
    expect(((await call("secretAPwd", "GET", "/case-files")).body as unknown as { id: string }[]).map((x) => x.id)).not.toContain(ids["secret-a"]);
    expect((await call("secretAPwd", "GET", `/case-files/${ids["secret-b"]}`)).status).toBe(404); // compartment B is not hers: no challenge
    expect((await call("secretAPwd", "GET", `/case-files/${ids["conf-a"]}`)).status).toBe(200);
  });
});

describe("units, roles, IDOR (T-11, T-15)", () => {
  it("unit-admin of another unit: 404 where hidden, 403 where readable; own unit works", async () => {
    expect((await call("unit-admin-beta", "GET", `/case-files/${ids["conf-a-draft"]}`)).status).toBe(404);
    expect((await call("unit-admin-beta", "PATCH", `/case-files/${ids["conf-a-draft"]}`, { title: "x", version: 1 })).status).toBe(404);
    expect((await call("unit-admin-beta", "DELETE", `/case-files/${ids["conf-a-draft"]}`)).status).toBe(404);
    expect((await call("unit-admin-beta", "PATCH", `/case-files/${ids["official-alpha-draft"]}`, { title: "x", version: 1 })).status).toBe(403);
    expect((await call("unit-admin-alpha", "PATCH", `/case-files/${ids["official-alpha-draft"]}`, { title: "ok", version: 1 })).status).toBe(200);
    expect((await admin.query("SELECT title FROM case_files WHERE id = $1", [ids["official-alpha-draft"]])).rows[0].title).toBe("ok");
  });

  it("auditor: no case-file access at all; platform-admin: none either", async () => {
    expect((await call("auditor", "GET", "/case-files")).status).toBe(403);
    expect((await call("auditor", "GET", `/case-files/${ids["official-alpha"]}`)).status).toBe(404);
    expect((await call("auditor", "POST", "/case-files", { title: "t", classification: "OFFICIAL", compartments: [] })).status).toBe(403);
    expect((await call("platform-admin", "GET", `/case-files/${ids["official-alpha"]}`)).status).toBe(404);
    expect((await call("platform-admin", "DELETE", `/case-files/${ids["official-alpha-draft"]}`)).status).toBe(404);
  });
});

describe("lifecycle, separation of duties, optimistic version (T-16)", () => {
  it("create -> stale edit 409 -> edit -> submit -> self-approve refused -> reviewer approves -> frozen -> export", async () => {
    const made = await call("unit-admin-alpha", "POST", "/case-files", { title: "case", body: "details", classification: "OFFICIAL", compartments: [] });
    expect(made.status).toBe(201);
    const id = made.body.id as string;
    expect(made.body).toMatchObject({ status: "draft", version: 1, unit: "alpha", authorId: sub("unit-admin-alpha") });

    expect((await call("unit-admin-alpha", "PATCH", `/case-files/${id}`, { title: "stale", version: 7 })).status).toBe(409);
    const edited = await call("unit-admin-alpha", "PATCH", `/case-files/${id}`, { title: "edited", version: 1 });
    expect(edited.status).toBe(200);
    expect(edited.body).toMatchObject({ title: "edited", version: 2 });

    expect((await call("unit-admin-alpha", "POST", `/case-files/${id}/approve`)).status).toBe(403); // draft
    expect((await call("unit-admin-alpha", "POST", `/case-files/${id}/submit`)).status).toBe(201);
    expect((await admin.query("SELECT submitted_by_id FROM case_files WHERE id = $1", [id])).rows[0].submitted_by_id).toBe(sub("unit-admin-alpha"));
    expect((await call("unit-admin-alpha", "POST", `/case-files/${id}/approve`)).status).toBe(403); // separation of duties
    expect((await call("analyst-official", "POST", `/case-files/${id}/approve`)).status).toBe(403); // analyst has no approve
    expect((await call("reviewer", "POST", `/case-files/${id}/approve`)).status).toBe(201);
    expect((await call("unit-admin-alpha", "PATCH", `/case-files/${id}`, { title: "late", version: 4 })).status).toBe(403);
    expect((await call("unit-admin-alpha", "DELETE", `/case-files/${id}`)).status).toBe(403);
    const exp = await call("analyst-official", "GET", `/case-files/${id}/export`);
    expect(exp.status).toBe(200); // managed address, noon, approved
    expect(exp.body).toMatchObject({ title: "edited", body: "details" });
    expect((await call("analyst-official", "GET", `/case-files/${ids["official-alpha-draft"]}/export`)).status).toBe(403); // not approved
  });

  it("analysts change only their own drafts; delete works for the owner", async () => {
    const made = await call("analyst-official", "POST", "/case-files", { title: "mine", classification: "OFFICIAL", compartments: [] });
    const id = made.body.id as string;
    expect((await call("analyst-secret-a", "PATCH", `/case-files/${id}`, { title: "hijack", version: 1 })).status).toBe(403);
    expect((await call("analyst-secret-a", "DELETE", `/case-files/${id}`)).status).toBe(403);
    expect((await call("analyst-official", "DELETE", `/case-files/${id}`)).status).toBe(200);
    expect((await call("analyst-official", "GET", `/case-files/${id}`)).status).toBe(404);
  });

  it("cannot create above clearance or with compartments one lacks; mass assignment is rejected", async () => {
    const before = (await admin.query("SELECT count(*)::int AS n FROM case_files")).rows[0].n;
    expect((await call("analyst-official", "POST", "/case-files", { title: "t", classification: "SECRET", compartments: [] })).status).toBe(403);
    expect((await call("analyst-official", "POST", "/case-files", { title: "t", classification: "OFFICIAL", compartments: ["A"] })).status).toBe(403);
    expect((await call("analyst-official", "POST", "/case-files", { title: "t", classification: "OFFICIAL", compartments: [], authorId: "x", unit: "beta", status: "approved", version: 9 })).status).toBe(400);
    expect((await admin.query("SELECT count(*)::int AS n FROM case_files")).rows[0].n).toBe(before);
  });

  it("a SECRET file can be created only with MFA by a cleared user", async () => {
    const body = { title: "s", classification: "SECRET", compartments: ["A"] };
    const noMfa = await call("secretAPwd", "POST", "/case-files", body);
    expect(noMfa.status).toBe(403);
    expect(noMfa.body).toMatchObject({ code: "STEP_UP_REQUIRED" });
    const ok = await call("analyst-secret-a", "POST", "/case-files", body);
    expect(ok.status).toBe(201);
    expect((await call("analyst-secret-b", "GET", `/case-files/${ok.body.id}`)).status).toBe(404);
  });
});

describe("break-glass over HTTP and in the database (T-25)", () => {
  it("allowed for a unit-admin with a justification, refused otherwise; alert carries the real subject", async () => {
    const h = { "x-break-glass-justification": "incident 99" };
    expect((await call("unit-admin-beta", "GET", `/case-files/${ids["conf-a"]}`)).status).toBe(404);
    const ok = await call("unit-admin-beta", "GET", `/case-files/${ids["conf-a"]}`, undefined, h);
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ title: "conf-a" });
    const alert = logs.map((l) => JSON.parse(l) as Record<string, unknown>).find((l) => l.msg === "break_glass_alert");
    expect(alert).toMatchObject({ sub: sub("unit-admin-beta"), resourceId: ids["conf-a"], justification: "incident 99" });
    expect((await call("unit-admin-beta", "GET", `/case-files/${ids["official-alpha"]}`, undefined, { "x-break-glass-justification": " " })).status).toBe(403);
    expect((await call("analyst-official", "GET", `/case-files/${ids["conf-a"]}`, undefined, h)).status).toBe(404);
    expect((await call("unit-admin-beta", "GET", `/case-files/${ids["secret-a"]}`, undefined, h)).status).toBe(404); // clearance floor
    expect((await call("unit-admin-beta", "PATCH", `/case-files/${ids["conf-a-draft"]}`, { title: "x", version: 1 }, h)).status).toBe(404); // not for writes
  });
});

describe("SQL injection: hostile values are data (T-14)", () => {
  const EVIL = ["'; DROP TABLE case_files; --", "' OR '1'='1", "\") ; DELETE FROM case_files; --", "$1 ${x} `backtick` \\ \\' %s", "Robert'); DROP TABLE Students;--", "\u{1F600} \u202e", "x".repeat(100)];

  it("title and body round-trip verbatim; the table is intact", async () => {
    const before = (await admin.query("SELECT count(*)::int AS n FROM case_files")).rows[0].n;
    for (const evil of EVIL) {
      const made = await call("unit-admin-alpha", "POST", "/case-files", { title: evil.slice(0, 100), body: evil, classification: "OFFICIAL", compartments: [] });
      expect(made.status, evil).toBe(201);
      const read = await call("unit-admin-alpha", "GET", `/case-files/${made.body.id}`);
      expect(read.body.title).toBe(evil.slice(0, 100));
      expect(read.body.body).toBe(evil);
    }
    const after = (await admin.query("SELECT count(*)::int AS n FROM case_files")).rows[0].n;
    expect(after).toBe(before + EVIL.length);
  });

  it("second order: stored hostile text is used again as a parameter by later operations without effect", async () => {
    const evil = "'); DELETE FROM case_files; --";
    const made = await call("unit-admin-alpha", "POST", "/case-files", { title: evil, body: evil, classification: "OFFICIAL", compartments: [] });
    const id = made.body.id as string;
    const before = (await admin.query("SELECT count(*)::int AS n FROM case_files")).rows[0].n;
    expect((await call("unit-admin-alpha", "PATCH", `/case-files/${id}`, { body: "changed only the body", version: 1 })).status).toBe(200); // title re-sent from storage as $2
    expect((await call("unit-admin-alpha", "POST", `/case-files/${id}/submit`)).status).toBe(201);
    expect((await call("reviewer", "POST", `/case-files/${id}/approve`)).status).toBe(201);
    expect((await call("analyst-official", "GET", `/case-files/${id}/export`)).body.title).toBe(evil);
    expect((await listIds("analyst-official")).length).toBeGreaterThan(3);
    expect((await admin.query("SELECT count(*)::int AS n FROM case_files")).rows[0].n).toBe(before);
  });

  it("hostile compartments and classification are refused (policy 403 first, validation 400 otherwise; never created), NUL bytes too", async () => {
    const before = (await admin.query("SELECT count(*)::int AS n FROM case_files")).rows[0].n;
    // the route guard decides before the validation pipe runs: input the policy cannot make sense of is denied there
    for (const compartments of [["A'); DROP TABLE case_files;--"], ["A,B"], ["x".repeat(33)], [1], "A"]) {
      expect([400, 403], JSON.stringify(compartments)).toContain((await call("unit-admin-alpha", "POST", "/case-files", { title: "t", classification: "OFFICIAL", compartments })).status);
    }
    expect([400, 403]).toContain((await call("unit-admin-alpha", "POST", "/case-files", { title: "t", classification: "OFFICIAL'; --", compartments: [] })).status);
    expect((await admin.query("SELECT count(*)::int AS n FROM case_files")).rows[0].n).toBe(before);
    expect((await call("unit-admin-alpha", "POST", "/case-files", { title: "a\u0000b", classification: "OFFICIAL", compartments: [] })).status).toBe(400);
    expect((await call("unit-admin-alpha", "POST", "/case-files", { title: "", classification: "OFFICIAL", compartments: [] })).status).toBe(400);
    expect((await call("unit-admin-alpha", "POST", "/case-files", { title: "x".repeat(101), classification: "OFFICIAL", compartments: [] })).status).toBe(400);
  });

  it("an identity claim that looks like SQL cannot reach rows (the subject comes from the verified token only)", async () => {
    // headers and query strings are never read as identity
    const r = await call("analyst-official", "GET", `/case-files?sub=x'%20OR%201=1&clearance=SECRET`, undefined, { "x-clearance": "SECRET", "x-sub": "' OR 1=1 --" });
    expect(((r.body as unknown as { classification: string }[]).map((x) => x.classification))).not.toContain("SECRET");
  });
});

describe("defence in depth: the database protects the data when the app is wrong (T-15)", () => {
  it("a handler with no policy and no filter still returns only what RLS allows for the caller", async () => {
    const off = (await call("analyst-official", "GET", "/buggy/with-context")).body as unknown as string[];
    expect(off).toContain("official-alpha");
    expect(off).not.toContain("secret-a");
    expect(off).not.toContain("conf-a");
    const sa = (await call("analyst-secret-a", "GET", "/buggy/with-context")).body as unknown as string[];
    expect(sa).toContain("secret-a");
    expect(sa).not.toContain("secret-b");
    const aud = (await call("auditor", "GET", "/buggy/with-context")).body as unknown as string[];
    expect(aud).toEqual([]); // auditor role has no read grant
  });

  it("a handler that forgot to set the context returns nothing (fail closed)", async () => {
    expect((await call("unit-admin-alpha", "GET", "/buggy/forgot-context")).body).toEqual([]);
  });
});

describe("hygiene (T-24)", () => {
  it("decision lines are authoritative and carry no tokens or claim dumps", () => {
    const lines = logs.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.msg === "decision");
    expect(lines.some((l) => l.authoritative === true)).toBe(true);
    const all = logs.join("\n");
    for (const t of [...tokens.values(), pwdOnlySecretA]) expect(all).not.toContain(t.access_token.split(".")[2]!);
    expect(all).not.toContain("DROP TABLE"); // request bodies are never logged
  });
});
