// Time-of-check/time-of-use, optimistic versioning, pooled-connection hygiene, timeouts (T-14, T-15, T-16, T-27, T-29).
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { CaseFileRepository } from "../../../apps/api/src/db/case-file.repository.js";
import { withContext } from "../../../apps/api/src/db/context.js";
import { sql } from "../../../apps/api/src/db/sql.js";
import { JsonLogger } from "../../../apps/api/src/http/logger.js";
import { MemoryAuditWriter } from "../../../apps/api/src/audit/audit.js";
import { CaseFileService, type Caller } from "../../../apps/api/src/casefiles/case-file.service.js";
import { adminPool, appPool, appUrl, clearRows, ctxOf, envOf, insertRow, MFA_ENV, subjectOf } from "./db.js";
import pg from "pg";

const admin = adminPool();
const pool = appPool(8);
const logs: string[] = [];
const files = new CaseFileService(pool, new CaseFileRepository(), new JsonLogger((l) => logs.push(l)), new MemoryAuditWriter());
afterAll(async () => {
  await clearRows(admin);
  await admin.end();
  await pool.end();
});
beforeEach(async () => {
  await clearRows(admin);
  logs.length = 0;
});

const caller = (s: Parameters<typeof subjectOf>[0], e = envOf()): Caller => ({ subject: subjectOf(s), env: e, reqId: "test" });
const analyst = (id = "u1") => caller({ id, roles: ["analyst"] });
const reviewer = (id: string) => caller({ id, roles: ["reviewer"], clearance: "CONFIDENTIAL" });
const unitAdmin = (id: string) => caller({ id, roles: ["unit-admin"], clearance: "CONFIDENTIAL" });
const status = (e: unknown) => (e as { getStatus?: () => number }).getStatus?.() ?? -1;
const settle = async <T>(p: Promise<T>) => p.then((v) => ({ ok: true as const, v }), (e) => ({ ok: false as const, status: status(e), e }));
const row = async (id: string) => (await admin.query("SELECT status, title, version, submitted_by_id FROM case_files WHERE id = $1", [id])).rows[0];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitUntilBlocked(): Promise<void> {
  for (let i = 0; i < 100; i++) {
    const r = await admin.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()");
    if (r.rows[0].n > 0) return;
    await sleep(20);
  }
  throw new Error("second transaction never blocked on the row lock");
}

describe("check/use race on one row (TOCTOU)", () => {
  it("a decision is made on the locked row: status changed by another transaction between the check and the write is seen", async () => {
    const id = await insertRow(admin, { authorId: "u1", status: "draft" });
    const repo = new CaseFileRepository();
    let release!: () => void;
    const holding = new Promise<void>((r) => (release = r));
    let locked!: () => void;
    const hasLock = new Promise<void>((r) => (locked = r));

    // T1: the author locks the draft and is about to submit it
    const t1 = withContext(pool, ctxOf(subjectOf({ id: "u1", roles: ["analyst"] }), envOf(), "submit"), async (tx) => {
      const r = await repo.lock(tx, id);
      locked();
      await holding;
      await repo.updateStatus(tx, id, "submitted", r!.version);
    });
    await hasLock;
    // T2: the same author edits the draft; it has to wait for T1's lock, then decide on the NEW state
    const t2 = settle(files.update(analyst("u1"), id, { title: "late edit", version: 1 }));
    await waitUntilBlocked();
    release();
    await t1;
    const r2 = await t2;
    expect(r2.ok).toBe(false);
    if (!r2.ok) expect(r2.status).toBe(403); // STATUS_FORBIDS on the submitted file, not a stale "draft"
    expect(await row(id)).toMatchObject({ status: "submitted", title: "t", version: 2 });
  });

  it("two reviewers approve at once: exactly one wins, the other is refused on the approved file", async () => {
    const id = await insertRow(admin, { authorId: "u1", status: "submitted", submittedById: "u1" });
    const [a, b] = await Promise.all([settle(files.approve(reviewer("r1"), id)), settle(files.approve(reviewer("r2"), id))]);
    expect([a.ok, b.ok].filter(Boolean)).toHaveLength(1);
    const loser = a.ok ? b : a;
    expect(loser.ok).toBe(false);
    if (!loser.ok) expect(loser.status).toBe(403);
    expect(await row(id)).toMatchObject({ status: "approved", version: 2 });
  });

  it("author and reviewer race to approve: the author never wins (separation of duties holds under load)", async () => {
    for (let i = 0; i < 10; i++) {
      const id = await insertRow(admin, { authorId: "adm", status: "submitted", submittedById: "adm" });
      const [byAuthor, byReviewer] = await Promise.all([settle(files.approve(unitAdmin("adm"), id)), settle(files.approve(reviewer("r1"), id))]);
      expect(byAuthor.ok).toBe(false);
      expect(byReviewer.ok).toBe(true);
      expect(await row(id)).toMatchObject({ status: "approved", version: 2 });
    }
  });

  it("double submit: one succeeds, the second is refused (draft only)", async () => {
    const id = await insertRow(admin, { authorId: "u1", status: "draft" });
    const [a, b] = await Promise.all([settle(files.submit(analyst("u1"), id)), settle(files.submit(analyst("u1"), id))]);
    expect([a.ok, b.ok].filter(Boolean)).toHaveLength(1);
    expect(await row(id)).toMatchObject({ status: "submitted", version: 2 });
  });

  it("update racing submit: the final state is always consistent (an edit never lands on a submitted file)", async () => {
    for (let i = 0; i < 25; i++) {
      const id = await insertRow(admin, { authorId: "u1", status: "draft" });
      const [upd, sub] = await Promise.all([settle(files.update(analyst("u1"), id, { title: "edited", version: 1 })), settle(files.submit(analyst("u1"), id))]);
      expect(sub.ok).toBe(true); // submit from draft cannot be refused by an edit
      const r = await row(id);
      if (upd.ok) expect(r).toMatchObject({ status: "submitted", title: "edited", version: 3 }); // edit first, then submit
      else expect(r).toMatchObject({ status: "submitted", title: "t", version: 2 }); // submit first: the edit saw a submitted file
    }
  });

  it("update racing delete of a draft: no resurrection, no error other than 403/404/409", async () => {
    for (let i = 0; i < 15; i++) {
      const id = await insertRow(admin, { authorId: "u1", status: "draft" });
      const [upd, del] = await Promise.all([settle(files.update(analyst("u1"), id, { title: "x", version: 1 })), settle(files.remove(analyst("u1"), id))]);
      expect(del.ok).toBe(true);
      expect((await admin.query("SELECT 1 FROM case_files WHERE id = $1", [id])).rowCount).toBe(0);
      if (!upd.ok) expect([403, 404, 409]).toContain(upd.status);
    }
  });

  it("stale version: a legitimate editor with an old copy gets 409, not a silent overwrite", async () => {
    const id = await insertRow(admin, { authorId: "u1", status: "draft", version: 3 });
    const r = await settle(files.update(analyst("u1"), id, { title: "x", version: 2 }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(409);
    expect((await settle(files.update(analyst("u1"), id, { title: "x", version: 3 }))).ok).toBe(true);
    expect((await row(id)).version).toBe(4);
  });

  it("a row lock held too long becomes a 409 (lock_timeout), not a hung request", async () => {
    const id = await insertRow(admin, { authorId: "u1", status: "draft" });
    const repo = new CaseFileRepository();
    let release!: () => void;
    const holding = new Promise<void>((r) => (release = r));
    let locked!: () => void;
    const hasLock = new Promise<void>((r) => (locked = r));
    const t1 = withContext(pool, ctxOf(subjectOf({ id: "u1", roles: ["analyst"] }), envOf(), "update"), async (tx) => {
      await repo.lock(tx, id);
      locked();
      await holding;
    });
    await hasLock;
    const started = Date.now();
    const r = await settle(files.update(analyst("u1"), id, { title: "x", version: 1 }));
    const took = Date.now() - started;
    release();
    await t1;
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(409);
    expect(took).toBeGreaterThan(2500);
    expect(took).toBeLessThan(6000);
  });
});

describe("authoritative decision inside the transaction (defence in depth)", () => {
  it("a file hidden from the caller is 404 and a nonexistent id is 404 (same refusal)", async () => {
    const hidden = await insertRow(admin, { classification: "SECRET", compartments: ["A"], status: "approved" });
    const a = await settle(files.read(analyst("u1"), hidden));
    const b = await settle(files.read(analyst("u1"), "00000000-0000-4000-8000-0000000000ff"));
    const c = await settle(files.read(analyst("u1"), "not-a-uuid"));
    for (const r of [a, b, c]) {
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.status).toBe(404);
    }
  });

  it("every authoritative refusal reaches the audit writer with the real reason and the authoritative marker", async () => {
    const mem = new MemoryAuditWriter();
    const svc = new CaseFileService(pool, new CaseFileRepository(), new JsonLogger(() => undefined), mem);
    const hidden = await insertRow(admin, { classification: "SECRET", compartments: ["A"], status: "approved" });
    const own = await insertRow(admin, { classification: "SECRET", compartments: ["A"], status: "approved" });
    await settle(svc.read(analyst("u1"), hidden)); // uncleared: hidden 404
    await settle(svc.read(caller({ roles: ["analyst"], clearance: "SECRET", compartments: ["A"] }), own)); // cleared, no MFA: step-up
    await settle(svc.read(analyst("u1"), "00000000-0000-4000-8000-0000000000ff")); // really not found
    expect(mem.entries.map((e) => [e.effect, e.reasonCode])).toEqual([
      ["deny", "CLEARANCE_TOO_LOW"],
      ["deny", "STEP_UP_REQUIRED"],
      ["deny", "RESOURCE_NOT_FOUND"],
    ]);
    for (const e of mem.entries) expect(e.details).toMatchObject({ authoritative: true });
  });

  it("cleared but without MFA: step-up challenge (403) instead of 404; uncleared without MFA: 404", async () => {
    const id = await insertRow(admin, { classification: "SECRET", compartments: ["A"], status: "approved" });
    const cleared = await settle(files.read(caller({ roles: ["analyst"], clearance: "SECRET", compartments: ["A"] }), id));
    expect(cleared.ok).toBe(false);
    if (!cleared.ok) {
      expect(cleared.status).toBe(403);
      expect(cleared.e.constructor.name).toBe("StepUpRequired");
    }
    const uncleared = await settle(files.read(caller({ roles: ["analyst"], clearance: "SECRET", compartments: ["B"] }), id));
    if (!uncleared.ok) expect(uncleared.status).toBe(404);
    expect(uncleared.ok).toBe(false);
    // with MFA the same cleared user reads it
    expect((await settle(files.read(caller({ roles: ["analyst"], clearance: "SECRET", compartments: ["A"] }, envOf({ ...MFA_ENV })), id))).ok).toBe(true);
  });

  it("the step-up probe leaves the context as it was (later statements in the same transaction still run unprivileged)", async () => {
    const id = await insertRow(admin, { classification: "SECRET", compartments: ["A"], status: "approved" });
    const other = await insertRow(admin, { classification: "SECRET", compartments: ["A"], status: "approved" });
    const c = caller({ roles: ["analyst"], clearance: "SECRET", compartments: ["A"] });
    // two lookups in the same service transaction path: the first triggers the probe, the second must not see MFA-visible rows
    const r1 = await settle(files.read(c, id));
    const r2 = await settle(files.list(c));
    expect(r1.ok).toBe(false);
    expect(r2.ok && r2.v.map((x) => x.id)).toEqual([]); // list shows no SECRET row without MFA
    void other;
  });

  it("the list is exactly what the read rule allows", async () => {
    await insertRow(admin, { classification: "OFFICIAL" });
    await insertRow(admin, { classification: "CONFIDENTIAL", compartments: ["A"] });
    await insertRow(admin, { classification: "CONFIDENTIAL", compartments: ["B"] });
    await insertRow(admin, { classification: "SECRET", compartments: ["A"] });
    const out = await files.list(caller({ roles: ["analyst"], clearance: "CONFIDENTIAL", compartments: ["A"] }));
    expect(out.map((x) => x.classification).sort()).toEqual(["CONFIDENTIAL", "OFFICIAL"]);
    expect(out.every((x) => x.body === undefined)).toBe(true); // lists never carry the body
  });

  it("if the app allows but the database refuses (layers disagree): 403 and an alert, never a 500 or a silent success", async () => {
    class RefusingRepo extends CaseFileRepository {
      override async updateText(): Promise<never> {
        throw Object.assign(new Error("policy: ROLE_NOT_PERMITTED"), { code: "42501" });
      }
    }
    const strict = new CaseFileService(pool, new RefusingRepo(), new JsonLogger((l) => logs.push(l)), new MemoryAuditWriter());
    const id = await insertRow(admin, { authorId: "u1", status: "draft" });
    const r = await settle(strict.update(analyst("u1"), id, { title: "x", version: 1 }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(403);
    expect(logs.some((l) => l.includes("db_denied_after_policy_allowed"))).toBe(true);
    expect((await row(id)).title).toBe("t");
  });

  it("the database alone refuses what the role may not do, even when the app is bypassed (reviewer cannot edit)", async () => {
    const id = await insertRow(admin, { authorId: "u1", status: "draft" });
    const repo = new CaseFileRepository();
    const err = await withContext(pool, ctxOf(subjectOf({ id: "u1", roles: ["reviewer"] }), envOf(), "update"), async (tx) => repo.updateText(tx, id, "x", "y", 1)).then(() => "ok", (e) => (e as { code?: string }).code);
    expect(err).toBe("42501"); // trigger: ROLE_NOT_PERMITTED
    expect((await row(id)).title).toBe("t");
  });
});

describe("pooled connections never carry context between requests (T-29)", () => {
  it("one physical connection, three requests: SECRET+MFA, then no context, then OFFICIAL", async () => {
    const one = appPool(1);
    const repo = new CaseFileRepository();
    const secret = await insertRow(admin, { classification: "SECRET", compartments: ["A"], status: "approved", title: "secret" });
    const official = await insertRow(admin, { classification: "OFFICIAL", status: "approved", title: "official" });

    const a = await withContext(one, ctxOf(subjectOf({ roles: ["analyst"], clearance: "SECRET", compartments: ["A"] }), envOf({ ...MFA_ENV }), "read"), async (tx) => (await repo.list(tx, 10)).map((r) => r.id));
    expect(a.sort()).toEqual([secret, official].sort());

    // same connection, no context at all
    const bare = await one.query("SELECT id FROM case_files");
    expect(bare.rows).toEqual([]);
    const leaked = (await one.query("SELECT current_setting('app.sub', true) AS sub, current_setting('app.clearance', true) AS c, current_setting('app.acr', true) AS acr, current_setting('app.compartments', true) AS comps")).rows[0];
    expect(Object.values(leaked).map((v) => v ?? "")).toEqual(["", "", "", ""]);

    // same connection, a weaker caller
    const b = await withContext(one, ctxOf(subjectOf({ roles: ["analyst"], clearance: "OFFICIAL" }), envOf(), "read"), async (tx) => (await repo.list(tx, 10)).map((r) => r.id));
    expect(b).toEqual([official]);
    await one.end();
  });

  it("a request that fails (rollback) does not leave context behind either", async () => {
    const one = appPool(1);
    await insertRow(admin, { classification: "OFFICIAL", status: "approved" });
    await expect(
      withContext(one, ctxOf(subjectOf({ roles: ["analyst"], clearance: "SECRET" }), envOf({ ...MFA_ENV }), "read"), async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect((await one.query("SELECT id FROM case_files")).rows).toEqual([]);
    await one.end();
  });

  it("break-glass does not leak into the next request on the same connection", async () => {
    const one = appPool(1);
    const repo = new CaseFileRepository();
    const hidden = await insertRow(admin, { classification: "CONFIDENTIAL", compartments: ["A"], status: "approved" });
    const adminCtx = subjectOf({ id: "adm", roles: ["unit-admin"], clearance: "CONFIDENTIAL", unit: "beta" });
    const withBg = await withContext(one, ctxOf(adminCtx, envOf({ breakGlass: { justification: "incident" } }), "read"), async (tx) => (await repo.list(tx, 10)).map((r) => r.id));
    expect(withBg).toEqual([hidden]);
    const without = await withContext(one, ctxOf(adminCtx, envOf(), "read"), async (tx) => (await repo.list(tx, 10)).map((r) => r.id));
    expect(without).toEqual([]);
    await one.end();
  });

  it("concurrent requests from different users on a small pool never see each other's rows", async () => {
    const small = appPool(2);
    const repo = new CaseFileRepository();
    const mine = await insertRow(admin, { classification: "SECRET", compartments: ["A"], status: "approved" });
    const pub = await insertRow(admin, { classification: "OFFICIAL", status: "approved" });
    const run = (secretUser: boolean) =>
      withContext(
        small,
        ctxOf(secretUser ? subjectOf({ roles: ["analyst"], clearance: "SECRET", compartments: ["A"] }) : subjectOf({ roles: ["analyst"], clearance: "OFFICIAL" }), secretUser ? envOf({ ...MFA_ENV }) : envOf(), "read"),
        async (tx) => {
          await tx.query(sql`SELECT pg_sleep(0.01)`);
          return (await repo.list(tx, 10)).map((r) => r.id).sort();
        },
      );
    const results = await Promise.all(Array.from({ length: 60 }, (_, i) => run(i % 2 === 0)));
    results.forEach((r, i) => expect(r).toEqual(i % 2 === 0 ? [mine, pub].sort() : [pub]));
    await small.end();
  });
});

describe("timeouts and pool limits (T-27)", () => {
  it("statement_timeout (5s) cancels a slow statement", async () => {
    const c = new pg.Client({ connectionString: appUrl() });
    await c.connect();
    const code = await c.query("SELECT pg_sleep(7)").then(() => "ok", (e) => (e as { code?: string }).code);
    await c.end();
    expect(code).toBe("57014");
  });

  it("an exhausted pool fails the request after the connection timeout instead of queueing forever", async () => {
    const tiny = appPool(1);
    const hold = await tiny.connect();
    const started = Date.now();
    await expect(tiny.query("SELECT 1")).rejects.toThrow(/timeout/i);
    expect(Date.now() - started).toBeLessThan(8000);
    hold.release();
    await tiny.end();
  });

  it("the role limits connections", async () => {
    const r = (await admin.query("SELECT rolconnlimit FROM pg_roles WHERE rolname = 'casefile_app'")).rows[0];
    expect(r.rolconnlimit).toBe(25);
  });
});
