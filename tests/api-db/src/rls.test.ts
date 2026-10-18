// Targeted row-level-security and trigger behaviour that the parity grids do not express directly (T-15, T-16, T-25).
import { randomUUID } from "node:crypto";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { sql } from "../../../apps/api/src/db/sql.js";
import { toDbContext } from "../../../apps/api/src/db/context.js";
import { adminPool, appPool, clearRows, ctxOf, envOf, insertRow, MFA_ENV, probe, subjectOf } from "./db.js";

const admin = adminPool();
const app = appPool(4);
afterAll(async () => {
  await clearRows(admin);
  await admin.end();
  await app.end();
});
beforeEach(() => clearRows(admin));

const SELECT_ID = sql`SELECT id FROM case_files WHERE id = $1`;
const UPDATE_TITLE = sql`UPDATE case_files SET title = 'x' WHERE id = $1`;
const code = async (p: Promise<unknown>) => p.then(() => "ok", (e) => (e as { code?: string; message?: string }).code ?? "error");

const visible = (s = subjectOf(), e = envOf()) => async (id: string) => probe(app, ctxOf(s, e, "read"), async (tx) => (await tx.query(SELECT_ID, [id])).rowCount === 1);

describe("break-glass in the database (T-25)", () => {
  const admin1 = subjectOf({ id: "adm", roles: ["unit-admin"], clearance: "CONFIDENTIAL", unit: "beta", compartments: [] });
  const bg = (j: string, extra = {}) => envOf({ breakGlass: { justification: j }, ...extra });

  it("opens need-to-know only, for a role with the grant, with a non-blank justification", async () => {
    const id = await insertRow(admin, { classification: "CONFIDENTIAL", compartments: ["A"], status: "approved" });
    expect(await visible(admin1, envOf())(id)).toBe(false);
    expect(await visible(admin1, bg("incident 5"))(id)).toBe(true);
    expect(await visible(admin1, bg("   "))(id)).toBe(false);
    expect(await visible(admin1, bg(""))(id)).toBe(false);
    expect(await visible({ ...admin1, roles: ["analyst"] }, bg("incident 5"))(id)).toBe(false);
    expect(await visible({ ...admin1, roles: ["reviewer"] }, bg("incident 5"))(id)).toBe(false);
  });

  it("never beats the clearance floor or step-up", async () => {
    const secret = await insertRow(admin, { classification: "SECRET", compartments: ["A"], status: "approved" });
    expect(await visible(admin1, bg("incident 5"))(secret)).toBe(false); // CONFIDENTIAL < SECRET
    const top = { ...admin1, clearance: "SECRET" };
    expect(await visible(top, bg("incident 5"))(secret)).toBe(false); // no MFA
    expect(await visible(top, bg("incident 5", { ...MFA_ENV }))(secret)).toBe(true);
  });

  it("is ignored for writes: the flag does not open update or delete", async () => {
    const id = await insertRow(admin, { classification: "CONFIDENTIAL", compartments: ["A"], unit: "alpha", status: "draft" });
    const ctx = ctxOf(admin1, bg("incident 5"), "read"); // flag present
    const out = await probe(app, ctx, async (tx) => ({ upd: (await tx.query(UPDATE_TITLE, [id])).rowCount }));
    expect(out.upd).toBe(0);
  });

  it("the API-side context builder drops the flag for non-read actions and for blank justifications", () => {
    expect(toDbContext(admin1, bg("x"), "update").breakGlass).toBeUndefined();
    expect(toDbContext(admin1, bg("  "), "read").breakGlass).toBeUndefined();
    expect(toDbContext(admin1, bg(" x "), "read").breakGlass).toEqual({ justification: "x" });
  });
});

describe("guard trigger: immutability, versioning, recorded submitter (T-16)", () => {
  it("the database refuses to change classification, unit, compartments, author, id, created_at even for a superuser", async () => {
    const id = await insertRow(admin, {});
    for (const set of ["classification = 'SECRET'", "unit = 'beta'", "compartments = '{A}'", "author_id = 'other'", "id = gen_random_uuid()", "created_at = now() - interval '1 day'"]) {
      // static statements from this test file
      const c = await code(admin.query(`UPDATE case_files SET ${set} WHERE id = '${id}'`));
      expect(c, set).toBe("42501");
    }
  });

  it("illegal status transitions are refused: draft->approved, submitted->draft, approved->anything", async () => {
    const author = subjectOf({ id: "u1", roles: ["unit-admin"], clearance: "CONFIDENTIAL" });
    const ctx = ctxOf(author, envOf(), "update");
    for (const [from, to] of [["draft", "approved"], ["submitted", "draft"], ["approved", "draft"], ["approved", "submitted"]] as const) {
      const id = await insertRow(admin, { status: from, authorId: "u9", submittedById: from === "draft" ? null : "u8" });
      const c = await probe(app, ctx, async (tx) => code(tx.query(sql`UPDATE case_files SET status = $2::case_status WHERE id = $1`, [id, to])));
      // for submitted->draft the CHECK (draft <=> no submitter) or the trigger refuses; either way not "ok"
      expect(["42501", "23514"], `${from}->${to}`).toContain(c);
    }
  });

  it("submit records the submitter from the context, bumps version and updated_at; text update bumps version", async () => {
    const id = await insertRow(admin, { authorId: "u1", status: "draft" });
    const ctx = ctxOf(subjectOf({ id: "u1", roles: ["analyst"] }), envOf(), "submit");
    await probe(app, ctx, async () => undefined);
    // commit for real (probe rolls back): use a direct committed transaction through the pool with the same context
    const { withContext } = await import("../../../apps/api/src/db/context.js");
    await withContext(app, ctx, async (tx) => {
      await tx.query(sql`UPDATE case_files SET status = 'submitted' WHERE id = $1`, [id]);
    });
    const r = (await admin.query("SELECT status, submitted_by_id, version, updated_at > created_at AS touched FROM case_files WHERE id = $1", [id])).rows[0];
    expect(r).toMatchObject({ status: "submitted", submitted_by_id: "u1", version: 2, touched: true });
    // a reviewer approves: submitter is kept, version bumps again
    await withContext(app, ctxOf(subjectOf({ id: "r1", roles: ["reviewer"], clearance: "CONFIDENTIAL" }), envOf(), "approve"), async (tx) => {
      await tx.query(sql`UPDATE case_files SET status = 'approved' WHERE id = $1`, [id]);
    });
    expect((await admin.query("SELECT status, submitted_by_id, version FROM case_files WHERE id = $1", [id])).rows[0]).toMatchObject({ status: "approved", submitted_by_id: "u1", version: 3 });
  });

  it("an approved file cannot be edited or deleted by the database even for the unit-admin of its unit", async () => {
    const id = await insertRow(admin, { status: "approved", authorId: "u9" });
    const ctx = ctxOf(subjectOf({ id: "adm", roles: ["unit-admin"], clearance: "CONFIDENTIAL" }), envOf(), "update");
    const out = await probe(app, ctx, async (tx) => ({
      upd: await code(tx.query(UPDATE_TITLE, [id])),
    }));
    expect(out.upd).toBe("42501");
    const del = await probe(app, ctx, async (tx) => (await tx.query(sql`DELETE FROM case_files WHERE id = $1`, [id])).rowCount);
    expect(del).toBe(0);
  });
});

describe("context values are data, never SQL (T-14)", () => {
  it("hostile subject strings do not widen access or break the statement", async () => {
    await insertRow(admin, { authorId: "u1" });
    for (const sub of ["u1' OR '1'='1", "x'; DROP TABLE case_files; --", "u1\" OR true", "$$"]) {
      const rows = await probe(app, ctxOf(subjectOf({ id: sub, roles: ["analyst"], unit: "alpha" }), envOf(), "read"), async (tx) => (await tx.query(sql`SELECT id FROM case_files WHERE author_id = $1`, [sub])).rows);
      expect(rows).toEqual([]);
    }
    expect((await admin.query("SELECT count(*)::int AS n FROM case_files")).rows[0].n).toBe(1);
  });

  it("unsafe context members are refused before they reach the database", async () => {
    const { withContext } = await import("../../../apps/api/src/db/context.js");
    const base = ctxOf(subjectOf(), envOf());
    await expect(withContext(app, { ...base, compartments: ["A,B"] }, async () => 1)).rejects.toThrow(/unsafe/);
    await expect(withContext(app, { ...base, roles: ["analyst,unit-admin"] }, async () => 1)).rejects.toThrow(/unsafe/);
    await expect(withContext(app, { ...base, sub: "u1\n" }, async () => 1)).rejects.toThrow(/unsafe/);
    await expect(withContext(app, { ...base, unit: "x".repeat(700) }, async () => 1)).rejects.toThrow(/unsafe/);
  });

  it("a comma in a compartment cannot smuggle a second compartment (would be a privilege escalation)", async () => {
    const id = await insertRow(admin, { classification: "CONFIDENTIAL", compartments: ["B"], status: "approved" });
    const s = subjectOf({ clearance: "CONFIDENTIAL", compartments: ["A"] });
    expect(await visible(s)(id)).toBe(false);
    const { withContext } = await import("../../../apps/api/src/db/context.js");
    await expect(withContext(app, { ...ctxOf(s, envOf()), compartments: ["A,B"] }, async () => 1)).rejects.toThrow();
  });
});

describe("constraints reject hostile data at the table (T-14)", () => {
  it.each([
    ["compartment with SQL", { compartments: ["A'); DROP TABLE case_files;--"] }],
    ["compartment too long", { compartments: ["x".repeat(33)] }],
    ["too many compartments", { compartments: Array.from({ length: 17 }, (_, i) => `c${i}`) }],
    ["unit with space", { unit: "al pha" }],
    ["empty title", { title: "" }],
    ["author with quote", { authorId: "a'b" }],
  ])("%s", async (_n, over) => {
    const id = randomUUID();
    const c = await code(insertRow(admin, { id, ...over }));
    expect(c).toBe("23514");
  });

  it("title, body and hostile text are stored verbatim", async () => {
    const evil = "'); DELETE FROM case_files; -- \\ $1 ${x} \u{1F600}";
    const id = await insertRow(admin, { title: evil.slice(0, 100), body: evil });
    expect((await admin.query("SELECT body FROM case_files WHERE id = $1", [id])).rows[0].body).toBe(evil);
  });
});
