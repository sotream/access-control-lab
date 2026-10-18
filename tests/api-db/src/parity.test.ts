// Policy-vs-database parity (T-15, T-16, T-17, T-25): for generated subjects, environments and rows, packages/policy and
// Postgres row-level security + trigger must give the same answer. A mismatch fails with a readable diff.
import { randomUUID } from "node:crypto";
import fc from "fast-check";
import type { Environment, Subject } from "@acl/policy";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { adminPool, appPool, clearRows, envOf, insertRow, MFA_ENV, pmap, subjectOf } from "./db.js";
import { compare, DB_ACTIONS, diff, KNOWN_DIFFERENCES, type DbAction, type GridRow, type Mismatch } from "./parity.js";

const admin = adminPool();
const app = appPool(5);
const rows: GridRow[] = [];

// every combination that matters to a rule: classification x compartments x unit x status/submitter x author
const COMPS = [[], ["A"], ["B"], ["A", "B"]];
beforeAll(async () => {
  await clearRows(admin);
  for (const classification of ["OFFICIAL", "CONFIDENTIAL", "SECRET"])
    for (const compartments of COMPS)
      for (const unit of ["alpha", "beta"])
        for (const [status, submittedById] of [["draft", null], ["submitted", "u1"], ["submitted", "u2"], ["approved", "u1"], ["approved", "u2"]] as const)
          for (const authorId of ["u1", "u2"]) {
            const id = randomUUID();
            await insertRow(admin, { id, classification, compartments, unit, status, authorId, submittedById });
            rows.push({ id, classification, compartments, unit, status, authorId, submittedById });
          }
});
afterAll(async () => {
  await clearRows(admin);
  await admin.end();
  await app.end();
});

const ATTACH_SQL = "INSERT INTO attachments (case_file_id, display_name, media_type, size_bytes, sha256, storage_key, uploaded_by_id, status, scanned_at) VALUES ($1,'a.txt','text/plain',1,decode(repeat('00',32),'hex'),md5(random()::text || clock_timestamp()::text),'u1','clean',now())";
/** one attachment per file, inserted as the superuser: what a subject sees of them must equal what the parent's read rule shows */
async function seedAttachments(rs: readonly GridRow[]): Promise<void> {
  await admin.query("DELETE FROM attachments");
  for (const r of rs) await admin.query(ATTACH_SQL, [r.id]);
}

const ROLE_SETS = [["analyst"], ["reviewer"], ["unit-admin"], ["auditor"], ["platform-admin"], ["analyst", "reviewer"], ["ghost"]];

function subjects(clearances: string[], comps: string[][], ids = ["u1", "u2"]): Subject[] {
  const out: Subject[] = [];
  for (const roles of ROLE_SETS) for (const clearance of clearances) for (const compartments of comps) for (const unit of ["alpha", "beta"]) for (const id of ids) out.push(subjectOf({ roles, clearance, compartments, unit, id }));
  return out;
}

const CONCURRENCY = 4;
/** all (subject, env) pairs for one action, a few at a time */
async function grid(action: DbAction, subs: Subject[], envs: Environment[], rs: readonly GridRow[]): Promise<Mismatch[]> {
  const pairs = subs.flatMap((s) => envs.map((e) => [s, e] as const));
  return (await pmap(pairs, CONCURRENCY, ([s, e]) => compare(app, action, s, e, rs))).flat();
}

const ENVS: Environment[] = [envOf(), envOf({ ...MFA_ENV })];

describe("known intentional differences are written down", () => {
  it("is non-empty and each entry names where it is covered", () => {
    expect(KNOWN_DIFFERENCES.length).toBeGreaterThanOrEqual(5);
    for (const d of KNOWN_DIFFERENCES) {
      expect(d.coveredBy.length).toBeGreaterThan(5);
      expect(d.what.length).toBeGreaterThan(20);
    }
  });
});

describe("grid parity: every subject x env x row, per action", () => {
  it("read: 3 clearances x 4 compartment sets x roles x units x ids x {password, mfa}", async () => {
    expect(diff(await grid("read", subjects(["OFFICIAL", "CONFIDENTIAL", "SECRET"], [[], ["A"], ["A", "B"]]), ENVS, rows))).toBe("");
  });

  it("read with break-glass requested (non-blank justification)", async () => {
    const bg = [envOf({ breakGlass: { justification: "incident 1" } }), envOf({ ...MFA_ENV, breakGlass: { justification: "incident 1" } })];
    expect(diff(await grid("read", subjects(["OFFICIAL", "CONFIDENTIAL", "SECRET"], [[], ["A"]]), bg, rows))).toBe("");
  });

  it.each(DB_ACTIONS.filter((a) => a !== "read"))("%s", async (action) => {
    // a draft that has attachments cannot be deleted (foreign key): that is an intentional difference, so this grid runs without attachments
    if (action === "delete") await admin.query("DELETE FROM attachments");
    if (action === "attachments-read") await seedAttachments(rows);
    // the submitter only matters for approve (separation of duties); other actions use the rows without the u2 submitter variants
    const rs = action === "approve" ? rows : rows.filter((r) => r.submittedById !== "u2");
    expect(diff(await grid(action, subjects(["OFFICIAL", "SECRET"], [[], ["A", "B"]], ["u1"]), ENVS, rs))).toBe("");
  });
});

describe("property parity: random subject, environment and row", () => {
  const tag = fc.constantFrom("A", "B", "C");
  const subjectArb: fc.Arbitrary<Subject> = fc.record({
    id: fc.constantFrom("u1", "u2", "u3"),
    roles: fc.array(fc.constantFrom("analyst", "reviewer", "unit-admin", "auditor", "platform-admin", "ghost"), { maxLength: 3 }),
    clearance: fc.constantFrom("OFFICIAL", "CONFIDENTIAL", "SECRET"),
    unit: fc.constantFrom("alpha", "beta", "gamma"),
    compartments: fc.array(tag, { maxLength: 3 }),
  });
  const envArb: fc.Arbitrary<Environment> = fc
    .record({
      acr: fc.constantFrom("pwd", "mfa", "other"),
      amr: fc.subarray(["pwd", "otp"]),
      bg: fc.constantFrom(undefined, "incident 7", "x"),
    })
    .map(({ acr, amr, bg }) => envOf({ acr, amr, ...(bg ? { breakGlass: { justification: bg } } : {}) }));
  const rowArb: fc.Arbitrary<GridRow> = fc
    .record({
      classification: fc.constantFrom("OFFICIAL", "CONFIDENTIAL", "SECRET"),
      unit: fc.constantFrom("alpha", "beta", "gamma"),
      compartments: fc.array(tag, { maxLength: 3 }),
      status: fc.constantFrom("draft", "submitted", "approved"),
      authorId: fc.constantFrom("u1", "u2", "u3"),
      sub: fc.constantFrom("u1", "u2", "u3"),
    })
    .map((r) => ({ id: randomUUID(), classification: r.classification, unit: r.unit, compartments: [...new Set(r.compartments)], status: r.status, authorId: r.authorId, submittedById: r.status === "draft" ? null : r.sub }));

  it.each(DB_ACTIONS)("%s", async (action: DbAction) => {
    await fc.assert(
      fc.asyncProperty(subjectArb, envArb, fc.array(rowArb, { minLength: 1, maxLength: 4 }), async (s, e, rs) => {
        for (const r of rs) await insertRow(admin, r);
        if (action === "attachments-read") await seedAttachments(rs);
        try {
          expect(diff(await compare(app, action, s, e, rs))).toBe("");
        } finally {
          await admin.query("DELETE FROM attachments WHERE case_file_id = ANY($1::uuid[])", [rs.map((r) => r.id)]);
          await admin.query("DELETE FROM case_files WHERE id = ANY($1::uuid[])", [rs.map((r) => r.id)]);
        }
      }),
      { numRuns: 100 },
    );
  });
});

describe("the intentional differences, demonstrated", () => {
  it("blank break-glass justification: policy refuses, database (flag never sent) behaves as a normal read", async () => {
    const hidden = rows.find((r) => r.classification === "CONFIDENTIAL" && r.compartments.join() === "A" && r.unit === "alpha" && r.status === "approved" && r.authorId === "u1")!;
    const s = subjectOf({ roles: ["unit-admin"], clearance: "CONFIDENTIAL", compartments: [] });
    const bad = await compare(app, "read", s, envOf({ breakGlass: { justification: "  " } }), [hidden]);
    expect(bad).toEqual([]); // both deny: the compartment gap is not opened by a blank justification
    const ok = rows.find((r) => r.classification === "OFFICIAL" && r.compartments.length === 0 && r.status === "approved")!;
    const diffs = await compare(app, "read", s, envOf({ breakGlass: { justification: "" } }), [ok]);
    expect(diffs).toHaveLength(1); // policy: explicit request without justification is refused; db: a plain read succeeds
    expect(diffs[0]).toMatchObject({ db: true, policy: false, policyReason: "BREAK_GLASS_JUSTIFICATION_REQUIRED" });
  });
});
