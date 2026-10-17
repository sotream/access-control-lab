// Invariants that must hold for ANY input, not just the table cases. fast-check pinned in package.json.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { evaluate } from "./evaluate.js";
import { matchesReadFilter, readFilter } from "./filter.js";
import { ACTIONS, CLEARANCES, ROLES, STATUSES, clearanceRank, type Action, type Environment, type Resource, type Subject } from "./model.js";
import { EXPECTED_RBAC } from "./testkit.js";

const RESOURCE_ACTIONS: Action[] = ["create", "read", "update", "submit", "approve", "delete", "export"];
const RUNS = { numRuns: 1500 };

// small alphabets on purpose: collisions (same id, same unit, same compartment) are where the interesting cases are
const tag = fc.constantFrom("A", "B", "C");
const comps = fc.array(tag, { maxLength: 4 });
const id = fc.constantFrom("u1", "u2", "u3");
const unit = fc.constantFrom("alpha", "beta");
const role = fc.oneof(fc.constantFrom(...ROLES), fc.constantFrom("ghost", "constructor", "__proto__"));

const subjectArb: fc.Arbitrary<Subject> = fc.record({
  id,
  roles: fc.array(role, { maxLength: 3 }),
  clearance: fc.constantFrom(...CLEARANCES),
  unit,
  compartments: comps,
});
const resourceArb: fc.Arbitrary<Resource> = fc.record({
  id: fc.constant("f"),
  classification: fc.constantFrom(...CLEARANCES),
  ownerUnit: unit,
  compartments: comps,
  status: fc.constantFrom(...STATUSES),
  authorId: id,
  submittedById: fc.option(id, { nil: null }),
});
const envArb: fc.Arbitrary<Environment> = fc.record(
  {
    acr: fc.constantFrom("pwd", "mfa", "x"),
    amr: fc.subarray(["pwd", "otp"]),
    now: fc.integer({ min: 1_700_000_000, max: 1_800_000_000 }),
    networkZone: fc.constantFrom("managed", "office"),
    breakGlass: fc.record({ justification: fc.constantFrom("", " ", "incident 42") }),
  },
  { requiredKeys: ["acr", "amr", "now", "networkZone"] },
);
const actionArb = fc.constantFrom(...ACTIONS);
const resActionArb = fc.constantFrom(...RESOURCE_ACTIONS);

describe("invariants", () => {
  it("deny whenever clearance < classification, for any role, action, env, break-glass (T-15)", () => {
    fc.assert(
      fc.property(subjectArb, resourceArb, envArb, resActionArb, (s, r, e, a) => {
        fc.pre(clearanceRank(s.clearance) < clearanceRank(r.classification));
        expect(evaluate(s, a, r, e).effect).toBe("deny");
      }),
      RUNS,
    );
  });

  it("adding a compartment to the resource never turns a deny into an allow", () => {
    fc.assert(
      fc.property(subjectArb, resourceArb, envArb, resActionArb, tag, (s, r, e, a, extra) => {
        const stricter = { ...r, compartments: [...r.compartments, extra] };
        if (evaluate(s, a, stricter, e).effect === "allow") expect(evaluate(s, a, r, e).effect).toBe("allow");
      }),
      RUNS,
    );
  });

  it("adding a compartment to the subject never turns an allow into a deny for read", () => {
    fc.assert(
      fc.property(subjectArb, resourceArb, envArb, tag, (s, r, e, extra) => {
        const wider = { ...s, compartments: [...s.compartments, extra] };
        if (evaluate(s, "read", r, e).effect === "allow") expect(evaluate(wider, "read", r, e).effect).toBe("allow");
      }),
      RUNS,
    );
  });

  it("no allow without a role grant for the action (independent matrix)", () => {
    fc.assert(
      fc.property(subjectArb, resourceArb, envArb, actionArb, (s, r, e, a) => {
        if (evaluate(s, a, r, e).effect === "allow") {
          const granted = s.roles.some((x) => Object.hasOwn(EXPECTED_RBAC, x) && (EXPECTED_RBAC as Record<string, Action[]>)[x]!.includes(a));
          expect(granted).toBe(true);
        }
      }),
      RUNS,
    );
  });

  it("no allow on a SECRET resource without acr=mfa and otp in amr (T-17)", () => {
    fc.assert(
      fc.property(subjectArb, resourceArb, envArb, resActionArb, (s, r, e, a) => {
        fc.pre(r.classification === "SECRET");
        if (evaluate(s, a, r, e).effect === "allow") {
          expect(e.acr).toBe("mfa");
          expect(e.amr).toContain("otp");
        }
      }),
      RUNS,
    );
  });

  it("an approval never goes to the author or the submitter (T-16)", () => {
    fc.assert(
      fc.property(subjectArb, resourceArb, envArb, (s, r, e) => {
        if (evaluate(s, "approve", r, e).effect === "allow") {
          expect(r.authorId).not.toBe(s.id);
          expect(r.submittedById ?? null).not.toBe(s.id);
        }
      }),
      RUNS,
    );
  });

  it("writes in another unit are allowed only to a cross-unit role (reviewer approve)", () => {
    fc.assert(
      fc.property(subjectArb, resourceArb, envArb, fc.constantFrom<Action>("create", "update", "submit", "approve", "delete"), (s, r, e, a) => {
        fc.pre(r.ownerUnit !== s.unit);
        if (evaluate(s, a, r, e).effect === "allow") {
          expect(a).toBe("approve");
          expect(s.roles).toContain("reviewer");
        }
      }),
      RUNS,
    );
  });

  it("an allowed change only ever happens in the status machine's source status", () => {
    const from: Partial<Record<Action, string>> = { update: "draft", submit: "draft", delete: "draft", approve: "submitted", export: "approved", create: "draft" };
    fc.assert(
      fc.property(subjectArb, resourceArb, envArb, resActionArb, (s, r, e, a) => {
        fc.pre(a !== "read");
        if (evaluate(s, a, r, e).effect === "allow") expect(r.status).toBe(from[a]);
      }),
      RUNS,
    );
  });

  it("break-glass allows only: read, unit-admin, non-empty justification, floor satisfied", () => {
    fc.assert(
      fc.property(subjectArb, resourceArb, envArb, actionArb, (s, r, e, a) => {
        const d = evaluate(s, a, r, e);
        if (d.reason === "ALLOWED_BREAK_GLASS") {
          expect(a).toBe("read");
          expect(s.roles).toContain("unit-admin");
          expect(e.breakGlass?.justification.trim().length).toBeGreaterThan(0);
          expect(clearanceRank(s.clearance)).toBeGreaterThanOrEqual(clearanceRank(r.classification));
          expect(d.obligations).toContain("alert");
        }
      }),
      RUNS,
    );
  });

  it("deterministic and total: same input gives an equal decision, never throws", () => {
    fc.assert(
      fc.property(subjectArb, resourceArb, envArb, actionArb, (s, r, e, a) => {
        expect(evaluate(s, a, r, e)).toEqual(evaluate(s, a, r, e));
      }),
      RUNS,
    );
  });

  it("garbage in any argument never throws and never allows when subject, action or env is not an object/known value", () => {
    fc.assert(
      fc.property(fc.anything(), fc.anything(), fc.anything(), fc.anything(), (s, a, r, e) => {
        const d = (evaluate as (...x: unknown[]) => ReturnType<typeof evaluate>)(s, a, r, e);
        expect(["allow", "deny"]).toContain(d.effect);
        if (d.effect === "allow") expect(ACTIONS as readonly unknown[]).toContain(a);
      }),
      { numRuns: 3000 },
    );
  });

  it("read filter and evaluate(read) agree (SQL/RLS parity basis, no break-glass)", () => {
    fc.assert(
      fc.property(subjectArb, resourceArb, envArb, (s, r, e) => {
        const plain = { ...e, breakGlass: undefined };
        expect(matchesReadFilter(readFilter(s, plain), r)).toBe(evaluate(s, "read", r, plain).effect === "allow");
      }),
      RUNS,
    );
  });
});
