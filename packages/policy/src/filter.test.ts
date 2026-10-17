import { describe, expect, it } from "vitest";
import { evaluate } from "./evaluate.js";
import { matchesReadFilter, readFilter } from "./filter.js";
import { ROLE_GRANTS, WRITE_ACTIONS } from "./matrix.js";
import { ROLES } from "./model.js";
import { MFA, env, resource, subject } from "./testkit.js";
import { visibility } from "./visibility.js";

describe("readFilter / matchesReadFilter", () => {
  it("OFFICIAL analyst without compartments sees OFFICIAL, no compartmented rows", () => {
    const f = readFilter(subject(), env());
    expect(f).toEqual({ roleAllowed: true, classifications: ["OFFICIAL"], compartmentsSubsetOf: [] });
    expect(matchesReadFilter(f, resource())).toBe(true);
    expect(matchesReadFilter(f, resource({ compartments: ["A"] }))).toBe(false);
    expect(matchesReadFilter(f, resource({ classification: "CONFIDENTIAL" }))).toBe(false);
  });

  it("SECRET is listed only with MFA", () => {
    const s = subject({ clearance: "SECRET", compartments: ["A", "A"] });
    expect(readFilter(s, env()).classifications).toEqual(["OFFICIAL", "CONFIDENTIAL"]);
    expect(readFilter(s, env({ ...MFA })).classifications).toEqual(["OFFICIAL", "CONFIDENTIAL", "SECRET"]);
    expect(readFilter(s, env({ ...MFA })).compartmentsSubsetOf).toEqual(["A"]);
  });

  it("roles without read, unknown roles and invalid input read nothing", () => {
    for (const roles of [["auditor"], ["platform-admin"], [], ["nope"]]) {
      const f = readFilter(subject({ roles }), env());
      expect(f.roleAllowed).toBe(false);
      expect(f.classifications).toEqual([]);
      expect(matchesReadFilter(f, resource())).toBe(false);
    }
    expect(readFilter(subject({ clearance: "x" }), env()).roleAllowed).toBe(false);
    expect(readFilter(subject(), { ...env(), now: NaN }).roleAllowed).toBe(false);
  });

  it("malformed rows never match", () => {
    const f = readFilter(subject(), env());
    expect(matchesReadFilter(f, { classification: "OFFICIAL", compartments: undefined as unknown as string[] })).toBe(false);
    expect(matchesReadFilter(f, { classification: "NOPE", compartments: [] })).toBe(false);
  });

  it("agrees with evaluate(read) on a grid", () => {
    for (const clearance of ["OFFICIAL", "CONFIDENTIAL", "SECRET"])
      for (const sc of [[], ["A"], ["A", "B"]])
        for (const e of [env(), env({ ...MFA })])
          for (const classification of ["OFFICIAL", "CONFIDENTIAL", "SECRET"])
            for (const rc of [[], ["A"], ["B"], ["A", "B"]]) {
              const s = subject({ clearance, compartments: sc });
              const r = resource({ classification, compartments: rc });
              expect(matchesReadFilter(readFilter(s, e), r)).toBe(evaluate(s, "read", r, e).effect === "allow");
            }
  });
});

describe("visibility (404 vs 403 rule)", () => {
  it("visible when readable", () => expect(visibility(subject(), resource(), env())).toBe("visible"));
  it("hidden when clearance is too low", () => expect(visibility(subject(), resource({ classification: "CONFIDENTIAL" }), env())).toBe("hidden"));
  it("hidden when a compartment is missing", () => expect(visibility(subject(), resource({ compartments: ["A"] }), env())).toBe("hidden"));
  it("hidden when the role cannot read", () => expect(visibility(subject({ roles: ["auditor"] }), resource(), env())).toBe("hidden"));
  it("visible when only step-up is missing (the user is cleared)", () => {
    expect(visibility(subject({ clearance: "SECRET" }), resource({ classification: "SECRET" }), env())).toBe("visible");
  });
  it("hidden when step-up is missing and the subject is also not cleared", () => {
    expect(visibility(subject({ clearance: "CONFIDENTIAL" }), resource({ classification: "SECRET" }), env())).toBe("hidden");
  });
  it("break-glass does not make a resource visible", () => {
    expect(visibility(subject({ roles: ["unit-admin"] }), resource({ compartments: ["A"] }), env({ breakGlass: { justification: "x" } }))).toBe("hidden");
  });
});

describe("matrix consistency", () => {
  it("every role is defined; crossUnit and ownOnly are subsets of the role's actions; crossUnit only for writes", () => {
    for (const r of ROLES) {
      const g = ROLE_GRANTS[r];
      expect(g, r).toBeDefined();
      for (const a of g.crossUnit) {
        expect(g.actions, `${r} crossUnit ${a}`).toContain(a);
        expect(WRITE_ACTIONS, `${r} crossUnit ${a}`).toContain(a);
      }
      for (const a of g.ownOnly) expect(g.actions, `${r} ownOnly ${a}`).toContain(a);
    }
    expect(Object.keys(ROLE_GRANTS).sort()).toEqual([...ROLES].sort());
  });

  it("the matrix is frozen", () => {
    expect(Object.isFrozen(ROLE_GRANTS)).toBe(true);
    expect(Object.isFrozen(ROLE_GRANTS.analyst.actions)).toBe(true);
  });
});
