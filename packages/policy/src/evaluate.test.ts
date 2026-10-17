import { describe, expect, it } from "vitest";
import { evaluate, evaluateRole } from "./evaluate.js";
import { ACTIONS, CLEARANCES, ROLES, STATUSES, type Action } from "./model.js";
import { EXPECTED_RBAC, MFA, STATUS_FOR, at, env, perfect, resource, subject } from "./testkit.js";

const RESOURCE_ACTIONS: Action[] = ["create", "read", "update", "submit", "approve", "delete", "export"];

describe("RBAC matrix: every role x every action, default deny (T-11)", () => {
  const cases = ROLES.flatMap((role) => ACTIONS.map((action) => ({ role, action, allowed: EXPECTED_RBAC[role].includes(action) })));
  it.each(cases)("$role / $action -> allowed=$allowed", ({ role, action, allowed }) => {
    const { s, r, e } = perfect(role, action);
    const d = evaluate(s, action, r, e);
    expect(d.effect).toBe(allowed ? "allow" : "deny");
    expect(d.reason).toBe(allowed ? "ALLOWED" : "ROLE_NOT_PERMITTED");
    if (allowed) expect(d.obligations).toEqual(["audit"]);
  });

  it("a subject with no roles, or only unknown roles, is denied everything", () => {
    for (const roles of [[], ["superuser"], ["Analyst"], ["constructor", "toString", "__proto__", "hasOwnProperty"]]) {
      for (const action of ACTIONS) {
        const { r, e } = perfect("analyst", action);
        const d = evaluate(subject({ roles, clearance: "SECRET", compartments: ["A"] }), action, r, e);
        expect(d.effect, `${roles.join()}/${action}`).toBe("deny");
        expect(d.reason).toBe("ROLE_NOT_PERMITTED");
      }
    }
  });

  it("several roles give the union of their grants", () => {
    const { r, e } = perfect("reviewer", "approve");
    expect(evaluate(subject({ id: "actor", roles: ["auditor", "reviewer"], clearance: "SECRET", compartments: ["A"] }), "approve", r, e).effect).toBe("allow");
    expect(evaluate(subject({ id: "actor", roles: ["auditor", "reviewer"], clearance: "SECRET", compartments: ["A"] }), "readAudit", null, e).effect).toBe("allow");
  });

  it("duplicate roles change nothing", () => {
    const { r, e } = perfect("analyst", "read");
    expect(evaluate(subject({ roles: ["analyst", "analyst"] }), "read", r, e)).toEqual(evaluate(subject({ roles: ["analyst"] }), "read", r, e));
  });
});

describe("clearance floor: subject x classification grid (T-15)", () => {
  const grid = CLEARANCES.flatMap((sc, si) => CLEARANCES.map((rc, ri) => ({ sc, rc, allowed: si >= ri })));
  it.each(grid)("subject $sc reads $rc -> $allowed", ({ sc, rc, allowed }) => {
    const d = evaluate(subject({ clearance: sc }), "read", resource({ classification: rc }), env({ ...MFA }));
    expect(d.effect).toBe(allowed ? "allow" : "deny");
    if (!allowed) expect(d.reason).toBe("CLEARANCE_TOO_LOW");
  });

  it("applies to every resource action, not only read", () => {
    for (const role of ROLES) {
      for (const action of RESOURCE_ACTIONS.filter((a) => EXPECTED_RBAC[role].includes(a))) {
        const { s, r, e } = perfect(role, action);
        const d = evaluate({ ...s, clearance: "OFFICIAL" }, action, { ...r!, classification: "CONFIDENTIAL" }, e);
        expect(d.effect, `${role}/${action}`).toBe("deny");
        expect(d.matchedRules).toContain("abac.clearance-floor");
      }
    }
  });
});

describe("need-to-know compartments (T-15)", () => {
  const cases: [string, string[], string[], boolean][] = [
    ["resource has none, subject has none", [], [], true],
    ["resource has none, subject has some", [], ["A", "B"], true],
    ["equal sets", ["A"], ["A"], true],
    ["subject superset", ["A"], ["A", "B"], true],
    ["subject subset (missing one)", ["A", "B"], ["A"], false],
    ["disjoint", ["A"], ["B"], false],
    ["subject has none, resource has one", ["A"], [], false],
    ["duplicates in resource", ["A", "A"], ["A"], true],
    ["duplicates in subject", ["A"], ["A", "A"], true],
    ["case sensitive", ["A"], ["a"], false],
    ["whitespace is not trimmed", ["A"], ["A "], false],
    ["empty-string compartment is a real tag", [""], [], false],
  ];
  it.each(cases)("%s", (_n, res, sub, allowed) => {
    const d = evaluate(subject({ compartments: sub }), "read", resource({ compartments: res }), env());
    expect(d.effect).toBe(allowed ? "allow" : "deny");
    if (!allowed) expect(d.reason).toBe("COMPARTMENT_MISSING");
  });
});

describe("malformed input fails closed (T-13)", () => {
  const good = { s: subject(), r: resource(), e: env() };
  const bad: [string, () => unknown[]][] = [
    ["subject null", () => [null, "read", good.r, good.e]],
    ["subject string", () => ["analyst", "read", good.r, good.e]],
    ["subject unknown clearance", () => [subject({ clearance: "TOPSECRET" }), "read", good.r, good.e]],
    ["subject lower-case clearance", () => [subject({ clearance: "secret" }), "read", good.r, good.e]],
    ["subject clearance number", () => [{ ...subject(), clearance: 2 }, "read", good.r, good.e]],
    ["subject missing id", () => [{ ...subject(), id: undefined }, "read", good.r, good.e]],
    ["subject empty id", () => [subject({ id: "" }), "read", good.r, good.e]],
    ["subject roles not array", () => [{ ...subject(), roles: "analyst" }, "read", good.r, good.e]],
    ["subject roles with non-string", () => [{ ...subject(), roles: ["analyst", 1] }, "read", good.r, good.e]],
    ["subject missing unit", () => [{ ...subject(), unit: undefined }, "read", good.r, good.e]],
    ["subject compartments missing", () => [{ ...subject(), compartments: undefined }, "read", good.r, good.e]],
    ["subject compartments non-string", () => [{ ...subject(), compartments: [1] }, "read", good.r, good.e]],
    ["action unknown", () => [good.s, "destroy", good.r, good.e]],
    ["action undefined", () => [good.s, undefined, good.r, good.e]],
    ["action inherited name", () => [good.s, "toString", good.r, good.e]],
    ["resource null for a resource action", () => [good.s, "read", null, good.e]],
    ["resource unknown classification", () => [good.s, "read", resource({ classification: "TOP" }), good.e]],
    ["resource missing classification", () => [good.s, "read", { ...resource(), classification: undefined }, good.e]],
    ["resource unknown status", () => [good.s, "read", resource({ status: "archived" }), good.e]],
    ["resource missing owner unit", () => [good.s, "read", { ...resource(), ownerUnit: undefined }, good.e]],
    ["resource compartments missing", () => [good.s, "read", { ...resource(), compartments: undefined }, good.e]],
    ["resource missing author", () => [good.s, "read", { ...resource(), authorId: undefined }, good.e]],
    ["resource submittedById number", () => [good.s, "read", { ...resource(), submittedById: 5 }, good.e]],
    ["resource array", () => [good.s, "read", [], good.e]],
    ["env null", () => [good.s, "read", good.r, null]],
    ["env missing acr", () => [good.s, "read", good.r, { ...good.e, acr: undefined }]],
    ["env amr not array", () => [good.s, "read", good.r, { ...good.e, amr: "otp" }]],
    ["env now NaN", () => [good.s, "read", good.r, { ...good.e, now: NaN }]],
    ["env now string", () => [good.s, "read", good.r, { ...good.e, now: "1" }]],
    ["env now Infinity", () => [good.s, "read", good.r, { ...good.e, now: Infinity }]],
    ["env zone missing", () => [good.s, "read", good.r, { ...good.e, networkZone: undefined }]],
    ["env breakGlass wrong shape", () => [good.s, "read", good.r, { ...good.e, breakGlass: "yes" }]],
    ["env breakGlass justification not string", () => [good.s, "read", good.r, { ...good.e, breakGlass: { justification: 1 } }]],
  ];
  it.each(bad)("%s -> deny INVALID_INPUT", (_n, args) => {
    const d = (evaluate as (...a: unknown[]) => ReturnType<typeof evaluate>)(...args());
    expect(d.effect).toBe("deny");
    expect(d.reason).toBe("INVALID_INPUT");
  });

  it("resource-less actions ignore the resource but still validate subject and env", () => {
    expect(evaluate(subject({ roles: ["auditor"] }), "readAudit", null, env()).effect).toBe("allow");
    expect(evaluate(subject({ roles: ["auditor"], clearance: "x" }), "readAudit", null, env()).reason).toBe("INVALID_INPUT");
    expect(evaluate(subject({ roles: ["auditor"] }), "readAudit", null, { ...env(), now: NaN }).reason).toBe("INVALID_INPUT");
  });
});

describe("step-up for SECRET (T-17)", () => {
  const cases: [string, string, string[], boolean][] = [
    ["password only", "pwd", ["pwd"], false],
    ["mfa acr but amr lacks otp", "mfa", ["pwd"], false],
    ["otp in amr but acr is pwd (downgrade request)", "pwd", ["pwd", "otp"], false],
    ["acr mfa and otp", "mfa", ["pwd", "otp"], true],
    ["acr mfa, amr only otp", "mfa", ["otp"], true],
    ["acr case differs", "MFA", ["pwd", "otp"], false],
    ["otp case differs", "mfa", ["pwd", "OTP"], false],
    ["acr empty", "", ["otp"], false],
    ["acr numeric string", "2", ["pwd", "otp"], false],
  ];
  it.each(cases)("SECRET read, %s", (_n, acr, amr, allowed) => {
    const d = evaluate(subject({ clearance: "SECRET" }), "read", resource({ classification: "SECRET" }), env({ acr, amr }));
    expect(d.effect).toBe(allowed ? "allow" : "deny");
    if (!allowed) {
      expect(d.reason).toBe("STEP_UP_REQUIRED");
      expect(d.obligations).toEqual(["step-up"]);
    }
  });

  it("every action on a SECRET file needs it", () => {
    for (const role of ROLES) {
      for (const action of RESOURCE_ACTIONS.filter((a) => EXPECTED_RBAC[role].includes(a))) {
        const { s, r, e } = perfect(role, action);
        const secret = { ...r!, classification: "SECRET" };
        expect(evaluate(s, action, secret, e).effect, `${role}/${action} with mfa`).toBe("allow");
        const d = evaluate(s, action, secret, { ...e, acr: "pwd", amr: ["pwd"] });
        expect(d.effect, `${role}/${action} without mfa`).toBe("deny");
        expect(d.reason).toBe("STEP_UP_REQUIRED");
      }
    }
  });

  it("is not demanded for OFFICIAL or CONFIDENTIAL", () => {
    for (const c of ["OFFICIAL", "CONFIDENTIAL"]) {
      expect(evaluate(subject({ clearance: "SECRET" }), "read", resource({ classification: c }), env()).effect).toBe("allow");
    }
  });
});

describe("unit scope on writes (T-15)", () => {
  it.each(["create", "update", "submit", "delete"] as const)("%s in another unit is denied for a unit-admin", (action) => {
    const { s, r, e } = perfect("unit-admin", action);
    const d = evaluate(s, action, { ...r!, ownerUnit: "beta" }, e);
    expect(d.reason).toBe("UNIT_MISMATCH");
  });

  it("approve in another unit: denied for unit-admin, allowed for reviewer (cross-unit approve)", () => {
    const ua = perfect("unit-admin", "approve");
    expect(evaluate(ua.s, "approve", { ...ua.r!, ownerUnit: "beta" }, ua.e).reason).toBe("UNIT_MISMATCH");
    const rv = perfect("reviewer", "approve");
    expect(evaluate(rv.s, "approve", { ...rv.r!, ownerUnit: "beta" }, rv.e).effect).toBe("allow");
  });

  it.each(["read", "export"] as const)("%s across units is not unit-scoped", (action) => {
    const { s, r, e } = perfect("unit-admin", action);
    expect(evaluate(s, action, { ...r!, ownerUnit: "beta" }, e).effect).toBe("allow");
  });

  it("unit comparison is exact", () => {
    const { s, r, e } = perfect("unit-admin", "update");
    for (const u of ["Alpha", "alpha ", "alph", ""]) {
      expect(evaluate(s, "update", { ...r!, ownerUnit: u || "x" }, e).effect).toBe("deny");
    }
  });
});

describe("ownership for analysts (T-15)", () => {
  it.each(["update", "submit", "delete"] as const)("analyst %s of someone else's draft is denied", (action) => {
    const { s, r, e } = perfect("analyst", action);
    const d = evaluate(s, action, { ...r!, authorId: "other" }, e);
    expect(d.reason).toBe("NOT_OWNER");
  });

  it("unit-admin is not bound to ownership", () => {
    const { s, r, e } = perfect("unit-admin", "update");
    expect(evaluate(s, "update", { ...r!, authorId: "other" }, e).effect).toBe("allow");
  });

  it("a subject who is analyst and unit-admin is not own-only (some granting role is free)", () => {
    const { s, r, e } = perfect("analyst", "update");
    expect(evaluate({ ...s, roles: ["analyst", "unit-admin"] }, "update", { ...r!, authorId: "other" }, e).effect).toBe("allow");
  });

  it("analyst read is not ownership bound", () => {
    const { s, r, e } = perfect("analyst", "read");
    expect(evaluate(s, "read", { ...r!, authorId: "other" }, e).effect).toBe("allow");
  });
});

describe("status machine", () => {
  const rows = RESOURCE_ACTIONS.flatMap((action) => STATUSES.map((status) => ({ action, status, allowed: STATUS_FOR[action] === status || (action === "read") })));
  it.each(rows)("$action on $status -> $allowed", ({ action, status, allowed }) => {
    const { s, r, e } = perfect("unit-admin", action);
    const d = evaluate(s, action, { ...r!, status, authorId: action === "create" ? r!.authorId : "other" }, e);
    expect(d.effect).toBe(allowed ? "allow" : "deny");
    if (!allowed) expect(d.reason).toBe("STATUS_FORBIDS");
  });

  it("no update after approved, delete only draft, export only approved (explicit)", () => {
    const u = perfect("unit-admin", "update");
    expect(evaluate(u.s, "update", { ...u.r!, status: "approved" }, u.e).reason).toBe("STATUS_FORBIDS");
    const dl = perfect("unit-admin", "delete");
    expect(evaluate(dl.s, "delete", { ...dl.r!, status: "submitted" }, dl.e).reason).toBe("STATUS_FORBIDS");
    const ex = perfect("analyst", "export");
    expect(evaluate(ex.s, "export", { ...ex.r!, status: "draft" }, ex.e).reason).toBe("STATUS_FORBIDS");
  });
});

describe("separation of duties on approve (T-16)", () => {
  const approve = (over: Parameters<typeof resource>[0], who = "actor") => {
    const { s, e } = perfect("reviewer", "approve");
    return evaluate({ ...s, id: who }, "approve", resource({ status: "submitted", compartments: ["A"], authorId: "author", ...over }), e);
  };
  it("approver is not the author", () => expect(approve({ authorId: "actor" }).reason).toBe("SEPARATION_OF_DUTIES"));
  it("approver is not the submitter", () => expect(approve({ submittedById: "actor" }).reason).toBe("SEPARATION_OF_DUTIES"));
  it("author and submitter both other: allowed", () => expect(approve({ submittedById: "third" }).effect).toBe("allow"));
  it("no submitter recorded: only author is compared", () => expect(approve({ submittedById: undefined }).effect).toBe("allow"));
  it("a unit-admin cannot approve their own file either", () => {
    const { s, e } = perfect("unit-admin", "approve");
    const d = evaluate(s, "approve", resource({ status: "submitted", compartments: ["A"], authorId: "actor" }), e);
    expect(d.reason).toBe("SEPARATION_OF_DUTIES");
  });
  it("holds across units and with a SECRET clearance", () => {
    const { s, e } = perfect("reviewer", "approve");
    const d = evaluate(s, "approve", resource({ status: "submitted", compartments: ["A"], authorId: "actor", ownerUnit: "beta" }), e);
    expect(d.reason).toBe("SEPARATION_OF_DUTIES");
  });
});

describe("export conditions: network zone and window", () => {
  const exp = (e: Parameters<typeof env>[0]) => {
    const { s, r } = perfect("analyst", "export");
    return evaluate(s, "export", r, env({ ...MFA, ...e }));
  };
  it("managed zone inside the window is allowed", () => expect(exp({}).effect).toBe("allow"));
  it.each(["office", "unmanaged", "", "MANAGED", "managed "])("zone %j is denied", (z) => expect(exp({ networkZone: z }).reason).toBe("NETWORK_ZONE_FORBIDS"));
  it.each([
    [5, 59, false],
    [6, 0, true],
    [12, 0, true],
    [19, 59, true],
    [20, 0, false],
    [0, 0, false],
    [23, 59, false],
  ])("%i:%i UTC -> %s", (h, m, ok) => {
    const d = exp({ now: at(h, m) });
    expect(d.effect).toBe(ok ? "allow" : "deny");
    if (!ok) expect(d.reason).toBe("OUTSIDE_EXPORT_WINDOW");
  });
  it("both violated: zone is reported first, both are listed", () => {
    const d = exp({ networkZone: "office", now: at(3) });
    expect(d.reason).toBe("NETWORK_ZONE_FORBIDS");
    expect(d.matchedRules).toEqual(expect.arrayContaining(["abac.export-network-zone", "abac.export-window"]));
  });
  it("only export has these conditions", () => {
    const { s, r } = perfect("analyst", "read");
    expect(evaluate(s, "read", r, env({ ...MFA, networkZone: "office", now: at(3) })).effect).toBe("allow");
  });
});

describe("break-glass read (T-25)", () => {
  const bg = (justification: string) => ({ breakGlass: { justification } });
  const hiddenFile = resource({ classification: "CONFIDENTIAL", compartments: ["A"], ownerUnit: "alpha" });
  const admin = subject({ id: "adm", roles: ["unit-admin"], clearance: "CONFIDENTIAL", unit: "beta", compartments: [] });

  it("a unit-admin with a justification reads past a compartment gap, with audit and alert obligations", () => {
    const d = evaluate(admin, "read", hiddenFile, env(bg("incident 4711")));
    expect(d.effect).toBe("allow");
    expect(d.reason).toBe("ALLOWED_BREAK_GLASS");
    expect(d.obligations).toEqual(["audit", "alert"]);
    expect(d.matchedRules).toContain("break-glass.override-need-to-know");
  });

  it("without the flag the same read is denied", () => {
    expect(evaluate(admin, "read", hiddenFile, env()).reason).toBe("COMPARTMENT_MISSING");
  });

  it.each(["", " ", "\n\t "])("flag with empty justification %j is denied and asks for one", (j) => {
    const d = evaluate(admin, "read", hiddenFile, env(bg(j)));
    expect(d.effect).toBe("deny");
    expect(d.reason).toBe("BREAK_GLASS_JUSTIFICATION_REQUIRED");
    expect(d.obligations).toEqual(["require-justification"]);
  });

  it("empty justification is refused even when normal access would have worked", () => {
    const d = evaluate(subject(), "read", resource(), env(bg("")));
    expect(d.reason).toBe("BREAK_GLASS_JUSTIFICATION_REQUIRED");
  });

  it("not needed: normal allow, no alert", () => {
    const d = evaluate(subject(), "read", resource(), env(bg("just looking")));
    expect(d.reason).toBe("ALLOWED");
    expect(d.obligations).toEqual(["audit"]);
  });

  it.each(["analyst", "reviewer", "auditor", "platform-admin"])("role %s has no break-glass grant", (role) => {
    const d = evaluate({ ...admin, roles: [role] }, "read", hiddenFile, env(bg("incident")));
    expect(d.effect).toBe("deny");
    expect(["BREAK_GLASS_NOT_PERMITTED", "ROLE_NOT_PERMITTED"]).toContain(d.reason);
  });

  it("analyst with a read grant but no break-glass: BREAK_GLASS_NOT_PERMITTED", () => {
    expect(evaluate({ ...admin, roles: ["analyst"] }, "read", hiddenFile, env(bg("incident"))).reason).toBe("BREAK_GLASS_NOT_PERMITTED");
  });

  it("never beats the clearance floor", () => {
    const d = evaluate(admin, "read", resource({ classification: "SECRET", compartments: ["A"] }), env({ ...MFA, ...bg("incident") }));
    expect(d.effect).toBe("deny");
    expect(d.reason).toBe("CLEARANCE_TOO_LOW");
  });

  it("never beats the floor even when need-to-know is also missing", () => {
    const d = evaluate(admin, "read", resource({ classification: "SECRET", compartments: ["A", "B"] }), env({ ...MFA, ...bg("incident") }));
    expect(d.reason).toBe("CLEARANCE_TOO_LOW");
  });

  it("never beats step-up", () => {
    const top = { ...admin, clearance: "SECRET", compartments: ["A"] };
    const f = resource({ classification: "SECRET", compartments: ["A"] });
    expect(evaluate(top, "read", f, env(bg("incident"))).reason).toBe("STEP_UP_REQUIRED");
    const gap = resource({ classification: "SECRET", compartments: ["A", "B"] });
    expect(evaluate(top, "read", gap, env({ ...MFA, ...bg("incident") })).reason).toBe("ALLOWED_BREAK_GLASS");
    expect(evaluate(top, "read", gap, env(bg("incident"))).effect).toBe("deny");
  });

  it("applies to read only", () => {
    for (const action of ["update", "delete", "approve", "export", "submit"] as const) {
      const { s, e } = perfect("unit-admin", action);
      const d = evaluate({ ...s, compartments: [] }, action, resource({ compartments: ["A"], status: STATUS_FOR[action], authorId: "other" }), { ...e, breakGlass: { justification: "incident" } });
      expect(d.effect, action).toBe("deny");
      expect(d.reason).toBe("COMPARTMENT_MISSING");
    }
  });

  it("does not help a role that cannot read at all", () => {
    expect(evaluate(subject({ roles: ["auditor"] }), "read", resource(), env(bg("incident"))).reason).toBe("ROLE_NOT_PERMITTED");
  });
});

describe("deny overrides allow, deterministic reasons (T-11)", () => {
  it("reports the highest priority violation and lists every violated rule", () => {
    const d = evaluate(
      subject({ id: "u", roles: ["reviewer"], clearance: "OFFICIAL", unit: "alpha", compartments: [] }),
      "approve",
      resource({ classification: "SECRET", compartments: ["A"], status: "draft", authorId: "u" }),
      env(),
    );
    expect(d.effect).toBe("deny");
    expect(d.reason).toBe("CLEARANCE_TOO_LOW");
    expect(d.matchedRules).toEqual(
      expect.arrayContaining(["abac.clearance-floor", "abac.need-to-know", "abac.status-machine", "abac.separation-of-duties", "abac.step-up"]),
    );
  });

  it("a role grant never rescues an ABAC violation", () => {
    for (const role of ROLES) {
      for (const action of RESOURCE_ACTIONS.filter((a) => EXPECTED_RBAC[role].includes(a))) {
        const { s, r, e } = perfect(role, action);
        expect(evaluate({ ...s, compartments: [] }, action, r, e).effect, `${role}/${action}`).toBe("deny");
      }
    }
  });

  it("allow lists the role grant and each rule that applied", () => {
    const { s, r, e } = perfect("reviewer", "approve");
    const d = evaluate(s, "approve", r, e);
    expect(d.matchedRules).toEqual(
      expect.arrayContaining(["rbac.role-grants-action", "rbac.grant:reviewer", "abac.clearance-floor", "abac.need-to-know", "abac.unit-scope", "abac.status-machine", "abac.separation-of-duties"]),
    );
  });
});

describe("purity and determinism", () => {
  it("same input, same decision, repeatedly", () => {
    const { s, r, e } = perfect("unit-admin", "update");
    const first = evaluate(s, "update", r, e);
    for (let i = 0; i < 20; i++) expect(evaluate(s, "update", r, e)).toEqual(first);
  });

  it("does not read the clock: the decision depends only on env.now", () => {
    const { s, r } = perfect("analyst", "export");
    const e = env({ ...MFA });
    const before = evaluate(s, "export", r, e);
    const real = Date.now;
    Date.now = () => 0;
    try {
      expect(evaluate(s, "export", r, e)).toEqual(before);
    } finally {
      Date.now = real;
    }
  });

  it("does not mutate its inputs and returns frozen decisions", () => {
    const s = Object.freeze(subject({ roles: Object.freeze(["unit-admin"]) as unknown as string[], compartments: Object.freeze([]) as unknown as string[] }));
    const r = Object.freeze(resource({ compartments: Object.freeze(["A"]) as unknown as string[] }));
    const e = Object.freeze(env({ breakGlass: Object.freeze({ justification: "x" }) }));
    const snapshot = JSON.stringify([s, r, e]);
    const d = evaluate(s, "read", r, e);
    expect(JSON.stringify([s, r, e])).toBe(snapshot);
    expect(Object.isFrozen(d)).toBe(true);
    expect(Object.isFrozen(d.matchedRules)).toBe(true);
    expect(Object.isFrozen(d.obligations)).toBe(true);
    expect(Object.isFrozen(evaluate(subject({ roles: [] }), "read", r, env()))).toBe(true);
  });
});

describe("create is decided on the candidate resource", () => {
  it("analyst creates an OFFICIAL draft in own unit", () => {
    expect(evaluate(subject(), "create", resource(), env()).effect).toBe("allow");
  });
  it("cannot create above own clearance", () => {
    expect(evaluate(subject(), "create", resource({ classification: "SECRET" }), env({ ...MFA })).reason).toBe("CLEARANCE_TOO_LOW");
  });
  it("cannot create with compartments they lack", () => {
    expect(evaluate(subject(), "create", resource({ compartments: ["A"] }), env()).reason).toBe("COMPARTMENT_MISSING");
  });
  it("cannot create in another unit", () => {
    expect(evaluate(subject(), "create", resource({ ownerUnit: "beta" }), env()).reason).toBe("UNIT_MISMATCH");
  });
  it("cannot create as approved or submitted", () => {
    for (const status of ["approved", "submitted"]) expect(evaluate(subject(), "create", resource({ status }), env()).reason).toBe("STATUS_FORBIDS");
  });
  it("cannot create on behalf of another author", () => {
    expect(evaluate(subject(), "create", resource({ authorId: "other" }), env()).reason).toBe("NOT_OWNER");
  });
});


describe("evaluateRole: role-only decision for routes without a resource", () => {
  const cases = ROLES.flatMap((role) => ACTIONS.map((action) => ({ role, action, allowed: EXPECTED_RBAC[role].includes(action) })));
  it.each(cases)("$role / $action -> $allowed", ({ role, action, allowed }) => {
    const d = evaluateRole(subject({ roles: [role] }), action);
    expect(d.effect).toBe(allowed ? "allow" : "deny");
    expect(d.reason).toBe(allowed ? "ALLOWED" : "ROLE_NOT_PERMITTED");
  });
  it("unknown roles, inherited names, no roles: denied", () => {
    for (const roles of [[], ["x"], ["constructor"], ["__proto__"]]) expect(evaluateRole(subject({ roles }), "read").reason).toBe("ROLE_NOT_PERMITTED");
  });
  it("invalid subject or action: INVALID_INPUT", () => {
    expect(evaluateRole(subject({ clearance: "x" }), "read").reason).toBe("INVALID_INPUT");
    expect(evaluateRole(subject(), "nope" as Action).reason).toBe("INVALID_INPUT");
    expect((evaluateRole as (...a: unknown[]) => { reason: string })(null, "read").reason).toBe("INVALID_INPUT");
  });
  it("lists every granting role once", () => {
    expect(evaluateRole(subject({ roles: ["analyst", "analyst", "unit-admin"] }), "read").matchedRules).toEqual(["rbac.role-grants-action", "rbac.grant:analyst", "rbac.grant:unit-admin"]);
  });
});
