// A-90..A-95: property-based fuzzing of the inputs of the API and the BFF. The seed is fixed in CI (FUZZ_SEED unset: 20261018) and printed, a random one runs
// in the nightly workflow (FUZZ_SEED=random). Properties: never a 5xx, never a stack trace or an internal path, a consistent error shape,
// and a valid request with ONE extra field is never accepted.
import fc from "fast-check";
import { beforeAll, describe, expect, it } from "vitest";
import { api, FORM, form, vault } from "./http.js";
import { oidcTokens, type Tokens } from "./kc.js";
import { bff, session } from "./sessions.js";
import type { BffSession } from "./kc.js";

const SEED = process.env.FUZZ_SEED === "random" ? Math.floor(Math.random() * 2 ** 31) : Number(process.env.FUZZ_SEED ?? 20261018);
const RUNS = Number(process.env.FUZZ_RUNS ?? 60);
const LEAK = /stack|node_modules|\bat \S+ \(|\.tsx?:\d+|\.js:\d+|Error:|ECONN|postgres|pg_|SELECT |relation "|syntax error|\/app\/|\/usr\//i;
const cfg = { seed: SEED, numRuns: RUNS, interruptAfterTimeLimit: 120_000 };
console.log(`FUZZ seed ${SEED}, ${RUNS} runs per property (re-run with FUZZ_SEED=${SEED})`);

const NASTY = ["", " ", "\u0000", "\u0000abc", "a\u0000b", "\ud800", "\udfff", "\ufeff", "\u202e", "\u200b", "\uffff", "😀".repeat(50), "é".repeat(200), "e\u0301".repeat(60), "../".repeat(30), "%00", "%ff", "%zz", "${7*7}", "{{7*7}}", "<script>", "\\", "\\\\\\", "'", '"', "`", "\r\n", "\n", "__proto__", "constructor", "prototype", "toString", "null", "undefined", "true", "0", "-0", "1e999", "NaN", "Infinity", "9".repeat(400), "a".repeat(5000)];
const str = fc.oneof(fc.string({ unit: "binary" }), fc.string({ unit: "grapheme" }), fc.constantFrom(...NASTY), fc.stringMatching(/^[ -~]{0,200}$/));
const num = fc.oneof(fc.integer(), fc.double({ noNaN: true }), fc.constantFrom(0, -1, 2 ** 31, 2 ** 53, -(2 ** 53), 1e308, 5e-324));
const value: fc.Arbitrary<unknown> = fc.letrec((tie) => ({ v: fc.oneof({ depthSize: "small", maxDepth: 6 }, str, num, fc.boolean(), fc.constant(null), fc.array(tie("v"), { maxLength: 4 }), fc.dictionary(str, tie("v"), { maxKeys: 4 })) })).v;

const shape = (r: { status: number; text: string; json: unknown }, where: string) => {
  expect(r.status, `${where}: server error ${r.text.slice(0, 120)}`).toBeLessThan(500);
  expect(r.text.slice(0, 800), `${where}: leak`).not.toMatch(LEAK);
};

let s: BffSession;
let admin: BffSession;
let auditor: BffSession;
let t: Tokens;
let target: string;
let editTarget: string; // stays a draft: PATCH on a frozen file is refused for authorisation before the body is looked at
beforeAll(async () => {
  s = await session("analyst-official");
  admin = await session("unit-admin-alpha");
  auditor = await session("auditor");
  t = await oidcTokens("unit-admin-alpha");
  target = ((await bff(admin, "POST", "/case-files", { title: "attack: fuzz target", classification: "OFFICIAL", compartments: [] })).json as { id: string }).id;
  editTarget = ((await bff(admin, "POST", "/case-files", { title: "attack: fuzz edit target", classification: "OFFICIAL", compartments: [] })).json as { id: string }).id;
}, 300_000);

const bearer = () => ({ authorization: `Bearer ${t.access_token}`, "content-type": "application/json" });
const rawJson = (body: string) => ({ headers: bearer(), body });

describe("A-90 the API: arbitrary JSON bodies", () => {
  it("any value as the body of a create, an update or an approval: a client error with the common shape, never a 5xx, never a leak", async () => {
    await fc.assert(
      fc.asyncProperty(value, async (v) => {
        for (const [method, path] of [["POST", "/case-files"], ["PATCH", `/case-files/${editTarget}`], ["POST", `/case-files/${target}/submit`]] as const) {
          const r = await api(path, { method, ...rawJson(JSON.stringify(v) ?? "null") });
          shape(r, `${method} ${path} ${JSON.stringify(v)?.slice(0, 80)}`);
          if (r.status >= 400 && r.json) expect(Object.keys(r.json as object).every((k) => ["statusCode", "error", "message", "code"].includes(k))).toBe(true);
        }
      }),
      cfg,
    );
  });
  it("bodies that are not JSON at all, truncated JSON, huge numbers, BOMs, wrong content types", async () => {
    const raw = ["", "{", '{"title":', '{"title":"x"', "\ufeff{}", '{"version":1e999}', '{"version":-1e999}', '{"version":0.1e1}', '{"a":' + "[".repeat(500), '{"title":"x","title":"y"}', "{'title':'x'}", "\u0000", "null", "[]", '"str"', "12", "true", "{}".repeat(1000)];
    for (const body of raw) for (const ct of ["application/json", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "application/json; charset=utf-16", ""]) {
      const r = await api("/case-files", { method: "POST", headers: { authorization: `Bearer ${t.access_token}`, ...(ct ? { "content-type": ct } : {}) }, body });
      shape(r, `${JSON.stringify(body.slice(0, 40))} as ${ct}`);
    }
  });
});

describe("A-91 the API: arbitrary identifiers, query strings and headers", () => {
  it("any string as an id, any query on the list and audit endpoints, any value in a header", async () => {
    const a = await oidcTokens("auditor");
    await fc.assert(
      fc.asyncProperty(str, str, async (x, y) => {
        const enc = encodeURIComponent(x.toWellFormed());
        for (const path of [`/case-files/${enc}`, `/case-files/${enc}/attachments`, `/case-files/${enc}/attachments/${encodeURIComponent(y.toWellFormed())}`, `/case-files?${enc}=${encodeURIComponent(y.toWellFormed())}`, `/audit-log?${new URLSearchParams({ actor: x.toWellFormed(), cursor: y.toWellFormed(), limit: x.toWellFormed(), from: y.toWellFormed(), effect: x.toWellFormed() })}`, `/audit-log/export?${new URLSearchParams({ format: x.toWellFormed(), cursor: y.toWellFormed() })}`]) {
          const r = await api(path, { headers: { authorization: `Bearer ${a.access_token}` } });
          shape(r, path.slice(0, 100));
        }
        const header = y.replace(/[^\x20-\x7e]/g, "");
        shape(await api("/me", { headers: { authorization: `Bearer ${t.access_token}`, "x-break-glass-justification": header, "x-acl-zone": header, "x-attachment-name": header, "x-attachment-type": header } }), "headers");
      }),
      cfg,
    );
  });
});

describe("A-92 the API: uploads with arbitrary bytes, names and types", () => {
  it("random bytes, random declared types and encoded names are refused or stored harmlessly, never a 5xx", async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ maxLength: 4000 }), str, str, async (bytes, type, name) => {
        const r = await api(`/case-files/${target}/attachments`, { method: "POST", headers: { authorization: `Bearer ${t.access_token}`, "content-type": "application/octet-stream", "x-attachment-type": type.replace(/[^\x20-\x7e]/g, "").slice(0, 100), "x-attachment-name": encodeURIComponent(name.toWellFormed()).slice(0, 600) }, body: Buffer.from(bytes) });
        shape(r, "upload");
        expect([201, 400, 403, 404, 413, 415, 422], `status ${r.status}`).toContain(r.status);
      }),
      { ...cfg, numRuns: Math.min(RUNS, 40) },
    );
  });
});

describe("A-93 the BFF: arbitrary JSON, forms and query strings", () => {
  it("any value through the JSON proxy, and any strings through the forms and the break-glass page", async () => {
    await fc.assert(
      fc.asyncProperty(value, str, str, async (v, x, y) => {
        shape(await vault("/bff/case-files", { method: "POST", jar: admin.jar, headers: { origin: "https://vault.localhost", "x-csrf-token": admin.csrf, "content-type": "application/json" }, body: JSON.stringify(v) ?? "null" }), "proxy create");
        shape(await vault("/actions/case-files/create", { method: "POST", jar: admin.jar, headers: { ...FORM, origin: "https://vault.localhost" }, body: form({ csrf: admin.csrf, title: x, body: y, classification: x, compartments: y }) }), "create form");
        shape(await vault(`/actions/case-files/${target}/update`, { method: "POST", jar: admin.jar, headers: { ...FORM, origin: "https://vault.localhost" }, body: form({ csrf: admin.csrf, title: x, body: y, version: x }) }), "update form");
        shape(await vault(`/actions/case-files/${target}/break-glass`, { method: "POST", jar: admin.jar, headers: { ...FORM, origin: "https://vault.localhost" }, body: form({ csrf: admin.csrf, justification: y }) }), "break-glass form");
        shape(await vault(`/cases?${new URLSearchParams({ m: x.toWellFormed(), e: y.toWellFormed() })}`, { jar: s.jar }), "page query");
        shape(await vault(`/audit?${new URLSearchParams({ actor: x.toWellFormed(), cursor: y.toWellFormed(), effect: x.toWellFormed(), limit: y.toWellFormed() })}`, { jar: auditor.jar }), "audit page query");
      }),
      cfg,
    );
  });
  it("arbitrary cookies and arbitrary paths under every route family", async () => {
    await fc.assert(
      fc.asyncProperty(str, str, async (x, y) => {
        const cookie = `__Host-casefile_session=${x.replace(/[^\x21-\x7e]/g, "").replace(/[;,"\\]/g, "")}`;
        shape(await vault("/api/auth/session", { headers: { cookie } }), "cookie");
        for (const base of ["/bff", "/cases", "/actions", "/attachments", "/api/auth", "/audit"]) shape(await vault(`${base}/${encodeURIComponent(x.toWellFormed())}/${encodeURIComponent(y.toWellFormed())}`, { jar: s.jar }), `${base} path`);
      }),
      cfg,
    );
  });
});

describe("A-94 unknown fields are never accepted", () => {
  it("a valid create or update with one extra field of any name and value is refused", async () => {
    const known = new Set(["title", "body", "classification", "compartments", "version"]);
    await fc.assert(
      fc.asyncProperty(str, value, async (name, v) => {
        fc.pre(!known.has(name));
        for (const [method, path, base] of [["POST", "/case-files", { title: "t", classification: "OFFICIAL", compartments: [] }], ["PATCH", `/case-files/${editTarget}`, { title: "t", version: 1 }]] as const) {
          const body = `{"${JSON.stringify(name).slice(1, -1)}":${JSON.stringify(v) ?? "null"},${JSON.stringify(base).slice(1)}`;
          const r = await api(path, { method, ...rawJson(body) });
          shape(r, `${method} ${path} extra ${JSON.stringify(name).slice(0, 40)}`);
          expect(r.status, `an extra field ${JSON.stringify(name).slice(0, 40)} was accepted (${r.status})`).toBe(400);
        }
      }),
      cfg,
    );
  });
});

describe("A-95 prototype pollution payloads", () => {
  it("__proto__, constructor and prototype at any depth, in bodies, queries and forms, are refused and change nothing", async () => {
    const payloads = ['{"__proto__":{"isAdmin":true}}', '{"a":{"__proto__":{"isAdmin":true}}}', '{"constructor":{"prototype":{"isAdmin":true}}}', '{"title":"t","classification":"OFFICIAL","compartments":[],"__proto__":{"status":"approved"}}', '[{"__proto__":{}}]', '{"__pro\\u0074o__":{"x":1}}'];
    for (const p of payloads) {
      const r = await api("/case-files", { method: "POST", ...rawJson(p) });
      expect(r.status, p).toBe(400);
    }
    for (const q of ["__proto__[isAdmin]=1", "constructor[prototype][isAdmin]=1", "__proto__.isAdmin=1"]) {
      shape(await api(`/case-files?${q}`, { headers: { authorization: `Bearer ${t.access_token}` } }), q);
      shape(await vault(`/cases?${q}`, { jar: s.jar }), q);
    }
    const after = await api("/me", { headers: { authorization: `Bearer ${t.access_token}` } });
    expect(JSON.stringify(after.json)).not.toContain("isAdmin");
  });
});
