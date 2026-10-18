// The database vocabulary and the policy package cannot drift apart; no string-built SQL anywhere (T-13, T-14, T-15).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { ROLE_GRANTS, CLEARANCES, STATUSES, ACTIONS, ROLES } from "@acl/policy";
import { afterAll, describe, expect, it } from "vitest";
import { adminPool } from "./db.js";

const admin = adminPool();
afterAll(() => admin.end());

describe("database vocabulary equals packages/policy", () => {
  it("classification enum, in rank order", async () => {
    const r = await admin.query("SELECT unnest(enum_range(NULL::classification))::text AS v");
    expect(r.rows.map((x) => x.v)).toEqual([...CLEARANCES]);
  });

  it("case_status enum", async () => {
    const r = await admin.query("SELECT unnest(enum_range(NULL::case_status))::text AS v");
    expect(r.rows.map((x) => x.v)).toEqual([...STATUSES]);
  });

  it("role_grants table equals ROLE_GRANTS (role, action, cross-unit, own-only, break-glass)", async () => {
    const want = ROLES.flatMap((role) =>
      ROLE_GRANTS[role].actions.map((action) => ({
        role,
        action,
        cross_unit: ROLE_GRANTS[role].crossUnit.includes(action),
        own_only: ROLE_GRANTS[role].ownOnly.includes(action),
        break_glass: action === "read" && ROLE_GRANTS[role].breakGlass,
      })),
    );
    const got = (await admin.query("SELECT role, action, cross_unit, own_only, break_glass FROM role_grants")).rows;
    const key = (x: { role: string; action: string }) => `${x.role}/${x.action}`;
    expect(got.sort((a, b) => key(a).localeCompare(key(b)))).toEqual(want.sort((a, b) => key(a).localeCompare(key(b))));
  });

  it("every action in role_grants is a known action; every role a known role", async () => {
    const r = (await admin.query("SELECT DISTINCT role, action FROM role_grants")).rows;
    for (const x of r) {
      expect(ROLES as readonly string[]).toContain(x.role);
      expect(ACTIONS as readonly string[]).toContain(x.action);
    }
  });

  it("break-glass is configured for read only", async () => {
    const r = await admin.query("SELECT 1 FROM role_grants WHERE break_glass AND action <> 'read'");
    expect(r.rows).toEqual([]);
  });
});

// ---- no template-literal SQL ----

const API_SRC = fileURLToPath(new URL("../../../apps/api/src/", import.meta.url));
const SQL_WORD = /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP|ALTER|CREATE|TRUNCATE|WHERE|FROM)\b/;

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? files(p) : p.endsWith(".ts") && !p.endsWith(".test.ts") ? [p] : [];
  });
}

/** Template literals that look like SQL and interpolate a value, or any `sql` template that interpolates. */
export function findTemplateSql(source: string): string[] {
  const hits: string[] = [];
  const re = /([A-Za-z_$][\w$]*)?`((?:[^`\\]|\\.)*)`/g;
  for (const m of source.matchAll(re)) {
    const tag = m[1] ?? "";
    const text = m[2] ?? "";
    if (!text.includes("${")) continue;
    if (tag === "sql" || SQL_WORD.test(text.replace(/\$\{[^}]*\}/g, ""))) hits.push(m[0].slice(0, 80));
  }
  return hits;
}

describe("no string-built SQL in the API source (T-14)", () => {
  it("the scanner itself catches the usual mistakes", () => {
    expect(findTemplateSql("db.query(`SELECT * FROM t WHERE id = ${id}`)")).toHaveLength(1);
    expect(findTemplateSql("sql`SELECT ${x}`")).toHaveLength(1);
    expect(findTemplateSql("const q = `DELETE FROM files WHERE a = '${a}'`")).toHaveLength(1);
    expect(findTemplateSql("log(`user ${u} logged in`)")).toHaveLength(0);
    expect(findTemplateSql("sql`SELECT 1 WHERE id = $1`")).toHaveLength(0);
  });

  it("apps/api/src has none", () => {
    const bad = files(API_SRC).flatMap((f) => findTemplateSql(readFileSync(f, "utf8")).map((h) => `${f.replace(API_SRC, "")}: ${h}`));
    expect(bad).toEqual([]);
  });

  it("every query call in the data layer passes a sql`` constant or a literal, never a variable built at runtime", () => {
    const src = readFileSync(join(API_SRC, "db/case-file.repository.ts"), "utf8");
    const calls = [...src.matchAll(/tx\.query(?:<[^>]*>)?\(([A-Za-z_]+)/g)].map((m) => m[1]);
    expect(calls.length).toBeGreaterThan(5);
    for (const c of calls) expect(src, c).toMatch(new RegExp(`const ${c} = sql\``));
  });
});
