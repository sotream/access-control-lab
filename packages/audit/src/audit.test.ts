import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { appendAudit, buildRow, genesisHead, rowFromDb, validateEntry, type Db } from "./chain.js";
import { canonicalBytes, checkpointBytes, stableStringify } from "./canonical.js";
import { csvCell, csvLine } from "./csv.js";
import { fingerprint, makeCursor, openCursor } from "./cursor.js";
import { DETAIL_KEYS, sanitizeText, validateDetails } from "./details.js";
import { parseAuditKeys } from "./keys.js";
import { GENESIS_HASH_HEX, type AuditRow } from "./model.js";
import { makeCheckpoint, verifyChain, verifyCheckpointMac } from "./verify.js";
import { T0, chain, clone, entry, keyB64, randomRing, ring } from "./testkit.js";

describe("format spec acl-audit/v1: an independent re-implementation of the spec agrees with the library", () => {
  it("genesis hash is SHA-256 of the ASCII string `acl-audit/v1 genesis`", () => {
    expect(GENESIS_HASH_HEX).toBe(createHash("sha256").update("acl-audit/v1 genesis").digest("hex"));
    expect(genesisHead()).toEqual({ lastId: 0, lastHash: Buffer.from(GENESIS_HASH_HEX, "hex") });
  });

  it("row hash = HMAC-SHA256(key, UTF-8 JSON array of the listed fields), recomputed by hand", () => {
    const r = ring();
    const row = buildRow(entry({ actorRoles: ["reviewer", "analyst"], obligations: ["audit", "alert"], details: { rule_ids: ["z", "a"], alert: true } }), genesisHead(), r, new Date(T0));
    const text = JSON.stringify([
      "acl-audit/v1",
      "1",
      "2026-10-18T12:00:00.000Z",
      "user-1",
      ["analyst", "reviewer"],
      "read",
      "case_file",
      "0f1e2d3c-4b5a-4968-8776-655443322110",
      "allow",
      "ALLOWED",
      ["alert", "audit"],
      "req-00000001",
      "api",
      '{"alert":true,"rule_ids":["z","a"]}',
      GENESIS_HASH_HEX,
      "k1",
    ]);
    expect(canonicalBytes(row).toString("utf8")).toBe(text);
    expect(row.hash.toString("hex")).toBe(createHmac("sha256", Buffer.alloc(32, 1)).update(text).digest("hex"));
  });

  it("golden vector (documented in docs/audit.md): any change to the format breaks this test", () => {
    const row = buildRow(entry(), genesisHead(), ring(), new Date(T0));
    expect(row.hash.toString("hex")).toBe("0a7ca7a8026824380156366d16adcff06e601ee9b0747ea2fd5fa11ca61f7de4");
  });

  it("checkpoint bytes and mac", () => {
    const r = ring();
    const c = makeCheckpoint({ lastId: 7, lastHash: Buffer.alloc(32, 9) }, r, new Date(T0));
    expect(checkpointBytes(c).toString("utf8")).toBe(JSON.stringify(["acl-audit-checkpoint/v1", "2026-10-18T12:00:00.000Z", "7", "09".repeat(32), "k1"]));
    expect(c.mac.toString("hex")).toBe(createHmac("sha256", Buffer.alloc(32, 1)).update(checkpointBytes(c)).digest("hex"));
    expect(verifyCheckpointMac(c, r)).toBe(true);
  });
});

describe("stableStringify", () => {
  it("sorts keys at every depth, keeps array order, escapes strings", () => {
    expect(stableStringify({ b: 1, a: { d: [3, 2, 1], c: "x\"y" }, e: null, f: true })).toBe('{"a":{"c":"x\\"y","d":[3,2,1]},"b":1,"e":null,"f":true}');
  });
  it("refuses anything that is not integers, strings, booleans, null, arrays, objects", () => {
    for (const bad of [1.5, NaN, Infinity, undefined, () => 1, Symbol("x"), 10n]) expect(() => stableStringify(bad), String(bad)).toThrow();
  });
});

describe("entries are validated like the table constraints (T-14, T-24)", () => {
  it("accepts a normal entry", () => expect(() => validateEntry(entry())).not.toThrow());
  it.each([
    ["actor with space", { actorSub: "a b" }],
    ["empty actor", { actorSub: "" }],
    ["too many roles", { actorRoles: Array.from({ length: 17 }, (_, i) => `r${i}`) }],
    ["role with quote", { actorRoles: ["a'b"] }],
    ["action starting with digit", { action: "1read" }],
    ["resource type upper case", { resourceType: "Case" }],
    ["resource id with slash", { resourceId: "a/b" }],
    ["effect other", { effect: "maybe" as never }],
    ["reason lower case", { reasonCode: "allowed" }],
    ["too many obligations", { obligations: Array.from({ length: 9 }, (_, i) => `o${i}`) }],
    ["request id too short", { requestId: "abc" }],
    ["source other", { source: "cli" as never }],
    ["details with a token", { details: { access_token: "eyJ..." } }],
    ["details with a claims dump", { details: { claims: { sub: "x" } } }],
  ])("refuses %s", (_n, over) => expect(() => validateEntry(entry(over as never))).toThrow(/invalid audit entry|details/));
  it("resource id may be null", () => expect(() => validateEntry(entry({ resourceId: null }))).not.toThrow());
});

describe("details: a fixed set of keys with fixed types (no tokens, no claim dumps, no free text)", () => {
  it("allowed keys list", () => expect([...DETAIL_KEYS].sort()).toEqual(["acr", "alert", "authoritative", "count", "detail_code", "event", "filters", "format", "from_id", "justification", "rule_ids", "to_id", "truncated"]));
  it.each([
    [{ justification: "incident 4711" }],
    [{ alert: true, authoritative: false, truncated: true }],
    [{ rule_ids: ["a.b:c"], event: "login", acr: "mfa", detail_code: "X_1" }],
    [{ count: 0, from_id: 1, to_id: 2, format: "csv" }],
    [{ filters: { from: "2026-01-01", actor: "u1", effect: "deny" } }],
    [{}],
  ])("accepts %j", (d) => expect(() => validateDetails(d)).not.toThrow());
  it.each([
    ["not an object", "x"],
    ["array", []],
    ["null", null],
    ["unknown key", { token: "x" }],
    ["justification not sanitised", { justification: "a\nb" }],
    ["justification empty", { justification: "" }],
    ["justification too long", { justification: "x".repeat(501) }],
    ["alert not boolean", { alert: "yes" }],
    ["rule ids not tags", { rule_ids: ["a b"] }],
    ["too many rule ids", { rule_ids: Array.from({ length: 21 }, () => "a") }],
    ["event with space", { event: "a b" }],
    ["format other", { format: "xml" }],
    ["negative count", { count: -1 }],
    ["fractional count", { count: 1.5 }],
    ["filter key unknown", { filters: { password: "x" } }],
    ["filter value long", { filters: { actor: "x".repeat(65) } }],
    ["filter value not string", { filters: { actor: 5 } }],
    ["nested object where a tag is expected", { acr: { a: 1 } }],
  ])("refuses %s", (_n, d) => expect(() => validateDetails(d)).toThrow());
});

describe("details size", () => {
  it("the worst legitimate details object fits the limit with room to spare", () => {
    const d = { justification: "x".repeat(500), rule_ids: Array.from({ length: 20 }, () => "y".repeat(64)), filters: { from: "z".repeat(64), to: "z".repeat(64), actor: "z".repeat(64), resource: "z".repeat(64), action: "z".repeat(64), effect: "z".repeat(64) }, alert: true, authoritative: true, event: "e".repeat(64), acr: "a".repeat(64), detail_code: "d".repeat(64), count: 1, from_id: 1, to_id: 2, format: "csv", truncated: false };
    expect(() => validateDetails(d)).not.toThrow();
    expect(JSON.stringify(d).length).toBeLessThan(4000);
  });
});

describe("sanitizeText", () => {
  it("removes control, bidi and invisible characters, collapses whitespace, caps length", () => {
    const bidi = String.fromCodePoint(0x202e);
    const zw = String.fromCodePoint(0x200b);
    expect(sanitizeText(`  incident\n4711\t${bidi}x${zw}y  `)).toBe("incident 4711 x y");
    expect(sanitizeText("a".repeat(600))).toBe("a".repeat(500));
    expect(sanitizeText("a".repeat(600), 10)).toBe("a".repeat(10));
    expect(sanitizeText(`a${String.fromCodePoint(0x1f600)}`)).toBe(`a${String.fromCodePoint(0x1f600)}`);
  });
  it("empty or non-text input is undefined", () => {
    for (const v of ["", "   ", "\n\t", undefined, null, 5, {}, String.fromCodePoint(0x200b)]) expect(sanitizeText(v)).toBeUndefined();
  });
});

describe("key ring", () => {
  it("first entry signs, all verify; bad rings refused", () => {
    const r = parseAuditKeys(`new:${keyB64(2)},old:${keyB64(1)}`);
    expect(r.currentId).toBe("new");
    expect([...r.keys.keys()]).toEqual(["new", "old"]);
    for (const bad of ["", "abc", `a b:${keyB64()}`, `a:${Buffer.alloc(31).toString("base64")}`, `a:${keyB64()},a:${keyB64()}`]) expect(() => parseAuditKeys(bad)).toThrow();
  });
});

describe("verifyChain: what it detects (T-26)", () => {
  const r = ring();
  const ok = (rows: AuditRow[], opts = {}) => verifyChain(rows, r, opts);

  it("a correct chain verifies, async iterables too", async () => {
    const rows = chain(20);
    const res = await ok(rows);
    expect(res).toMatchObject({ ok: true, checked: 20, lastId: 20, issues: [] });
    async function* gen() {
      yield* rows;
    }
    expect((await verifyChain(gen(), r)).ok).toBe(true);
  });

  it("an empty chain is fine", async () => expect(await ok([])).toMatchObject({ ok: true, checked: 0, lastId: 0, lastHash: GENESIS_HASH_HEX }));

  it.each([
    ["actor", (x: AuditRow) => (x.actorSub = "someone-else")],
    ["roles", (x: AuditRow) => (x.actorRoles = ["platform-admin"])],
    ["action", (x: AuditRow) => (x.action = "delete")],
    ["resource type", (x: AuditRow) => (x.resourceType = "other")],
    ["resource id", (x: AuditRow) => (x.resourceId = "other")],
    ["effect (deny rewritten to allow)", (x: AuditRow) => (x.effect = x.effect === "allow" ? "deny" : "allow")],
    ["reason", (x: AuditRow) => (x.reasonCode = "FORGED")],
    ["obligations", (x: AuditRow) => (x.obligations = [])],
    ["request id", (x: AuditRow) => (x.requestId = "req-99999999")],
    ["source", (x: AuditRow) => (x.source = "bff")],
    ["details", (x: AuditRow) => (x.details = { alert: false })],
    ["timestamp", (x: AuditRow) => (x.ts = new Date(x.ts.getTime() + 1))],
    ["stored hash", (x: AuditRow) => (x.hash = Buffer.alloc(32, 7))],
  ])("an edited %s is reported at that row", async (_n, edit) => {
    const rows = chain(10);
    edit(rows[4] as AuditRow);
    const res = await ok(rows);
    expect(res.ok).toBe(false);
    expect(res.firstBad).toMatchObject({ id: 5, code: "HASH" });
  });

  it("an edited row whose hash is recomputed WITHOUT the key is still caught (HMAC, not a plain hash)", async () => {
    const rows = chain(10);
    const x = rows[4] as AuditRow;
    x.effect = "deny";
    const { hash: _h, ...rest } = x;
    void _h;
    x.hash = createHash("sha256").update(canonicalBytes(rest)).digest(); // what a DB-only attacker can do
    expect((await ok(rows)).firstBad).toMatchObject({ id: 5, code: "HASH" });
  });

  it("an edited row re-signed with a DIFFERENT key is caught", async () => {
    const rows = chain(10);
    const forged = chain(10, randomRing());
    rows[4] = { ...(forged[4] as AuditRow), keyId: "k1" };
    expect((await ok(rows)).issues.some((i) => i.id === 5 && i.code === "HASH")).toBe(true);
  });

  it("a deleted middle row is a gap, reported at the row after it", async () => {
    const rows = chain(10);
    rows.splice(4, 1);
    const res = await ok(rows);
    expect(res.firstBad).toMatchObject({ id: 6, code: "GAP" });
    expect(res.issues.some((i) => i.code === "PREV_HASH" && i.id === 6)).toBe(true);
  });

  it("a deleted first row", async () => {
    const rows = chain(5);
    rows.shift();
    expect((await ok(rows)).firstBad).toMatchObject({ id: 2, code: "GAP" });
  });

  it("reordered rows", async () => {
    const rows = chain(6);
    [rows[2], rows[3]] = [rows[3] as AuditRow, rows[2] as AuditRow];
    const res = await ok(rows);
    expect(res.ok).toBe(false);
    expect(res.issues.some((i) => i.code === "REORDER" || i.code === "GAP")).toBe(true);
  });

  it("a forked or duplicated id", async () => {
    const rows = chain(5);
    const dup = clone(rows[2] as AuditRow);
    dup.requestId = "req-77777777";
    rows.splice(3, 0, dup);
    expect((await ok(rows)).issues.some((i) => i.code === "FORK")).toBe(true);
  });

  it("an unknown key id and a swapped key id", async () => {
    const rows = chain(4);
    (rows[1] as AuditRow).keyId = "ghost";
    expect((await ok(rows)).issues.some((i) => i.code === "KEY_UNKNOWN" && i.id === 2)).toBe(true);
    const two = parseAuditKeys(`k1:${keyB64(1)},k2:${keyB64(2)}`);
    const rows2 = chain(4, two);
    (rows2[1] as AuditRow).keyId = "k2"; // claims another key: its hash was made with k1
    expect((await verifyChain(rows2, two)).firstBad).toMatchObject({ id: 2, code: "HASH" });
  });

  it("rotation: rows signed with an old key still verify while it stays in the ring", async () => {
    const rows = chain(3, parseAuditKeys(`k1:${keyB64(1)}`));
    const rotated = parseAuditKeys(`k2:${keyB64(2)},k1:${keyB64(1)}`);
    expect((await verifyChain(rows, rotated)).ok).toBe(true);
    expect((await verifyChain(rows, parseAuditKeys(`k2:${keyB64(2)}`))).firstBad).toMatchObject({ code: "KEY_UNKNOWN" });
  });

  it("a malformed details object is reported even if the hash matches", async () => {
    const rows = chain(3);
    const x = rows[1] as AuditRow;
    x.details = { token: "x" };
    const { hash: _h, ...rest } = x;
    void _h;
    x.hash = createHmac("sha256", Buffer.alloc(32, 1)).update(canonicalBytes(rest)).digest();
    expect((await ok(rows)).issues.some((i) => i.code === "SCHEMA" && i.id === 2)).toBe(true);
  });

  it("head mismatch: tail deleted without touching the head, or head edited", async () => {
    const rows = chain(10);
    const last = rows[9] as AuditRow;
    expect((await ok(rows, { head: { lastId: 10, lastHash: last.hash } })).ok).toBe(true);
    expect((await ok(rows.slice(0, 7), { head: { lastId: 10, lastHash: last.hash } })).issues.some((i) => i.code === "HEAD_MISMATCH")).toBe(true);
    expect((await ok(rows, { head: { lastId: 10, lastHash: Buffer.alloc(32) } })).issues.some((i) => i.code === "HEAD_MISMATCH")).toBe(true);
  });

  it("tail truncation is caught by a checkpoint even when the head was rewritten to match", async () => {
    const rows = chain(10);
    const cp = makeCheckpoint({ lastId: 10, lastHash: (rows[9] as AuditRow).hash }, r, new Date(T0));
    const cut = rows.slice(0, 6);
    const head = { lastId: 6, lastHash: (cut[5] as AuditRow).hash }; // an attacker with write access fixes the head too
    const res = await ok(cut, { head, checkpoints: [cp] });
    expect(res.ok).toBe(false);
    expect(res.issues.some((i) => i.code === "TAIL_TRUNCATED" && i.id === 10)).toBe(true);
  });

  it("a checkpoint whose recorded hash differs from the row, a forged checkpoint, and a checkpoint for a missing row", async () => {
    const rows = chain(10);
    const good = makeCheckpoint({ lastId: 5, lastHash: (rows[4] as AuditRow).hash }, r);
    expect((await ok(rows, { checkpoints: [good] })).ok).toBe(true);
    const wrong = makeCheckpoint({ lastId: 5, lastHash: Buffer.alloc(32, 3) }, r);
    expect((await ok(rows, { checkpoints: [wrong] })).issues.some((i) => i.code === "CHECKPOINT_MISMATCH")).toBe(true);
    const forged = { ...good, mac: Buffer.alloc(32) };
    expect((await ok(rows, { checkpoints: [forged] })).issues.some((i) => i.code === "CHECKPOINT_MAC")).toBe(true);
    const otherKey = makeCheckpoint({ lastId: 5, lastHash: (rows[4] as AuditRow).hash }, randomRing());
    expect(verifyCheckpointMac(otherKey, r)).toBe(false);
    const withHole = rows.filter((x) => x.id !== 5);
    expect((await ok(withHole, { checkpoints: [good] })).issues.some((i) => i.code === "CHECKPOINT_MISMATCH" || i.code === "GAP")).toBe(true);
  });

  it("range verification from a trusted checkpoint row; head and tail checks apply to full runs only", async () => {
    const rows = chain(10);
    const start = { id: 4, hash: (rows[3] as AuditRow).hash };
    expect((await ok(rows.slice(4), { startAfter: start })).ok).toBe(true);
    expect((await ok(rows.slice(4), { startAfter: { id: 4, hash: Buffer.alloc(32) } })).firstBad).toMatchObject({ id: 5, code: "PREV_HASH" });
    const partial = await ok(rows, { toId: 6 });
    expect(partial).toMatchObject({ ok: true, checked: 6, lastId: 6 });
    const cp = makeCheckpoint({ lastId: 10, lastHash: (rows[9] as AuditRow).hash }, r);
    expect((await ok(rows, { toId: 6, checkpoints: [cp] })).ok).toBe(true); // a later checkpoint is not a truncation in a partial run
  });

  it("reports every issue, the earliest first", async () => {
    const rows = chain(10);
    (rows[7] as AuditRow).actorSub = "x";
    (rows[2] as AuditRow).actorSub = "y";
    const res = await ok(rows);
    expect(res.issues.map((i) => i.id)).toEqual([3, 8]);
    expect(res.firstBad?.id).toBe(3);
  });
});

describe("appendAudit against a fake database", () => {
  function fakeDb(head = { last_id: 0, last_hash: Buffer.from(GENESIS_HASH_HEX, "hex") }) {
    const calls: string[] = [];
    const inserted: unknown[][] = [];
    const db: Db = {
      async query(text, params) {
        calls.push(text.split(" ").slice(0, 3).join(" "));
        if (text.startsWith("SELECT last_id")) return { rows: [head] };
        if (text.startsWith("INSERT")) inserted.push(params ?? []);
        return { rows: [] };
      },
    };
    return { db, calls, inserted };
  }

  it("takes the chain lock first, reads the head, inserts the next signed row", async () => {
    const { db, calls, inserted } = fakeDb();
    const row = await appendAudit(db, entry(), ring(), new Date(T0));
    expect(calls).toEqual(["SELECT pg_advisory_xact_lock($1)", "SELECT last_id, last_hash", "INSERT INTO audit_log"]);
    expect(row.id).toBe(1);
    expect(inserted[0]?.[0]).toBe(1);
    expect(JSON.parse(inserted[0]?.[12] as string)).toEqual({ rule_ids: ["rbac.role-grants-action"] });
    expect((await verifyChain([row], ring())).ok).toBe(true);
  });

  it("continues from an existing head", async () => {
    const { db } = fakeDb({ last_id: 41, last_hash: Buffer.alloc(32, 5) });
    const row = await appendAudit(db, entry(), ring(), new Date(T0));
    expect(row.id).toBe(42);
    expect(row.prevHash).toEqual(Buffer.alloc(32, 5));
  });

  it("refuses an invalid entry before any insert, and a missing head", async () => {
    const { db, inserted } = fakeDb();
    await expect(appendAudit(db, entry({ actorSub: "a b" }), ring())).rejects.toThrow(/invalid audit entry/);
    expect(inserted).toHaveLength(0);
    const empty: Db = { query: async () => ({ rows: [] }) };
    await expect(appendAudit(empty, entry(), ring())).rejects.toThrow(/head missing/);
  });

  it("rowFromDb maps column names and types", () => {
    const row = chain(1)[0] as AuditRow;
    const db = { id: "1", ts: row.ts, actor_sub: row.actorSub, actor_roles: row.actorRoles, action: row.action, resource_type: row.resourceType, resource_id: row.resourceId, effect: row.effect, reason_code: row.reasonCode, obligations: row.obligations, request_id: row.requestId, source: row.source, details: row.details, prev_hash: row.prevHash, key_id: row.keyId, hash: row.hash };
    expect(rowFromDb(db)).toEqual(row);
    expect(rowFromDb({ ...db, resource_id: undefined }).resourceId).toBeNull();
  });
});

describe("CSV (T-12 for exports): formula injection is neutralised", () => {
  it.each([
    ["=1+1", "'=1+1"],
    ["+SUM(A1)", "'+SUM(A1)"],
    ["-2+3", "'-2+3"],
    ["@SUM(1)", "'@SUM(1)"],
    ["\t=cmd", "'\t=cmd"],
    ["\r=cmd", "\"'\r=cmd\""],
    ["  =HYPERLINK(\"http://evil\")", "\"'  =HYPERLINK(\"\"http://evil\"\")\""],
    ["=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0"],
    ["plain", "plain"],
    ["a,b", '"a,b"'],
    ['say "hi"', '"say ""hi"""'],
    ["line\nbreak", '"line\nbreak"'],
    ["x=1", "x=1"],
    ["", ""],
  ])("%j -> %j", (input, out) => expect(csvCell(input)).toBe(out));
  it("non-strings and arrays", () => {
    expect(csvCell(5)).toBe("5");
    expect(csvCell(null)).toBe("");
    expect(csvCell(undefined)).toBe("");
    expect(csvCell(["audit", "=alert"])).toBe("audit;=alert"); // not at the start of the cell
    expect(csvCell(["=a", "b"])).toBe("'=a;b");
    expect(csvLine(["a", "=b", 3])).toBe("a,'=b,3");
  });
});

describe("cursors are stable, tamper-evident and bound to the filters", () => {
  const r = ring();
  const fp = fingerprint({ actor: "u1", effect: undefined, action: "read" });
  it("round-trips", () => expect(openCursor(r, makeCursor(r, 123, fp), fp)).toBe(123));
  it("the fingerprint ignores undefined filters and key order", () => {
    expect(fingerprint({ a: "1", b: undefined })).toBe(fingerprint({ a: "1" }));
    expect(fingerprint({ a: "1", b: "2" })).toBe(fingerprint({ b: "2", a: "1" }));
    expect(fingerprint({ a: "1" })).not.toBe(fingerprint({ a: "2" }));
  });
  it.each([
    ["id changed", (c: string) => c.replace(".123.", ".124.")],
    ["id huge", (c: string) => c.replace(".123.", ".999999999.")],
    ["mac truncated", (c: string) => c.slice(0, -1)],
    ["mac flipped", (c: string) => c.slice(0, -1) + (c.endsWith("a") ? "b" : "a")],
    ["other key id", (c: string) => c.replace(/^k1\./, "k9.")],
    ["garbage", () => "../../etc/passwd"],
    ["empty", () => ""],
    ["negative", (c: string) => c.replace(".123.", ".-1.")],
  ])("tampering (%s) is refused", (_n, f) => expect(openCursor(r, f(makeCursor(r, 123, fp)), fp)).toBeUndefined());
  it("a cursor from one filter set does not open on another, nor with another key", () => {
    const c = makeCursor(r, 5, fp);
    expect(openCursor(r, c, fingerprint({ actor: "u2" }))).toBeUndefined();
    expect(openCursor(randomRing(), c, fp)).toBeUndefined();
    const two = parseAuditKeys(`k2:${keyB64(2)},k1:${keyB64(1)}`);
    expect(openCursor(two, c, fp)).toBe(5); // a rotated ring still opens cursors from the old key
  });
});
