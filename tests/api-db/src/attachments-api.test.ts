// Attachments end to end with real Keycloak tokens, a real database and a real directory (T-28..T-31, T-44).
// Negative first: hostile files and names, the other users' files, SECRET without step-up, a scanner that fails, an audit that fails.
import { parseZoneKeys, signZone } from "@acl/netguard";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rowFromDb, type AuditRow } from "@acl/audit";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../../../apps/api/src/app.js";
import { loadConfig } from "../../../apps/api/src/config.js";
import { SCANNER, type Scanner, type ScanVerdict } from "../../../apps/api/src/attachments/scanner.js";
import { makeJpeg, makePdf, makePng, makeText } from "../../../apps/api/src/attachments/fixtures.js";
import { JsonLogger } from "../../../apps/api/src/http/logger.js";
import { decode, login, REALM_URL, type Tokens } from "../../identity/src/kc.js";
import { adminPool, appUrl, auditPool, clearRows, insertRow, migratorPool, resetAudit } from "./db.js";

const admin = adminPool();
const aud = auditPool();
const dir = mkdtempSync(join(tmpdir(), "acl-attachments-"));
const tokens = new Map<string, Tokens>();
const logs: string[] = [];
let url = "";
let close: () => Promise<void>;

/** the scanner of the running app; tests switch its answer */
let verdict: () => Promise<ScanVerdict> = async () => ({ verdict: "clean" });
const scanner: Scanner = { scan: () => verdict() };
const clean = async (): Promise<ScanVerdict> => ({ verdict: "clean" });

const subOf = (t: string) => JSON.parse(Buffer.from(t.split(".")[1]!, "base64url").toString()).sub as string;
const zone = (t: string) => ({ "x-acl-zone": signZone(parseZoneKeys(process.env.ZONE_SIGNING_KEYS!), "managed", subOf(t), Math.floor(Date.now() / 1000)) });
const sub = (u: string) => decode(tokens.get(u)!.access_token).claims.sub as string;

type Who = string; // key in `tokens`
async function api(who: Who, method: string, path: string, init: { body?: BodyInit; headers?: Record<string, string> } = {}) {
  const t = tokens.get(who)!.access_token;
  const res = await fetch(`${url}${path}`, { method, headers: { authorization: `Bearer ${t}`, ...zone(t), ...(init.headers ?? {}) }, body: init.body });
  const buf = Buffer.from(await res.arrayBuffer());
  return { status: res.status, headers: res.headers, buf, text: buf.toString("utf8"), json: (() => { try { return JSON.parse(buf.toString("utf8")); } catch { return undefined; } })() };
}
const json = (who: Who, method: string, path: string, body?: unknown) => api(who, method, path, body === undefined ? {} : { body: JSON.stringify(body), headers: { "content-type": "application/json" } });

interface Up { type?: string | null; name?: string; contentType?: string }
const upload = (who: Who, caseId: string, bytes: Buffer, o: Up = {}) =>
  api(who, "POST", `/case-files/${caseId}/attachments`, {
    body: new Uint8Array(bytes),
    headers: { "content-type": o.contentType ?? "application/octet-stream", ...(o.type === null ? {} : { "x-attachment-type": o.type ?? "image/png" }), ...(o.name === undefined ? {} : { "x-attachment-name": encodeURIComponent(o.name) }) },
  });

const rows = async (): Promise<AuditRow[]> => (await aud.query("SELECT * FROM audit_log ORDER BY id")).rows.map(rowFromDb);
const attachmentRows = async () => (await admin.query("SELECT * FROM attachments ORDER BY created_at")).rows;
const filesIn = (area: "quarantine" | "files") => { try { return readdirSync(join(dir, area)); } catch { return []; } };
const allFiles = () => [...filesIn("quarantine"), ...filesIn("files")];
const sha = (b: Buffer) => createHash("sha256").update(b).digest("hex");

let draft: string; // analyst-official's own OFFICIAL draft
let other: string; // someone else's OFFICIAL draft in unit alpha
let beta: string; // OFFICIAL draft in unit beta
let submitted: string;
let secret: string; // SECRET draft of analyst-secret-a, compartment A

beforeAll(async () => {
  await clearRows(admin);
  await resetAudit(admin);
  const cfg = loadConfig({ KEYCLOAK_ISSUER: REALM_URL, DATABASE_URL: appUrl(), AUDIT_HMAC_KEYS: process.env.AUDIT_HMAC_KEYS!, ZONE_SIGNING_KEYS: process.env.ZONE_SIGNING_KEYS!, THROTTLE_LIMIT: "100000", AUTH_FAIL_LIMIT: "10000", AUDIT_CHECKPOINT_SECONDS: "0", ATTACHMENT_DIR: dir });
  const app = await createApp(cfg, { logger: new JsonLogger((l) => logs.push(l)), clock: () => Date.UTC(2026, 9, 17, 12, 0, 0), extraProviders: [{ provide: SCANNER, useValue: scanner }] });
  await app.listen(0, "127.0.0.1");
  url = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}`;
  close = () => app.close();
  for (const u of ["analyst-official", "unit-admin-alpha", "unit-admin-beta", "reviewer", "analyst-secret-a", "analyst-secret-b", "auditor"]) tokens.set(u, await login(u));
  tokens.set("secret-a-pwd", await login("analyst-secret-a", { acrValues: "pwd" }));
  draft = ((await json("analyst-official", "POST", "/case-files", { title: "mine", classification: "OFFICIAL", compartments: [] })).json as { id: string }).id;
  other = await insertRow(admin, { classification: "OFFICIAL", unit: "alpha", status: "draft", authorId: "someone-else" });
  beta = await insertRow(admin, { classification: "OFFICIAL", unit: "beta", status: "draft", authorId: "someone-else" });
  submitted = await insertRow(admin, { classification: "OFFICIAL", unit: "alpha", status: "submitted", authorId: sub("analyst-official"), submittedById: sub("analyst-official") });
  secret = await insertRow(admin, { classification: "SECRET", unit: "alpha", compartments: ["A"], status: "draft", authorId: sub("analyst-secret-a") });
}, 400_000);
afterAll(async () => {
  await close?.();
  await clearRows(admin);
  await resetAudit(admin);
  await admin.end();
  await aud.end();
});

const nothingStored = async (before: number) => {
  expect((await attachmentRows()).length).toBe(before);
  expect(allFiles()).toHaveLength(before);
};

describe("hostile files are refused before anything is stored (T-28, T-29)", () => {
  const html = Buffer.from("<html><script>alert(document.cookie)</script></html>");
  const cases: [string, Buffer, Up, number, string][] = [
    ["wrong magic: a PDF declared as PNG", makePdf(), { type: "image/png" }, 415, "MEDIA_MISMATCH"],
    ["wrong magic: text declared as PDF", makeText(), { type: "application/pdf" }, 415, "MEDIA_MISMATCH"],
    ["no declared type", makePng(), { type: null }, 415, "MEDIA_MISMATCH"],
    ["polyglot: PNG followed by HTML", makePng(2, 2, html), {}, 422, "MALFORMED"],
    ["polyglot: JPEG with script inside", Buffer.concat([makeJpeg().subarray(0, -2), html, Buffer.from([0xff, 0xd9])]), { type: "image/jpeg" }, 422, "ACTIVE_CONTENT"],
    ["SVG", Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'), { type: "image/svg+xml" }, 422, "ACTIVE_CONTENT"],
    ["HTML", Buffer.from("<!doctype html><title>x</title>"), { type: "text/html" }, 422, "ACTIVE_CONTENT"],
    ["executable", Buffer.concat([Buffer.from("MZ"), Buffer.alloc(300, 1)]), { type: "application/octet-stream" }, 415, "UNSUPPORTED_TYPE"],
    ["zip archive (also office files)", Buffer.concat([Buffer.from("PK\x03\x04"), Buffer.alloc(300, 2)]), { type: "application/zip" }, 415, "UNSUPPORTED_TYPE"],
    ["gzip bomb", Buffer.concat([Buffer.from([0x1f, 0x8b, 8, 0]), Buffer.alloc(2000, 0)]), { type: "application/gzip" }, 415, "UNSUPPORTED_TYPE"],
    ["PNG decompression bomb by dimensions", makePng(20_000, 20_000), {}, 422, "MALFORMED"],
    ["PDF with JavaScript", makePdf("<< /S /JavaScript /JS (app.alert(1)) >>"), { type: "application/pdf" }, 422, "ACTIVE_CONTENT"],
    ["text with a bidi override", makeText(`a${String.fromCodePoint(0x202e)}b`), { type: "text/plain" }, 415, "UNSUPPORTED_TYPE"],
    ["empty file", Buffer.alloc(0), { type: "text/plain" }, 422, "EMPTY"],
    ["oversized file", Buffer.alloc(5 * 1024 * 1024 + 1, 0x61), { type: "text/plain" }, 413, "TOO_LARGE"],
  ];
  it.each(cases)("%s", async (_n, bytes, o, status, code) => {
    await resetAudit(admin);
    const before = (await attachmentRows()).length;
    const r = await upload("analyst-official", draft, bytes, o);
    // the body-parser limit may answer an oversized body itself (413) before the handler runs: no row is expected for that one
    expect(r.status).toBe(status);
    expect(r.text).not.toContain("alert(");
    await nothingStored(before);
    if (code !== "TOO_LARGE") {
      const rej = (await rows()).find((x) => x.action === "attachment.rejected");
      expect(rej, "a refusal is audited").toMatchObject({ effect: "deny", reasonCode: code, actorSub: sub("analyst-official") });
    }
  });

  it("wrong request shapes: JSON, multipart, form and a missing body are not accepted as an upload", async () => {
    const before = (await attachmentRows()).length;
    for (const [body, ct] of [[JSON.stringify({ a: 1 }), "application/json"], ["--x\r\ncontent-disposition: form-data; name=f\r\n\r\nabc\r\n--x--", "multipart/form-data; boundary=x"], ["a=b", "application/x-www-form-urlencoded"]] as const) {
      expect((await upload("analyst-official", draft, Buffer.from(body), { contentType: ct })).status).toBe(415);
    }
    expect((await api("analyst-official", "POST", `/case-files/${draft}/attachments`, { headers: { "content-type": "application/octet-stream", "x-attachment-type": "text/plain" } })).status).toBe(422); // empty
    await nothingStored(before);
  });

  it("file names: path traversal, double extension, RTL tricks and control characters end up as a harmless display name; no file leaves the storage directory", async () => {
    const names: [string, string][] = [
      ["../../../../etc/passwd", "passwd.png"],
      ["..\\..\\windows\\evil.exe", "evil.png"],
      ["invoice.pdf.exe", "invoice_pdf.png"],
      [`photo${String.fromCodePoint(0x202e)}gpj.exe`, "photo_gpj.png"],
      ["name\u0000with\nnul.png", "name_with_nul.png"],
      ["", "attachment.png"],
    ];
    const before = (await attachmentRows()).length;
    for (const [raw, shown] of names) {
      const r = await upload("analyst-official", draft, makePng(), { name: raw });
      expect(r.status, raw).toBe(201);
      expect(r.json.name).toBe(shown);
    }
    const stored = await attachmentRows();
    expect(stored.length).toBe(before + names.length);
    for (const row of stored.slice(before)) expect(row.storage_key).toMatch(/^[0-9a-f]{32}$/); // random key, unrelated to the name
    expect(allFiles().every((f) => /^[0-9a-f]{32}$/.test(f))).toBe(true);
    expect(readdirSync(dir).sort()).toEqual(["files", "quarantine"]); // nothing escaped upwards or sideways
    expect(readdirSync(tmpdir()).includes("passwd.png")).toBe(false);
  });
});

describe("who may add and see attachments: the parent's rules (T-30)", () => {
  it("upload needs the right to update the parent: not a reviewer, not another analyst's file, not another unit, not a submitted file", async () => {
    const before = (await attachmentRows()).length;
    await resetAudit(admin);
    const rev = await upload("reviewer", draft, makePng());
    expect(rev.status).toBe(403);
    // the ROUTE GUARD refused it as an update (not a service-level surprise after a read was allowed)
    const guardRow = (await rows()).find((x) => x.requestId === rev.headers.get("x-request-id"));
    expect(guardRow).toMatchObject({ action: "update", effect: "deny" });
    expect((await upload("analyst-official", other, makePng())).status).toBe(403); // analysts update only their own files
    expect((await upload("unit-admin-beta", draft, makePng())).status).toBe(403); // other unit
    expect((await upload("analyst-official", submitted, makePng())).status).toBe(403); // not a draft any more
    expect((await upload("auditor", draft, makePng())).status).toBe(404); // no read right on case files: the file does not exist for this role (ADR-9)
    expect((await upload("analyst-official", "00000000-0000-4000-8000-0000000000aa", makePng())).status).toBe(404);
    expect((await upload("analyst-official", "not-a-uuid", makePng())).status).toBe(404);
    expect(((await attachmentRows()).length)).toBe(before);
  });

  it("a unit admin may attach to a draft of their own unit", async () => {
    const r = await upload("unit-admin-alpha", other, makePdf(), { type: "application/pdf", name: "scan.pdf" });
    expect(r.status).toBe(201);
    expect(r.json).toMatchObject({ name: "scan.pdf", mediaType: "application/pdf", status: "clean", uploadedBy: sub("unit-admin-alpha") });
  });

  it("IDOR: an attachment id only works under its own case file; everything else is 404, the same as nothing", async () => {
    const mine = (await upload("analyst-official", draft, makePng(), { name: "mine.png" })).json.id as string;
    const theirs = (await upload("unit-admin-alpha", other, makePdf(), { type: "application/pdf" })).json.id as string;
    expect((await api("analyst-official", "GET", `/case-files/${draft}/attachments/${mine}`)).status).toBe(200);
    expect((await api("analyst-official", "GET", `/case-files/${draft}/attachments/${theirs}`)).status).toBe(404); // real id, wrong parent
    expect((await api("analyst-official", "GET", `/case-files/${other}/attachments/${mine}`)).status).toBe(404);
    for (const id of ["00000000-0000-4000-8000-0000000000bb", "not-a-uuid", "..%2f..%2fetc%2fpasswd", mine.toUpperCase().slice(0, 30)]) {
      expect((await api("analyst-official", "GET", `/case-files/${draft}/attachments/${id}`)).status, id).toBe(404);
    }
    // a user who cannot see the parent gets the case file's own answer: 404
    expect((await api("analyst-secret-a", "GET", `/case-files/${beta}/attachments/${theirs}`)).status).toBe(404);
  });

  it("SECRET: no step-up gives the challenge, a user outside the compartment or below the clearance gets 404, with MFA it works", async () => {
    const mfa = await upload("analyst-secret-a", secret, makePdf(), { type: "application/pdf", name: "secret.pdf" });
    expect(mfa.status).toBe(201);
    const id = mfa.json.id as string;
    const pwd = await api("secret-a-pwd", "GET", `/case-files/${secret}/attachments/${id}`);
    expect(pwd.status).toBe(403);
    expect(pwd.headers.get("www-authenticate") ?? "").toContain("insufficient_user_authentication");
    expect((await api("secret-a-pwd", "GET", `/case-files/${secret}/attachments`)).status).toBe(403);
    expect((await upload("secret-a-pwd", secret, makePdf(), { type: "application/pdf" })).status).toBe(403);
    for (const who of ["analyst-official", "analyst-secret-b", "unit-admin-alpha"]) {
      expect((await api(who, "GET", `/case-files/${secret}/attachments/${id}`)).status, who).toBe(404);
      expect((await api(who, "GET", `/case-files/${secret}/attachments`)).status, who).toBe(404);
      expect((await upload(who, secret, makePdf(), { type: "application/pdf" })).status, who).toBe(404);
    }
    const ok = await api("analyst-secret-a", "GET", `/case-files/${secret}/attachments/${id}`);
    expect(ok.status).toBe(200);
    expect(ok.buf.equals(makePdf())).toBe(true);
    // the denied attempts left no bytes in the response
    expect(pwd.buf.length).toBeLessThan(400);
  });

  it("the case-file list and the case file itself never carry attachment data; the auditor cannot reach attachments at all", async () => {
    const list = await json("analyst-official", "GET", "/case-files");
    expect(JSON.stringify(list.json)).not.toMatch(/storage|sha256|attachments/);
    expect((await api("auditor", "GET", `/case-files/${draft}/attachments`)).status).toBe(404);
  });

  it("a draft with attachments cannot be deleted (409) and nothing is lost; one without can", async () => {
    const withFile = ((await json("analyst-official", "POST", "/case-files", { title: "x", classification: "OFFICIAL", compartments: [] })).json as { id: string }).id;
    await upload("analyst-official", withFile, makePng());
    const before = (await attachmentRows()).length;
    expect((await json("analyst-official", "DELETE", `/case-files/${withFile}`)).status).toBe(409);
    expect((await attachmentRows()).length).toBe(before);
    expect((await json("analyst-official", "GET", `/case-files/${withFile}`)).status).toBe(200);
    const bare = ((await json("analyst-official", "POST", "/case-files", { title: "y", classification: "OFFICIAL", compartments: [] })).json as { id: string }).id;
    expect((await json("analyst-official", "DELETE", `/case-files/${bare}`)).status).toBe(200);
  });
});

describe("download: only clean files, only as an attachment (T-31)", () => {
  it("serves the exact bytes with attachment disposition, nosniff, a sandbox CSP and no caching; the stored hash is the file's hash", async () => {
    const bytes = makePng(3, 3);
    const up = await upload("analyst-official", draft, bytes, { name: "звіт (1).png" });
    expect(up.status).toBe(201);
    expect(up.json).toMatchObject({ name: "звіт (1).png", mediaType: "image/png", size: bytes.length, sha256: sha(bytes), status: "clean" });
    const d = await api("analyst-official", "GET", `/case-files/${draft}/attachments/${up.json.id}`);
    expect(d.status).toBe(200);
    expect(d.buf.equals(bytes)).toBe(true);
    expect(d.headers.get("content-type")).toBe("image/png");
    expect(d.headers.get("content-disposition")).toBe(`attachment; filename="____ (1).png"; filename*=UTF-8''%D0%B7%D0%B2%D1%96%D1%82%20%281%29.png`);
    expect(d.headers.get("x-content-type-options")).toBe("nosniff");
    expect(d.headers.get("content-security-policy")).toContain("sandbox");
    expect(d.headers.get("cache-control")).toBe("no-store");
    const row = (await attachmentRows()).find((r) => r.id === up.json.id)!;
    expect(row.sha256.toString("hex")).toBe(sha(bytes));
    expect(statSync(join(dir, "files", row.storage_key)).mode & 0o777).toBe(0o600);
    expect(statSync(join(dir, "files")).mode & 0o777).toBe(0o700);
  });

  it("a stored file changed on disk is not served (hash checked on the way out)", async () => {
    const up = await upload("analyst-official", draft, makeText("original contents\n"), { type: "text/plain", name: "n.txt" });
    const row = (await attachmentRows()).find((r) => r.id === up.json.id)!;
    writeFileSync(join(dir, "files", row.storage_key), "tampered contents\n");
    const d = await api("analyst-official", "GET", `/case-files/${draft}/attachments/${up.json.id}`);
    expect(d.status).toBe(503);
    expect(d.text).not.toContain("tampered");
    expect(logs.some((l) => l.includes("attachment_hash_mismatch"))).toBe(true);
  });
});

describe("the scanner hook fails closed (T-28)", () => {
  it("infected: refused, kept in quarantine, status quarantined, never downloadable, audited", async () => {
    await resetAudit(admin);
    verdict = async () => ({ verdict: "infected", signature: "Eicar-Test-Signature" });
    try {
      const filesBefore = filesIn("files").length;
      const r = await upload("analyst-official", draft, makeText("X5O!P%@AP test file\n"), { type: "text/plain", name: "eicar.txt" });
      expect(r.status).toBe(422);
      const row = (await attachmentRows()).find((x) => x.display_name === "eicar.txt")!;
      expect(row).toMatchObject({ status: "quarantined", scan_detail: "Eicar-Test-Signature" });
      expect(filesIn("quarantine")).toContain(row.storage_key);
      expect(filesIn("files").length).toBe(filesBefore);
      const list = await api("analyst-official", "GET", `/case-files/${draft}/attachments`);
      expect((list.json as { name: string; status: string }[]).find((x) => x.name === "eicar.txt")?.status).toBe("quarantined");
      expect((await api("analyst-official", "GET", `/case-files/${draft}/attachments/${row.id}`)).status).toBe(409);
      const scan = (await rows()).find((x) => x.action === "attachment.scan");
      expect(scan).toMatchObject({ effect: "deny", reasonCode: "QUARANTINED", resourceId: row.id });
      expect(scan!.details).toMatchObject({ scan: "INFECTED", detail_code: "Eicar-Test-Signature" });
    } finally {
      verdict = clean;
    }
  });

  it("scanner down, slow or broken: 503, the file stays pending and is never served", async () => {
    verdict = async () => {
      throw new Error("scanner unreachable");
    };
    try {
      const r = await upload("analyst-official", draft, makeText("waiting for a scan\n"), { type: "text/plain", name: "pending.txt" });
      expect(r.status).toBe(503);
      const row = (await attachmentRows()).find((x) => x.display_name === "pending.txt")!;
      expect(row.status).toBe("pending");
      expect(filesIn("files")).not.toContain(row.storage_key);
      expect((await api("analyst-official", "GET", `/case-files/${draft}/attachments/${row.id}`)).status).toBe(409);
      const scan = (await rows()).filter((x) => x.action === "attachment.scan").at(-1)!;
      expect(scan).toMatchObject({ effect: "deny", reasonCode: "SCAN_UNAVAILABLE" });
    } finally {
      verdict = clean;
    }
  });
});

describe("the audit trail of attachments (T-24, T-31)", () => {
  it("upload, scan and download each leave a row with size, hash and type (no name, no content); failed audit blocks the action", async () => {
    await resetAudit(admin);
    const bytes = makeJpeg();
    const up = await upload("analyst-official", draft, bytes, { type: "image/jpeg", name: "private-name-4711.jpg" });
    const id = up.json.id as string;
    await api("analyst-official", "GET", `/case-files/${draft}/attachments/${id}`);
    const rs = (await rows()).filter((r) => r.action.startsWith("attachment."));
    expect(rs.map((r) => [r.action, r.effect, r.reasonCode])).toEqual([["attachment.upload", "allow", "UPLOADED"], ["attachment.scan", "allow", "CLEAN"], ["attachment.download", "allow", "DOWNLOADED"]]);
    expect(rs[0]!.details).toEqual({ size: bytes.length, sha256: sha(bytes), media: "jpeg" });
    expect(rs[2]).toMatchObject({ resourceType: "attachment", resourceId: id });
    expect(JSON.stringify(rs)).not.toContain("private-name-4711");

    // no audit row, no action: with the audit table closed to the API role the upload is refused and nothing is stored
    const before = (await attachmentRows()).length;
    const files = allFiles().length;
    await admin.query("REVOKE INSERT ON audit_log FROM casefile_app");
    try {
      expect((await upload("analyst-official", draft, makePng(5, 5))).status).toBe(503);
      expect((await api("analyst-official", "GET", `/case-files/${draft}/attachments/${id}`)).status).toBe(503); // the guard refuses first: allow without a row
    } finally {
      await admin.query("GRANT INSERT ON audit_log TO casefile_app");
    }
    expect((await attachmentRows()).length).toBe(before);
    expect(allFiles().length).toBe(files);
  });

  it("logs never carry file names or contents", () => {
    const dump = logs.join("\n");
    expect(dump).not.toContain("private-name-4711");
    expect(dump).not.toContain("tampered contents");
  });
});

describe("the database refuses what the API would never do (defence in depth)", () => {
  it("even the superuser cannot rewrite an attachment or a final verdict (trigger), and the owner sees no rows without a context (forced RLS)", async () => {
    const clean = (await attachmentRows()).find((r) => r.status === "clean")!;
    const codes = async (stmt: string, params: unknown[]) => admin.query(stmt, params).then(() => "ok", (e: { code?: string }) => e.code);
    expect(await codes("UPDATE attachments SET display_name = 'renamed.png' WHERE id = $1", [clean.id])).toBe("42501");
    expect(await codes("UPDATE attachments SET sha256 = decode(repeat('11', 32), 'hex') WHERE id = $1", [clean.id])).toBe("42501");
    expect(await codes("UPDATE attachments SET status = 'quarantined', scanned_at = now() WHERE id = $1", [clean.id])).toBe("42501"); // a clean verdict is final
    const owner = migratorPool();
    try {
      expect((await owner.query("SELECT count(*)::int AS n FROM attachments")).rows[0].n).toBe(0);
    } finally {
      await owner.end();
    }
  });

  it("the app role cannot delete, cannot change anything but the verdict, cannot flip a final verdict, cannot insert for another uploader", async () => {
    const { appPool, probe, ctxOf, subjectOf, envOf } = await import("./db.js");
    const pool = appPool(2);
    try {
      const me = subjectOf({ id: sub("analyst-official"), roles: ["analyst"], clearance: "OFFICIAL", unit: "alpha" });
      const target = (await attachmentRows()).find((r) => r.status === "clean")!;
      const attempt = async (stmt: string, params: unknown[]) =>
        probe(pool, ctxOf(me, envOf()), async (tx) => {
          try {
            return `rows:${(await tx.query(stmt as never, params)).rowCount}`;
          } catch (e) {
            return (e as { code?: string }).code ?? "error";
          }
        });
      expect(await attempt("DELETE FROM attachments WHERE id = $1", [target.id])).toBe("42501");
      expect(await attempt("UPDATE attachments SET display_name = 'x' WHERE id = $1", [target.id])).toBe("42501"); // column privilege
      expect(await attempt("UPDATE attachments SET storage_key = repeat('a', 32) WHERE id = $1", [target.id])).toBe("42501");
      expect(await attempt("UPDATE attachments SET status = 'quarantined', scanned_at = now() WHERE id = $1", [target.id])).toBe("rows:0"); // a clean verdict is final: the row is not even updatable
      expect(await attempt("INSERT INTO attachments (case_file_id, display_name, media_type, size_bytes, sha256, storage_key, uploaded_by_id) VALUES ($1, 'a.txt', 'text/plain', 1, decode(repeat('00', 32), 'hex'), repeat('b', 32), 'somebody-else')", [draft])).toBe("42501");
      expect(await attempt("INSERT INTO attachments (case_file_id, display_name, media_type, size_bytes, sha256, storage_key, uploaded_by_id, status, scanned_at) VALUES ($1, 'a.txt', 'text/plain', 1, decode(repeat('00', 32), 'hex'), repeat('c', 32), $2, 'clean', now())", [draft, me.id])).toBe("42501"); // born clean
      expect(await attempt("INSERT INTO attachments (case_file_id, display_name, media_type, size_bytes, sha256, storage_key, uploaded_by_id) VALUES ($1, 'a/b.txt', 'text/plain', 1, decode(repeat('00', 32), 'hex'), repeat('d', 32), $2)", [draft, me.id])).toBe("23514"); // slash in a name
      expect(await attempt("INSERT INTO attachments (case_file_id, display_name, media_type, size_bytes, sha256, storage_key, uploaded_by_id) VALUES ($1, 'a.svg', 'image/svg+xml', 1, decode(repeat('00', 32), 'hex'), repeat('e', 32), $2)", [draft, me.id])).toBe("23514"); // type outside the allow-list
      expect(await attempt("INSERT INTO attachments (case_file_id, display_name, media_type, size_bytes, sha256, storage_key, uploaded_by_id) VALUES ($1, 'a.txt', 'text/plain', 1, decode(repeat('00', 32), 'hex'), '../../etc/passwd', $2)", [draft, me.id])).toBe("23514"); // storage key shape
    } finally {
      await pool.end();
    }
  });
});
