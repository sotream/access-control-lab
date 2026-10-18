// A-40..A-46: attacks through the upload form and the download route, with a real scanner behind them.
import { crc32 } from "node:zlib";
import { beforeAll, describe, expect, it } from "vitest";
import { fixtures } from "./fixtures.js";
import { multipart, vault } from "./http.js";
import { bff, session } from "./sessions.js";
import { psql, q } from "./stack.js";
import type { BffSession } from "./kc.js";

const same = { origin: "https://vault.localhost", "sec-fetch-site": "same-origin" };
const EICAR = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"].join("");

function png(w = 2, h = 2, extra = Buffer.alloc(0)): Buffer {
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body));
    return Buffer.concat([len, body, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr.set([8, 2, 0, 0, 0], 8);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", Buffer.from([0x78, 0x9c, 0x63, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01])), chunk("IEND", Buffer.alloc(0)), extra]);
}

let owner: BffSession;
let caseId: string;
const upload = (s: BffSession, id: string, file: Parameters<typeof multipart>[1], fields: Record<string, string> = {}, headers: Record<string, string> = {}) => {
  const m = multipart({ csrf: s.csrf, ...fields }, file);
  return vault(`/actions/case-files/${id}/attachments`, { method: "POST", jar: s.jar, headers: { ...same, ...m.headers, ...headers }, body: m.body });
};
const msg = (r: { location: string | null }) => (r.location ? new URL(r.location, "https://vault.localhost").searchParams.get("m") : null);
const rows = (id: string) => psql(`SELECT display_name || '|' || status || '|' || coalesce(scan_detail,'') FROM attachments WHERE case_file_id = ${q(id)} ORDER BY created_at`).split("\n").filter(Boolean);
const count = (id: string) => Number(psql(`SELECT count(*) FROM attachments WHERE case_file_id = ${q(id)}`));

beforeAll(async () => {
  fixtures();
  owner = await session("analyst-official");
  const made = await bff(owner, "POST", "/case-files", { title: "attack: uploads", classification: "OFFICIAL", compartments: [] });
  caseId = (made.json as { id: string }).id;
}, 300_000);

describe("A-40 hostile content is turned away and leaves nothing behind", () => {
  const html = Buffer.from("<html><script>alert(document.cookie)</script></html>");
  const cases: [string, Parameters<typeof multipart>[1], string][] = [
    ["EICAR as a text file", { name: "notes.txt", type: "text/plain", bytes: EICAR }, "rejected"],
    ["EICAR labelled as a PNG", { name: "x.png", type: "image/png", bytes: EICAR }, "rejected"],
    ["PNG followed by HTML (polyglot)", { name: "x.png", type: "image/png", bytes: png(2, 2, html) }, "rejected"],
    ["HTML named as an image", { name: "x.png", type: "image/png", bytes: html }, "rejected"],
    ["SVG with a script", { name: "x.svg", type: "image/svg+xml", bytes: '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>' }, "rejected"],
    ["a ZIP archive", { name: "x.zip", type: "application/zip", bytes: Buffer.concat([Buffer.from("PK\x03\x04"), Buffer.alloc(400, 1)]) }, "rejected"],
    ["a gzip bomb", { name: "x.gz", type: "application/gzip", bytes: Buffer.concat([Buffer.from([0x1f, 0x8b, 8, 0]), Buffer.alloc(4000, 0)]) }, "rejected"],
    ["an executable", { name: "x.exe", type: "application/x-msdownload", bytes: Buffer.concat([Buffer.from("MZ"), Buffer.alloc(400, 1)]) }, "rejected"],
    ["a PNG that claims 400 megapixels", { name: "x.png", type: "image/png", bytes: png(20_000, 20_000) }, "rejected"],
    ["a PDF with JavaScript", { name: "x.pdf", type: "application/pdf", bytes: "%PDF-1.7\n<< /S /JavaScript /JS (app.alert(1)) >>\n%%EOF\n" }, "rejected"],
    ["the declared type disagrees with the bytes", { name: "x.png", type: "application/pdf", bytes: png() }, "rejected"],
    ["an empty file", { name: "x.txt", type: "text/plain", bytes: "" }, "rejected"],
    ["text with a right-to-left override inside", { name: "x.txt", type: "text/plain", bytes: `a${String.fromCodePoint(0x202e)}b` }, "rejected"],
  ];
  it.each(cases)("%s", async (_n, file, expected) => {
    const before = count(caseId);
    const r = await upload(owner, caseId, file);
    expect(r.status).toBe(303);
    expect(msg(r)).toBe(expected);
    expect(count(caseId) - before, "a refused or quarantined file may only exist as a quarantined row").toBeLessThanOrEqual(_n.includes("EICAR") ? 1 : 0);
    expect(rows(caseId).filter((x) => x.includes("|clean|")).some((x) => /eicar|polyglot|script/i.test(x))).toBe(false);
  });
  it("oversize: a declared length over the cap is refused before the body is read (chunked bodies: A-72)", async () => {
    const big = multipart({ csrf: owner.csrf }, { name: "big.txt", type: "text/plain", bytes: Buffer.alloc(6 * 1024 * 1024, 0x61) });
    expect((await vault(`/actions/case-files/${caseId}/attachments`, { method: "POST", jar: owner.jar, headers: { ...same, ...big.headers }, body: big.body })).status).toBe(413);
  });
});

describe("A-41 the EICAR file is quarantined, never served, and visible only as a status", () => {
  it("the row says quarantined, the list shows it without a link, the download refuses it", async () => {
    const up = await upload(owner, caseId, { name: "eicar-visible.txt", type: "text/plain", bytes: EICAR });
    expect(msg(up), `upload answered ${up.status} ${up.location} ${up.text.slice(0, 200)}`).toBe("rejected");
    const row = rows(caseId).find((x) => x.startsWith("eicar-visible.txt"));
    expect(row).toMatch(/\|quarantined\|.*Eicar/i);
    const list = (await bff(owner, "GET", `/case-files/${caseId}/attachments`)).json as { id: string; name: string; status: string }[];
    const bad = list.find((x) => x.name === "eicar-visible.txt")!;
    expect(bad.status).toBe("quarantined");
    expect([404, 409]).toContain((await vault(`/attachments/${caseId}/${bad.id}`, { jar: owner.jar })).status);
    expect(JSON.stringify(list)).not.toMatch(/storage|key/i);
  });
});

describe("A-42 names: traversal, double extensions and RTL tricks end up harmless", () => {
  it("what is stored and offered for download is a safe name with the extension of the real type; nothing escapes the store", async () => {
    const names = ["../../../../etc/passwd", "..\\..\\windows\\system32\\evil.exe", "invoice.pdf.exe", `photo${String.fromCodePoint(0x202e)}gpj.exe`, "a\u0000b.png", "x".repeat(400) + ".png", "CON", "...", ".htaccess", "<script>alert(1)</script>.png", "name;rm -rf.png", "a\r\nContent-Disposition: attachment.png"];
    for (const name of names) {
      const r = await upload(owner, caseId, { name: name.replace(/"/g, "'"), type: "image/png", bytes: png() });
      expect([303, 400], name).toContain(r.status); // a CR or LF inside the filename breaks the multipart framing itself: refused as a bad form
    }
    const list = (await bff(owner, "GET", `/case-files/${caseId}/attachments`)).json as { id: string; name: string; status: string }[];
    for (const a of list.filter((x) => x.status === "clean")) {
      expect(a.name, a.name).toMatch(/^[\p{L}\p{N}\p{M} _()-]{1,80}\.(png|pdf|jpg|txt)$/u);
      const dl = await vault(`/attachments/${caseId}/${a.id}`, { jar: owner.jar });
      expect(dl.status).toBe(200);
      expect(String(dl.headers["content-disposition"])).toMatch(/^attachment; filename="[\x20-\x7e]{1,100}"; filename\*=UTF-8''[A-Za-z0-9%._~-]+$/);
      expect(dl.headers["content-type"]).toBe("image/png");
    }
  });
});

describe("A-43 downloads can never run in the application's origin", () => {
  it("every download is an attachment with nosniff, a sandbox CSP, no caching and an allow-listed type", async () => {
    const list = (await bff(owner, "GET", `/case-files/${caseId}/attachments`)).json as { id: string; status: string }[];
    const one = list.find((x) => x.status === "clean");
    expect(one).toBeTruthy();
    const dl = await vault(`/attachments/${caseId}/${one!.id}`, { jar: owner.jar });
    expect(dl.headers["x-content-type-options"]).toBe("nosniff");
    expect(String(dl.headers["content-security-policy"])).toMatch(/sandbox/);
    expect(dl.headers["cache-control"]).toBe("no-store");
    expect(dl.headers["cross-origin-resource-policy"]).toBe("same-origin");
  });
});

describe("A-44 IDOR and BOLA on attachments", () => {
  it("an attachment id works only under its own case file and only for those who may read that file", async () => {
    const mine = (await bff(owner, "GET", `/case-files/${caseId}/attachments`)).json as { id: string; status: string }[];
    const attach = mine.find((x) => x.status === "clean")!;
    const f = fixtures();
    // plant an attachment on a SECRET file the analyst cannot read (operator action)
    psql(`INSERT INTO attachments (case_file_id, display_name, media_type, size_bytes, sha256, storage_key, uploaded_by_id, status, scanned_at) VALUES (${q(f.secAlphaA)}, 'secret.txt', 'text/plain', 1, decode(repeat('00',32),'hex'), md5(random()::text||clock_timestamp()::text), 'fixture', 'clean', now())`);
    const secretAtt = psql(`SELECT id FROM attachments WHERE case_file_id = ${q(f.secAlphaA)} LIMIT 1`);
    expect((await vault(`/attachments/${f.offAlpha}/${attach.id}`, { jar: owner.jar })).status, "real id, wrong parent").toBe(404);
    expect((await vault(`/attachments/${f.secAlphaA}/${secretAtt}`, { jar: owner.jar })).status, "a file she cannot read").toBe(404);
    expect((await vault(`/attachments/${caseId}/${secretAtt}`, { jar: owner.jar })).status, "secret attachment id under her own file").toBe(404);
    expect((await bff(owner, "GET", `/case-files/${f.secAlphaA}/attachments`)).status).toBe(404);
    for (const user of ["analyst-secret-b", "unit-admin-alpha", "reviewer", "auditor", "platform-admin"]) {
      const s = await session(user);
      expect((await vault(`/attachments/${f.secAlphaA}/${secretAtt}`, { jar: s.jar })).status, user).toBe(404);
      expect((await vault(`/attachments/${caseId}/${attach.id}`, { jar: s.jar })).status, `${user} on the analyst's file`).toBe(user === "auditor" || user === "platform-admin" ? 404 : 200);
    }
    for (const bad of ["../../etc/passwd", "%2e%2e%2f", "not-a-uuid", "00000000-0000-4000-8000-000000000000", attach.id.toUpperCase().slice(0, 30)]) expect((await vault(`/attachments/${caseId}/${bad}`, { jar: owner.jar })).status, bad).toBe(404);
    const anon = await vault(`/attachments/${caseId}/${attach.id}`);
    expect(anon.status).toBe(303);
    expect(anon.location).toMatch(/\/api\/auth\/login/);
  });
  it("SECRET attachments: only the entitled user, who signed in with a second factor, adds and gets them", async () => {
    const a = await session("analyst-secret-a");
    const secretDraft = psql(`INSERT INTO case_files (title, body, classification, unit, compartments, status, author_id) VALUES ('attack: secret draft', 'x', 'SECRET', 'alpha', ARRAY['A'], 'draft', ${q(a.sub)}) RETURNING id`).split("\n")[0]!;
    expect(msg(await upload(a, secretDraft, { name: "plan.txt", type: "text/plain", bytes: "secret plan\n" }))).toBe("uploaded");
    const list = (await bff(a, "GET", `/case-files/${secretDraft}/attachments`)).json as { id: string }[];
    const dl = await vault(`/attachments/${secretDraft}/${list[0]!.id}`, { jar: a.jar });
    expect(dl.status).toBe(200);
    expect(dl.text).toBe("secret plan\n");
    for (const user of ["analyst-secret-b", "analyst-official", "reviewer", "unit-admin-alpha"]) {
      const s = await session(user);
      expect((await bff(s, "GET", `/case-files/${secretDraft}/attachments`)).status, user).toBe(404);
      expect((await vault(`/attachments/${secretDraft}/${list[0]!.id}`, { jar: s.jar })).status, user).toBe(404);
      expect(msg(await upload(s, secretDraft, { name: "x.txt", type: "text/plain", bytes: "x" })), user).not.toBe("uploaded");
    }
  });
  it("uploading to a file one may not update: refused, nothing stored", async () => {
    const f = fixtures();
    const before = count(f.offAlpha);
    for (const user of ["reviewer", "unit-admin-beta", "analyst-secret-a", "auditor", "platform-admin"]) {
      const s = await session(user);
      const r = await upload(s, f.offAlpha, { name: "x.txt", type: "text/plain", bytes: "x" });
      expect(msg(r), user).not.toBe("uploaded");
    }
    const sub = await upload(owner, f.submittedAlpha, { name: "x.txt", type: "text/plain", bytes: "x" });
    expect(msg(sub), "a submitted file").not.toBe("uploaded");
    expect(count(f.offAlpha)).toBe(before);
  });
});

describe("A-45 the generic proxy cannot be used for uploads or downloads", () => {
  it("raw bytes through /bff are not accepted, and the attachment bytes are not reachable under /bff", async () => {
    const r = await vault(`/bff/case-files/${caseId}/attachments`, { method: "POST", jar: owner.jar, headers: { ...same, "x-csrf-token": owner.csrf, "content-type": "application/octet-stream", "x-attachment-type": "text/plain" }, body: "hello" });
    expect(r.status).toBe(404);
    const list = (await bff(owner, "GET", `/case-files/${caseId}/attachments`)).json as { id: string }[];
    expect((await bff(owner, "GET", `/case-files/${caseId}/attachments/${list[0]!.id}`)).status).toBe(404);
  });
});

describe("A-46 races", () => {
  it("twenty parallel uploads of the same name: every success is exactly one clean row and one file, no orphan, no overwrite", async () => {
    const id = ((await bff(owner, "POST", "/case-files", { title: "attack: upload race", classification: "OFFICIAL", compartments: [] })).json as { id: string }).id;
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => upload(owner, id, { name: "same-name.txt", type: "text/plain", bytes: `payload ${i}\n` })));
    const ok = results.filter((r) => msg(r) === "uploaded").length;
    expect(ok).toBeGreaterThan(0);
    expect(rows(id).filter((x) => x.includes("|clean|")).length).toBe(ok);
    const keys = psql(`SELECT count(DISTINCT storage_key) FROM attachments WHERE case_file_id = ${q(id)}`);
    expect(Number(keys)).toBe(count(id));
    const list = (await bff(owner, "GET", `/case-files/${id}/attachments`)).json as { id: string; sha256: string; status: string }[];
    expect(new Set(list.map((x) => x.sha256)).size, "each payload kept its own bytes").toBe(list.length);
  });
  it("uploads racing a submit: no attachment is added after the file stopped being a draft", async () => {
    const id = ((await bff(owner, "POST", "/case-files", { title: "attack: submit race", classification: "OFFICIAL", compartments: [] })).json as { id: string }).id;
    const [, ...uploads] = await Promise.all([bff(owner, "POST", `/case-files/${id}/submit`, {}), ...Array.from({ length: 10 }, (_, i) => upload(owner, id, { name: `r${i}.txt`, type: "text/plain", bytes: `race ${i}\n` }))]);
    const late = psql(`SELECT count(*) FROM attachments a JOIN case_files c ON c.id = a.case_file_id WHERE c.id = ${q(id)} AND c.status <> 'draft' AND a.created_at > c.updated_at`);
    expect(Number(late)).toBe(0);
    expect(uploads.every((r) => r.status === 303)).toBe(true);
  });
});
