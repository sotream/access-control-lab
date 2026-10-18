// Attachments through the BFF: upload form, listing, download. Real Next.js, real API, real database, real Keycloak (T-28..T-31, T-05, T-12).
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { makePdf, makePng } from "../../../apps/api/src/attachments/fixtures.js";
import { Browser, adminDb, csrfOf, startApi, startStubApi, startWeb, WEB, type Resp, type WebServer } from "./harness.js";

let web: WebServer;
let api: Awaited<ReturnType<typeof startApi>> | undefined;
const admin = adminDb();
let owner: Browser;
let csrf: string;
let caseId: string;

beforeAll(async () => {
  api = await startApi();
  web = await startWeb();
  owner = new Browser();
  await owner.login("analyst-official");
  csrf = csrfOf((await owner.req("/cases/new")).text);
  const created = await owner.post("/actions/case-files/create", { csrf, title: "attach here", body: "b", classification: "OFFICIAL", compartments: "" });
  caseId = /\/cases\/([0-9a-f-]{36})/.exec(created.location ?? "")![1]!;
}, 300_000);
afterAll(async () => {
  await web?.stop();
  await api?.stop();
  await admin.end();
});

/** a browser's multipart form post: same-origin headers, the token in the form, content-length set by fetch */
function form(browser: Browser, id: string, file: { bytes: Buffer; name: string; type: string } | undefined, o: { csrf?: string | null; headers?: Record<string, string> } = {}): Promise<Resp> {
  const fd = new FormData();
  if (o.csrf !== null) fd.set("csrf", o.csrf ?? csrf);
  if (file) fd.set("file", new Blob([new Uint8Array(file.bytes)], { type: file.type }), file.name);
  return browser.req(`/actions/case-files/${id}/attachments`, { method: "POST", headers: { origin: WEB, "sec-fetch-site": "same-origin", ...(o.headers ?? {}) }, body: fd as unknown as string });
}
const png = { bytes: makePng(4, 4), name: "diagram.png", type: "image/png" };
const count = async () => (await admin.query("SELECT count(*)::int AS n FROM attachments")).rows[0].n as number;
const msg = (r: Resp) => new URL(r.location ?? "http://x/", WEB).searchParams.get("m");

describe("upload form: refusals first", () => {
  it("no session: 401; no Origin, foreign Origin, cross-site metadata, missing or wrong token: 403; nothing stored", async () => {
    const before = await count();
    expect((await form(new Browser(), caseId, png)).status).toBe(401);
    expect((await form(owner, caseId, png, { headers: { origin: "" } })).status).toBe(403);
    expect((await form(owner, caseId, png, { headers: { origin: "https://evil.example", "sec-fetch-site": "cross-site" } })).status).toBe(403);
    expect((await form(owner, caseId, png, { headers: { "sec-fetch-site": "same-site" } })).status).toBe(403);
    expect((await form(owner, caseId, png, { csrf: null })).status).toBe(403);
    expect((await form(owner, caseId, png, { csrf: "x".repeat(43) })).status).toBe(403);
    const other = new Browser();
    await other.login("reviewer");
    expect((await form(owner, caseId, png, { csrf: csrfOf((await other.req("/cases/new")).text) })).status).toBe(403); // another user's token
    expect(await count()).toBe(before);
  });

  it("length rules: a chunked body is 411, a declared size over the cap is 413 before the body is read", async () => {
    const chunked = await fetch(`${WEB}/actions/case-files/${caseId}/attachments`, {
      method: "POST",
      redirect: "manual",
      headers: { cookie: owner.web.header(), origin: WEB, "content-type": "multipart/form-data; boundary=x", "sec-fetch-site": "same-origin" },
      body: new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode("--x--")); c.close(); } }),
      // @ts-expect-error undici needs duplex for a streamed request body
      duplex: "half",
    });
    expect(chunked.status).toBe(411);
    const big = await form(owner, caseId, { bytes: Buffer.alloc(6 * 1024 * 1024, 0x61), name: "big.txt", type: "text/plain" });
    expect(big.status).toBe(413);
    expect((await form(owner, caseId, undefined)).location).toContain("m=rejected"); // no file part at all
  });

  it("hostile content is turned away by the API and the page says so in fixed words", async () => {
    const before = await count();
    const html = Buffer.from("<html><script>alert(1)</script></html>");
    for (const [file, why] of [
      [{ bytes: makePdf(), name: "a.png", type: "image/png" }, "wrong magic"],
      [{ bytes: makePng(2, 2, html), name: "p.png", type: "image/png" }, "polyglot"],
      [{ bytes: Buffer.from("MZ" + "a".repeat(300)), name: "x.exe", type: "application/x-msdownload" }, "executable"],
      [{ bytes: Buffer.from('<svg onload="alert(1)"/>'), name: "x.svg", type: "image/svg+xml" }, "svg"],
    ] as const) {
      const r = await form(owner, caseId, file);
      expect(r.status, why).toBe(303);
      expect(msg(r), why).toBe("rejected");
    }
    expect(await count()).toBe(before);
  });

  it("the generic proxy cannot upload or download: not in the allow-list", async () => {
    const aid = "0f1e2d3c-4b5a-4968-8776-655443322110";
    expect((await owner.req(`/bff/case-files/${caseId}/attachments`, { method: "POST", headers: { origin: WEB, "x-csrf-token": csrf, "content-type": "application/octet-stream" }, body: "abc" })).status).toBe(404);
    expect((await owner.req(`/bff/case-files/${caseId}/attachments/${aid}`)).status).toBe(404);
  });
});

describe("a stored attachment: list, download, access", () => {
  let aid: string;
  it("upload succeeds, the page lists it, the proxy lists metadata only", async () => {
    const r = await form(owner, caseId, png);
    expect(r.status).toBe(303);
    expect(msg(r)).toBe("uploaded");
    const page = await owner.req(`/cases/${caseId}`);
    expect(page.text).toContain("diagram.png");
    aid = /href="\/attachments\/[0-9a-f-]{36}\/([0-9a-f-]{36})"/.exec(page.text)![1]!;
    const meta = await owner.req(`/bff/case-files/${caseId}/attachments`);
    expect(meta.status).toBe(200);
    const body = JSON.parse(meta.text) as Record<string, unknown>[];
    expect(body[0]).toMatchObject({ name: "diagram.png", status: "clean", mediaType: "image/png" });
    expect(JSON.stringify(body)).not.toContain("storage");
  });

  it("download: exact bytes, attachment, nosniff, sandbox, no caching, type from the allow-list", async () => {
    const res = await fetch(`${WEB}/attachments/${caseId}/${aid}`, { headers: { cookie: owner.web.header() }, redirect: "manual" });
    expect(res.status).toBe(200);
    expect(Buffer.from(await res.arrayBuffer()).equals(png.bytes)).toBe(true);
    expect(res.headers.get("content-type")).toBe("image/png");
    expect(res.headers.get("content-disposition")).toMatch(/^attachment; filename="diagram\.png"/);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("content-security-policy")).toContain("sandbox");
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("no session: sent to sign in, never the bytes; another user without access: 404; bad ids: 404; POST is not a thing", async () => {
    const anon = await fetch(`${WEB}/attachments/${caseId}/${aid}`, { redirect: "manual" });
    expect(anon.status).toBe(303);
    expect(anon.headers.get("location")).toContain("/api/auth/login");
    expect(Buffer.from(await anon.arrayBuffer()).length).toBe(0);
    const outsider = new Browser();
    await outsider.login("analyst-secret-b"); // different user; OFFICIAL file is readable, so use a file they cannot read below
    const hidden = await admin.query("INSERT INTO case_files (title, body, classification, unit, compartments, status, author_id, submitted_by_id) VALUES ('s','', 'SECRET', 'alpha', ARRAY['A'], 'approved', 'x', 'y') RETURNING id");
    const hid = hidden.rows[0].id as string;
    await admin.query("INSERT INTO attachments (case_file_id, display_name, media_type, size_bytes, sha256, storage_key, uploaded_by_id, status, scanned_at) VALUES ($1,'s.txt','text/plain',1,decode(repeat('00',32),'hex'),repeat('f',32),'x','clean',now())", [hid]);
    const hidAttachment = (await admin.query("SELECT id FROM attachments WHERE case_file_id = $1", [hid])).rows[0].id as string;
    expect((await outsider.req(`/attachments/${hid}/${hidAttachment}`)).status).toBe(404);
    for (const p of [`/attachments/not-a-uuid/${aid}`, `/attachments/${caseId}/not-a-uuid`, `/attachments/${caseId}/..%2f..%2fetc%2fpasswd`]) expect((await owner.req(p)).status, p).toBe(404);
    expect((await owner.req(`/attachments/${caseId}/${aid}`, { method: "POST", headers: { origin: WEB } })).status).toBe(405);
    expect((await owner.req(`/bff/case-files/${caseId}/attachments/${aid}`)).status).toBe(404); // a REAL attachment id is still not reachable through the generic proxy
    const bigForm = await owner.req("/actions/case-files/create", { method: "POST", headers: { origin: WEB, "sec-fetch-site": "same-origin", "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf, title: "x", body: "a".repeat(300 * 1024) }) });
    expect(bigForm.status).toBe(413); // ordinary forms are bounded before they are read
    await admin.query("DELETE FROM attachments WHERE case_file_id = $1", [hid]);
    await admin.query("DELETE FROM case_files WHERE id = $1", [hid]);
  });
});

describe("the download route does not trust the API's headers", () => {
  it("a type outside the allow-list is refused; an odd disposition is replaced", async () => {
    await api?.stop();
    api = undefined;
    const seenTypes: Record<string, string>[] = [
      { "content-type": "text/html", "content-disposition": "inline" },
      { "content-type": "image/png", "content-disposition": "inline; filename=evil.html" },
      { "content-type": "image/svg+xml", "content-disposition": 'attachment; filename="a.svg"; filename*=UTF-8\'\'a.svg' },
    ];
    let n = 0;
    const stub = await startStubApi(() => ({ status: 200, headers: seenTypes[n++ % 3]!, body: "<script>alert(1)</script>" }));
    try {
      const aid2 = "0f1e2d3c-4b5a-4968-8776-655443322111";
      const get = () => fetch(`${WEB}/attachments/${caseId}/${aid2}`, { headers: { cookie: owner.web.header() }, redirect: "manual" });
      const html = await get();
      expect(html.status).toBe(502); // text/html is not an attachment type
      const inline = await get();
      expect(inline.status).toBe(200);
      expect(inline.headers.get("content-disposition")).toBe('attachment; filename="download"'); // "inline" never passes
      expect(inline.headers.get("content-type")).toBe("image/png");
      expect((await get()).status).toBe(502); // svg is not allowed either
    } finally {
      await stub.stop();
    }
  });
});
