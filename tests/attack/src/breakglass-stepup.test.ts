// A-60..A-64: break-glass abuse and step-up bypass attempts.
import { describe, expect, it } from "vitest";
import { api, FORM, form, vault } from "./http.js";
import { fixtures } from "./fixtures.js";
import { claimsOf, oidcTokens, bffLogin } from "./kc.js";
import { bff, session } from "./sessions.js";
import { psql, q } from "./stack.js";

const same = { origin: "https://vault.localhost", "sec-fetch-site": "same-origin" };
const breakGlass = (s: Awaited<ReturnType<typeof session>>, id: string, justification: string) => vault(`/actions/case-files/${id}/break-glass`, { method: "POST", jar: s.jar, headers: { ...FORM, ...same }, body: form({ csrf: s.csrf, justification }) });
const auditRows = (resource: string) => Number(psql(`SELECT count(*) FROM audit_log WHERE resource_id = ${q(resource)} AND details ? 'alert'`));

describe("A-60 break-glass: who may use it, for what, and what it leaves behind", () => {
  it("a unit admin with a real justification reads a compartmented file she is cleared for; it is audited with an alert marker, the justification sanitised", async () => {
    const f = fixtures();
    const s = await session("unit-admin-alpha");
    expect((await bff(s, "GET", `/case-files/${f.confAlphaA}`)).status, "without break-glass").toBe(404);
    const before = auditRows(f.confAlphaA);
    const r = await breakGlass(s, f.confAlphaA, `incident 4711\u0007\u202e <b>x</b>\r\nforged: line`);
    expect([200, 303]).toContain(r.status);
    expect(auditRows(f.confAlphaA)).toBeGreaterThan(before);
    const stored = psql(`SELECT details->>'justification' FROM audit_log WHERE resource_id = ${q(f.confAlphaA)} AND details ? 'justification' ORDER BY id DESC LIMIT 1`);
    expect(stored).not.toMatch(/[\u0000-\u001f\u007f\u202e]/u);
    expect(stored).toContain("incident 4711");
  });
  it("empty, blank, control-only and huge justifications are refused or cut, never accepted as they are", async () => {
    const f = fixtures();
    const s = await session("unit-admin-alpha");
    const before = auditRows(f.confAlphaA);
    for (const j of ["", "   ", "\t\n", "\u0007\u0008", "\u202e\u200b"]) {
      const r = await breakGlass(s, f.confAlphaA, j);
      expect(r.text, `justification ${JSON.stringify(j)}`).not.toContain("fixture body");
      expect(auditRows(f.confAlphaA), `allow row for ${JSON.stringify(j)}`).toBe(before);
    }
    const huge = await breakGlass(s, f.confAlphaA, "x".repeat(100_000));
    expect(huge.status).toBeLessThan(500);
    const longest = Number(psql(`SELECT max(length(details->>'justification')) FROM audit_log WHERE details ? 'justification'`));
    expect(longest).toBeLessThanOrEqual(500);
  });
  it("everyone else gets nothing from it: analysts, auditors, platform admins, users below the floor (by design a unit admin of ANY unit may use it, with a justification)", async () => {
    const f = fixtures();
    for (const user of ["analyst-official", "reviewer", "auditor", "platform-admin", "analyst-secret-b"] as const) {
      const s = await session(user);
      const r = await breakGlass(s, f.confAlphaA, "incident 1");
      const body = r.text;
      if (user === "reviewer") continue; // the reviewer holds compartment A: this is an ordinary read for her
      expect(body, user).not.toContain("fixture body");
      expect([403, 404, 303, 200], user).toContain(r.status);
    }
  });
  it("break-glass never lowers the clearance floor: SECRET stays hidden from a unit admin, however it is asked", async () => {
    const f = fixtures();
    const s = await session("unit-admin-alpha");
    const r = await breakGlass(s, f.secAlphaA, "incident 99");
    expect(r.text).not.toContain("fixture body");
    expect((await bff(s, "GET", `/case-files/${f.secAlphaA}`, undefined, { "x-break-glass-justification": "incident 99" })).status, "the proxy never forwards the header").toBe(404);
  });
  it("the header is not an input of the generic proxy: sending it through /bff changes nothing", async () => {
    const f = fixtures();
    const s = await session("unit-admin-alpha");
    expect((await bff(s, "GET", `/case-files/${f.confAlphaA}`, undefined, { "x-break-glass-justification": "incident 1", "X-Break-Glass-Justification": "incident 2" })).status).toBe(404);
  });
  it("repeated use is not blocked, but every single use is a row with the real subject", async () => {
    const f = fixtures();
    const s = await session("unit-admin-alpha");
    const before = auditRows(f.confAlphaA);
    for (let i = 0; i < 5; i++) await breakGlass(s, f.confAlphaA, `repeat ${i}`);
    expect(auditRows(f.confAlphaA) - before).toBeGreaterThanOrEqual(5);
    const admins = [s.sub, (await session("unit-admin-beta")).sub, (await session("reviewer")).sub];
    expect(Number(psql(`SELECT count(*) FROM audit_log WHERE resource_id = ${q(f.confAlphaA)} AND details ? 'alert' AND actor_sub NOT IN (${admins.map(q).join(",")})`)), "only unit admins ever produce a break-glass row").toBe(0);
  });
});

describe("A-61 step-up cannot be skipped or downgraded", () => {
  it("a SECRET user who asks Keycloak for the weaker level gets a token of that level, and with it no SECRET data: a step-up challenge; the BFF never asks for it", async () => {
    const f = fixtures();
    const t = await oidcTokens("analyst-secret-a", { acr: "pwd" });
    expect(claimsOf(t.access_token).acr, "the acr she asked for").not.toBe("mfa");
    const r = await api(`/case-files/${f.secAlphaA}`, { headers: { authorization: `Bearer ${t.access_token}` } });
    expect(r.status).toBe(403);
    expect(String(r.headers["www-authenticate"])).toContain("insufficient_user_authentication");
    // the BFF only ever asks Keycloak for the stronger level: an acr=pwd in its login URL is ignored, so that session is a normal (strong) one
    const b = await bffLogin("analyst-secret-b", { acr: "pwd" });
    expect((await bff(b, "GET", `/case-files/${f.secAlphaB}`)).status).toBe(200);
  });
  it("a token with a tampered acr claim is refused, and a user without clearance cannot step up into SECRET data", async () => {
    const t = await oidcTokens("analyst-official");
    const forged = `${t.access_token.split(".")[0]}.${Buffer.from(JSON.stringify({ ...claimsOf(t.access_token), acr: "mfa", amr: ["pwd", "otp"], clearance: "SECRET", compartments: ["A"] })).toString("base64url")}.${t.access_token.split(".")[2]}`;
    expect((await api("/me", { headers: { authorization: `Bearer ${forged}` } })).status).toBe(401);
    const f = fixtures();
    expect((await api(`/case-files/${f.secAlphaA}`, { headers: { authorization: `Bearer ${t.access_token}` } })).status, "the genuine token of an OFFICIAL user").toBe(404);
  });
  it("step-up age: a session that stepped up once keeps SECRET access for its whole lifetime (documented risk AR-03, no freshness check)", async () => {
    const s = await session("analyst-secret-a");
    const f = fixtures();
    expect((await bff(s, "GET", `/case-files/${f.secAlphaA}`)).status).toBe(200);
  });
});
