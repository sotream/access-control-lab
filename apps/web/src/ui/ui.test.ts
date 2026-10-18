import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";
import { describe, expect, it } from "vitest";
import { applyQuery, hrefFor, parseQuery, type Row } from "./cases-query";
import { Badge, Banner, highest, ScanChip } from "./components";
import { ErrorView, errorStatus } from "./errors";
import { en, t } from "./i18n";
import { navFor } from "./nav";
import { noticeFor } from "./messages";

const row = (n: number, over: Partial<Row> = {}): Row => ({ id: `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`, title: `Case ${n}`, classification: "OFFICIAL", unit: "alpha", status: "draft", compartments: [], version: 1, ...over });

describe("navigation by role", () => {
  it.each([
    [["analyst"], ["/cases", "/cases/new"], ["/review", "/audit", "/break-glass"]],
    [["reviewer"], ["/review"], ["/cases/new", "/audit"]],
    [["unit-admin"], ["/cases", "/break-glass"], ["/audit", "/review"]],
    [["auditor"], ["/audit", "/audit/verify"], ["/cases", "/break-glass"]],
    [["platform-admin"], ["/session"], ["/cases", "/audit", "/review"]],
    [[], ["/session"], ["/cases", "/audit"]],
  ])("%j sees %j and not %j", (roles, yes, no) => {
    const hrefs = navFor(roles).map((i) => i.href);
    for (const h of yes) expect(hrefs).toContain(h);
    for (const h of no) expect(hrefs).not.toContain(h);
    expect(new Set(hrefs).size).toBe(hrefs.length);
  });
  it("unknown roles get nothing extra", () => expect(navFor(["root", "__proto__"]).map((i) => i.href)).toEqual(["/", "/session"]));
});

describe("case list query", () => {
  const rows = [row(1, { title: "Bravo", classification: "SECRET" }), row(2, { title: "alpha", status: "submitted" }), row(3, { title: "Charlie", unit: "beta", classification: "CONFIDENTIAL" })];
  it("ignores values outside the fixed lists and bounds the rest", () => {
    const q = parseQuery({ status: "x", cls: "TOP", sort: "__proto__", dir: "sideways", page: "-4", q: "a".repeat(500), unit: ["a"] });
    expect(q).toMatchObject({ status: "", level: "", sort: "title", dir: "asc", page: 1, unit: "" });
    expect(q.q).toHaveLength(100);
    expect(parseQuery({ page: "1e9" }).page).toBe(1);
  });
  it("sorts by title case-insensitively and by classification rank", () => {
    expect(applyQuery(rows, parseQuery({})).rows.map((r) => r.title)).toEqual(["alpha", "Bravo", "Charlie"]);
    expect(applyQuery(rows, parseQuery({ sort: "classification", dir: "desc" })).rows.map((r) => r.classification)).toEqual(["SECRET", "CONFIDENTIAL", "OFFICIAL"]);
  });
  it("filters by status, level, unit and text", () => {
    expect(applyQuery(rows, parseQuery({ status: "submitted" })).total).toBe(1);
    expect(applyQuery(rows, parseQuery({ cls: "SECRET" })).total).toBe(1);
    expect(applyQuery(rows, parseQuery({ unit: "beta" })).total).toBe(1);
    expect(applyQuery(rows, parseQuery({ q: "CHAR" })).total).toBe(1);
  });
  it("paginates and clamps the page", () => {
    const many = Array.from({ length: 60 }, (_, i) => row(i));
    const r = applyQuery(many, parseQuery({ page: "3" }));
    expect(r.pages).toBe(3);
    expect(r.rows).toHaveLength(10);
    expect(applyQuery(many, parseQuery({ page: "99" })).rows).toHaveLength(10);
  });
  it("builds short links without defaults and encodes values", () => {
    expect(hrefFor("/cases", parseQuery({}), {})).toBe("/cases");
    expect(hrefFor("/cases", parseQuery({ q: "a&b=c" }), { page: 2 })).toBe("/cases?q=a%26b%3Dc&page=2");
    expect(hrefFor("/review", { ...parseQuery({}), status: "submitted" }, {})).toBe("/review");
  });
});

describe("classification display", () => {
  it("highest picks the top level; an unknown value counts as SECRET", () => {
    expect(highest(["OFFICIAL", "CONFIDENTIAL"])).toBe("CONFIDENTIAL");
    expect(highest([])).toBeUndefined();
    expect(highest(["OFFICIAL", "TOP"])).toBe("SECRET");
  });
  it("badge and banner carry the level as text", () => {
    expect(renderToStaticMarkup(createElement(Badge, { level: "SECRET" }))).toContain(">SECRET<");
    const b = renderToStaticMarkup(createElement(Banner, { level: "CONFIDENTIAL" }));
    expect(b).toContain("CONFIDENTIAL");
    expect(b).toContain('role="note"');
  });
  it("a scan status is a word and a glyph, never only a colour", () => {
    for (const [s, w] of [["clean", "Clean"], ["pending", "Pending scan"], ["quarantined", "Quarantined"], ["weird", "Unknown"]]) expect(renderToStaticMarkup(createElement(ScanChip, { status: s! }))).toContain(w);
  });
  it("escapes markup in data (React escaping, no raw HTML)", () => {
    const html = renderToStaticMarkup(createElement(Badge, { level: '<img src=x onerror=alert(1)>' }));
    expect(html).not.toContain("<img");
  });
});

describe("error pages leak nothing", () => {
  it("maps any status to a fixed set; proxies' 502/504 are 503", () => {
    expect(errorStatus(502)).toBe(503);
    expect(errorStatus(418)).toBe(500);
    expect(errorStatus(404)).toBe(404);
  });
  it("403 and 404 read the same on the case-file path (ADR-9): the 404 text never says hidden vs missing", () => {
    expect(t.err.text[404]).toMatch(/does not exist, or you may not see it/);
    expect(renderToStaticMarkup(createElement(ErrorView, { status: 404 }))).not.toMatch(/forbidden|clearance|compartment/i);
  });
  it("429 and 503 give advice, not internals", () => {
    expect(renderToStaticMarkup(createElement(ErrorView, { status: 429 }))).toContain("Wait a moment");
    expect(renderToStaticMarkup(createElement(ErrorView, { status: 503 }))).toContain("Nothing was changed");
  });
});

describe("messages and dictionary", () => {
  it("only known codes become a notice; prototype keys and markup do not", () => {
    expect(noticeFor("done")?.tone).toBe("ok");
    expect(noticeFor("conflict")?.tone).toBe("warn");
    expect(noticeFor("forbidden")?.tone).toBe("danger");
    for (const c of ["__proto__", "constructor", "<b>", "ok", "problem", "", undefined]) expect(noticeFor(c)).toBeUndefined();
  });
  it("every dictionary string is plain text: no markup, no template placeholders", () => {
    const walk = (o: unknown, path: string): void => {
      if (typeof o === "string") expect(o, path).not.toMatch(/[<>{}]|\$\{/);
      else if (o && typeof o === "object") for (const [k, v] of Object.entries(o)) walk(v, `${path}.${k}`);
    };
    walk(en, "en");
  });
});
