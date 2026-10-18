import { describe, expect, it } from "vitest";
import { safeAcr, safeReturnTo } from "./redirect";

const ID = "0f1e2d3c-4b5a-4968-8776-655443322110";

describe("safeReturnTo (T-03: open redirect)", () => {
  it.each([
    ["/", "/"],
    ["/session", "/session"],
    ["/cases", "/cases"],
    ["/cases/new", "/cases/new"],
    [`/cases/${ID}`, `/cases/${ID}`],
    [`/cases/${ID}/break-glass`, `/cases/${ID}/break-glass`],
    ["/cases?x=1#frag", "/cases"], // query and fragment are dropped
    [`/cases/${ID}?m=done`, `/cases/${ID}`],
  ])("%s is kept as %s", (input, out) => expect(safeReturnTo(input)).toBe(out));

  it.each([
    "https://evil.example/",
    "http://evil.example",
    "//evil.example",
    "///evil.example",
    "/\\evil.example",
    "\\\\evil.example",
    "\\/evil.example",
    "/%2f%2fevil.example",
    "/%5cevil.example",
    "%2f%2fevil.example",
    "/%252f%252fevil.example",
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,<script>1</script>",
    "vbscript:x",
    "evil.example",
    "cases",
    "/\tcases",
    "/\ncases",
    "/\r\nLocation: https://evil.example",
    "/cases\u0000",
    "/ cases",
    "/cases/../../etc/passwd",
    "/cases/%2e%2e/%2e%2e/admin",
    "/api/auth/logout",
    "/bff/me",
    "/actions/case-files/create",
    "/cases/not-a-uuid",
    "/cases/" + ID + "/delete",
    "/@evil.example",
    "/cases@evil.example",
    "/%00",
    "/%",
    "/" + "a".repeat(300),
    "",
    "   ",
  ])("hostile or unknown %j falls back to /", (input) => expect(safeReturnTo(input)).toBe("/"));

  it.each([undefined, null, 5, {}, [], ["/cases"], true])("non-string %j falls back to /", (v) => expect(safeReturnTo(v)).toBe("/"));

  it("never returns a value that contains a scheme, host, query or fragment", () => {
    for (const i of ["/cases?next=https://evil.example", "/session#//evil.example", `/cases/${ID}?r=//evil`]) {
      const out = safeReturnTo(i);
      expect(out).not.toMatch(/[?#:]/);
      expect(out.startsWith("/")).toBe(true);
    }
  });
});

describe("safeAcr", () => {
  it("only mfa passes", () => {
    expect(safeAcr("mfa")).toBe("mfa");
    for (const v of ["pwd", "MFA", "mfa ", "mfa,pwd", "", undefined, null, 2, "0", "silver"]) expect(safeAcr(v)).toBeUndefined();
  });
});
