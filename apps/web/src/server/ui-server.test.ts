import { describe, expect, it } from "vitest";
import { packJustification, unpackJustification } from "./break-glass";
import { meFromToken } from "./pages";
import { parseTheme } from "./theme";

const ID = "0f1e2d3c-4b5a-4968-8776-655443322110";
const OTHER = "1f1e2d3c-4b5a-4968-8776-655443322110";
const jwt = (claims: unknown) => `h.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.s`;
const good = { sub: ID, realm_access: { roles: ["analyst"] }, clearance: "SECRET", unit: "alpha", compartments: ["OPS"], acr: "mfa", amr: ["pwd", "otp"], auth_time: 1 };

describe("break-glass hand-over cookie", () => {
  it("round-trips any script, including umlauts and Cyrillic", () => {
    for (const j of ["incident 4711", "Störung im Rechenzentrum", "авария на узле", "line1\nline2"]) expect(unpackJustification(packJustification(ID, j), ID)).toBe(j.trim());
  });
  it("is bound to the case file it was made for", () => expect(unpackJustification(packJustification(ID, "incident 4711"), OTHER)).toBeUndefined());
  it.each([undefined, "", ID, `${ID}.`, `${ID}.!!!`, `${ID}.${"A".repeat(3001)}`, `${ID}.${Buffer.from("abcd").toString("base64url")}`, `${ID}.${Buffer.from("x".repeat(501)).toString("base64url")}`])("refuses %s", (v) => expect(unpackJustification(v, ID)).toBeUndefined());
  it("stays under the 4096-byte cookie limit for the longest allowed text (500 four-byte characters)", () => expect(packJustification(ID, "\u{1F600}".repeat(500)).length).toBeLessThan(4000));
});

describe("top bar data from the token (display only)", () => {
  it("reads the claims it shows", () => expect(meFromToken(jwt(good))).toMatchObject({ sub: ID, roles: ["analyst"], clearance: "SECRET", unit: "alpha", compartments: ["OPS"], acr: "mfa" }));
  it("drops values that are not plain tags, and refuses a token without subject or clearance", () => {
    expect(meFromToken(jwt({ ...good, realm_access: { roles: ["analyst", "<b>x</b>", 5] } }))?.roles).toEqual(["analyst"]);
    expect(meFromToken(jwt({ ...good, unit: "<script>" }))?.unit).toBe("?");
    expect(meFromToken(jwt({ ...good, sub: undefined }))).toBeUndefined();
    expect(meFromToken(jwt({ ...good, clearance: undefined }))).toBeUndefined();
    for (const t of ["", "x", "a.b", "a.!!.c", "a.bm90LWpzb24.c"]) expect(meFromToken(t)).toBeUndefined();
  });
});

describe("theme cookie", () => {
  it("only light and dark are kept", () => {
    expect(parseTheme("dark")).toBe("dark");
    expect(parseTheme("light")).toBe("light");
    for (const v of ["system", "", "<x>", undefined, "DARK", "__proto__"]) expect(parseTheme(v)).toBe("system");
  });
});
