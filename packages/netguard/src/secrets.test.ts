import { describe, expect, it } from "vitest";
import { assertStrongDbUrl, assertStrongKeyRing, assertStrongSecret, looksLikeDevValue, profileOf, resolveSecretFiles } from "./index.js";

const b64 = (b: Buffer) => b.toString("base64");
const random = () => b64(Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 37 + 11) % 251)));

describe("profileOf", () => {
  it("defaults to development, accepts production, refuses typos", () => {
    expect(profileOf({})).toBe("development");
    expect(profileOf({ ACL_ENV: "" })).toBe("development");
    expect(profileOf({ ACL_ENV: "development" })).toBe("development");
    expect(profileOf({ ACL_ENV: "production" })).toBe("production");
    for (const v of ["prod", "Production", "staging", "true"]) expect(() => profileOf({ ACL_ENV: v })).toThrow(/ACL_ENV/);
  });
});

describe("resolveSecretFiles", () => {
  const files: Record<string, string> = { "/s/a": "value-a\n", "/s/crlf": "value\r\n", "/s/empty": "\n", "/s/two": "x\n\n" };
  const read = (p: string) => {
    if (!(p in files)) throw new Error("ENOENT secret-content-must-not-leak");
    return files[p]!;
  };
  it("reads the file, drops one trailing newline, leaves other names alone", () => {
    expect(resolveSecretFiles({ A_FILE: "/s/a", B: "b" }, ["A", "B"], read)).toMatchObject({ A: "value-a", B: "b" });
    expect(resolveSecretFiles({ A_FILE: "/s/crlf" }, ["A"], read).A).toBe("value");
    expect(resolveSecretFiles({ A_FILE: "/s/two" }, ["A"], read).A).toBe("x\n");
    expect(resolveSecretFiles({ OTHER_FILE: "/s/a" }, ["A"], read).OTHER_FILE).toBe("/s/a"); // not a listed name: untouched
  });
  it("refuses both forms, a missing file and an empty file, without echoing content", () => {
    expect(() => resolveSecretFiles({ A: "x", A_FILE: "/s/a" }, ["A"], read)).toThrow(/both set/);
    expect(() => resolveSecretFiles({ A_FILE: "/nope" }, ["A"], read)).toThrow(/not readable$/);
    expect(() => resolveSecretFiles({ A_FILE: "/s/empty" }, ["A"], read)).toThrow(/empty/);
  });
  it("reads real files by default", () => {
    expect(() => resolveSecretFiles({ A_FILE: "/definitely/not/here" }, ["A"])).toThrow(/not readable/);
  });
});

describe("production strength checks", () => {
  it("recognises the shipped dev values and placeholders", () => {
    for (const v of ["dev-only-casefile-app-password", "changeme", "example", "My-Password-1"]) expect(looksLikeDevValue(v), v).toBe(true);
    expect(looksLikeDevValue("q9Xv2LmT8sWk4RzP7nYd3HfJ6bCa1UeG")).toBe(false);
  });
  it("key rings: short, text, dev-named, repeated-byte and low-entropy keys are refused; a random one passes", () => {
    expect(() => assertStrongKeyRing("R", `k:${b64(Buffer.alloc(16, 7))}`)).toThrow(/shorter/);
    expect(() => assertStrongKeyRing("R", `k:${b64(Buffer.from("dev-only-session-key-0123456789ab"))}`)).toThrow(/development/);
    expect(() => assertStrongKeyRing("R", `dev-1:${random()}`)).toThrow(/development/);
    expect(() => assertStrongKeyRing("R", `k:${b64(Buffer.alloc(32, 1))}`)).toThrow(/entropy/);
    expect(() => assertStrongKeyRing("R", `k:${b64(Buffer.from("abababababababababababababababab"))}`)).toThrow(/entropy/);
    expect(() => assertStrongKeyRing("R", `new:${random()},old:${b64(Buffer.alloc(32, 1))}`)).toThrow(/old/); // every key of the ring counts
    expect(() => assertStrongKeyRing("R", `k:${random()}`)).not.toThrow();
  });
  it("secrets and database passwords", () => {
    expect(() => assertStrongSecret("S", "short")).toThrow(/at least 32/);
    expect(() => assertStrongSecret("S", "dev-only-proxy-secret-0123456789abcdef")).toThrow(/development/);
    expect(() => assertStrongSecret("S", "a".repeat(40))).toThrow(/entropy/);
    expect(() => assertStrongSecret("S", "q9Xv2LmT8sWk4RzP7nYd3HfJ6bCa1UeG")).not.toThrow();
    expect(() => assertStrongDbUrl("D", "postgres://u:short@h/db")).toThrow(/16/);
    expect(() => assertStrongDbUrl("D", "postgres://u:dev-only-casefile-app-password@h/db")).toThrow(/development/);
    expect(() => assertStrongDbUrl("D", "postgres://u@h/db")).toThrow(/16/);
    expect(() => assertStrongDbUrl("D", "postgres://u:q9Xv2LmT8sWk4RzP7nYd@h/db")).not.toThrow();
  });
});
