import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { decrypt, encrypt, parseKeyRing, randomToken, safeEqual, sha256 } from "./crypto";

const k = () => randomBytes(32).toString("base64");
const ring = (spec: string) => parseKeyRing(spec);

describe("AES-256-GCM key ring (T-04: tokens at rest)", () => {
  it("round-trips and uses a fresh IV each time", () => {
    const r = ring(`a:${k()}`);
    const aad = Buffer.from("row-1");
    const x = encrypt(r, Buffer.from("secret tokens"), aad);
    const y = encrypt(r, Buffer.from("secret tokens"), aad);
    expect(x.keyId).toBe("a");
    expect(x.data.equals(y.data)).toBe(false);
    expect(decrypt(r, "a", x.data, aad).toString()).toBe("secret tokens");
    expect(x.data.toString("latin1")).not.toContain("secret tokens");
  });

  it("any tampering fails: ciphertext, tag, IV, AAD, key id", () => {
    const r = ring(`a:${k()},b:${k()}`);
    const aad = Buffer.from("row-1");
    const { keyId, data } = encrypt(r, Buffer.from("payload"), aad);
    for (const i of [0, 11, 12, 20, data.length - 1]) {
      const bad = Buffer.from(data);
      bad[i] = (bad[i] as number) ^ 1;
      expect(() => decrypt(r, keyId, bad, aad), `byte ${i}`).toThrow();
    }
    expect(() => decrypt(r, keyId, data, Buffer.from("row-2"))).toThrow(); // a blob moved to another row
    expect(() => decrypt(r, "b", data, aad)).toThrow(); // wrong key
    expect(() => decrypt(r, "zzz", data, aad)).toThrow(/unknown key/);
    expect(() => decrypt(r, keyId, data.subarray(0, 20), aad)).toThrow();
  });

  it("rotation: new key encrypts, old key still decrypts old data", () => {
    const old = k();
    const before = ring(`old:${old}`);
    const blob = encrypt(before, Buffer.from("x"), Buffer.from("r"));
    const after = ring(`new:${k()},old:${old}`);
    expect(encrypt(after, Buffer.from("y"), Buffer.from("r")).keyId).toBe("new");
    expect(decrypt(after, blob.keyId, blob.data, Buffer.from("r")).toString()).toBe("x");
  });

  it.each([
    ["empty", ""],
    ["no colon", "abc"],
    ["bad id", `a b:${k()}`],
    ["short key", `a:${Buffer.alloc(16).toString("base64")}`],
    ["long key", `a:${Buffer.alloc(33).toString("base64")}`],
    ["duplicate id", `a:${k()},a:${k()}`],
  ])("refuses a bad key ring: %s", (_n, spec) => expect(() => ring(spec)).toThrow());

  it("helpers", () => {
    expect(randomToken()).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(randomToken()).not.toBe(randomToken());
    expect(sha256("a")).toHaveLength(32);
    expect(safeEqual("abc", "abc")).toBe(true);
    expect(safeEqual("abc", "abd")).toBe(false);
    expect(safeEqual("abc", "abcd")).toBe(false);
  });
});
