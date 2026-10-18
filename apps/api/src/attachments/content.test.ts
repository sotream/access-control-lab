import { describe, expect, it } from "vitest";
import { decodeNameHeader, disposition, inspect, safeName } from "./content.js";
import { makeJpeg, makePdf, makePng, makeText } from "./fixtures.js";

const MAX = 5 * 1024 * 1024;
const code = (b: Buffer, declared?: string) => {
  const r = inspect(b, declared, MAX);
  return r.ok ? `ok:${r.media}` : r.code;
};
const cp = (...n: number[]) => String.fromCodePoint(...n);

describe("inspect: the bytes decide", () => {
  it("accepts the four allowed types when the declared type agrees", () => {
    expect(code(makePng(), "image/png")).toBe("ok:png");
    expect(code(makeJpeg(), "image/jpeg")).toBe("ok:jpeg");
    expect(code(makePdf(), "application/pdf")).toBe("ok:pdf");
    expect(code(makeText(), "text/plain")).toBe("ok:text");
    expect(code(makeText("Привіт, світе\n"), "text/plain")).toBe("ok:text");
  });

  it("refuses empty and oversized input before anything else", () => {
    expect(code(Buffer.alloc(0), "text/plain")).toBe("EMPTY");
    expect(code(Buffer.alloc(MAX + 1, 0x61), "text/plain")).toBe("TOO_LARGE");
  });

  it("wrong magic: the declared type does not match the bytes", () => {
    expect(code(makePdf(), "image/png")).toBe("MEDIA_MISMATCH");
    expect(code(makePng(), "application/pdf")).toBe("MEDIA_MISMATCH");
    expect(code(makeText(), "image/jpeg")).toBe("MEDIA_MISMATCH");
    expect(code(makePng(), undefined)).toBe("MEDIA_MISMATCH");
    expect(code(makePng(), "image/svg+xml")).toBe("MEDIA_MISMATCH");
  });

  it.each([
    ["Windows executable", Buffer.concat([Buffer.from("MZ"), Buffer.alloc(200, 1)])],
    ["ELF executable", Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(200, 1)])],
    ["shell script with a NUL", Buffer.from("#!/bin/sh\0\necho hi\n")],
    ["zip archive (also docx, xlsx, jar)", Buffer.concat([Buffer.from("PK\x03\x04"), Buffer.alloc(200, 2)])],
    ["gzip", Buffer.concat([Buffer.from([0x1f, 0x8b, 8]), Buffer.alloc(200, 3)])],
    ["7z", Buffer.concat([Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]), Buffer.alloc(200, 4)])],
    ["random binary", Buffer.from(Array.from({ length: 300 }, (_, i) => (i * 131 + 7) % 256))],
    ["UTF-16 text", Buffer.from("﻿hello", "utf16le")],
  ])("refuses %s", (_n, b) => {
    expect(code(b, "text/plain")).toBe("UNSUPPORTED_TYPE");
    expect(code(b, "application/octet-stream")).toBe("UNSUPPORTED_TYPE");
  });

  it.each([
    ["SVG", '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'],
    ["HTML", "<!DOCTYPE html><html><body>hi</body></html>"],
    ["HTML in a text file", "notes\n<script>alert(1)</script>\n"],
    ["XML", '<?xml version="1.0"?><a/>'],
    ["PHP", "<?php echo 1; ?>"],
    ["javascript url", "see javascript:alert(1)"],
  ])("refuses markup: %s", (_n, s) => {
    expect(code(Buffer.from(s), "text/plain")).toBe("ACTIVE_CONTENT");
    expect(code(Buffer.from(s), "image/svg+xml")).toBe("ACTIVE_CONTENT");
  });

  it("polyglots: markup or script hidden inside an image, a PDF or after the end of the file", () => {
    const html = Buffer.from("<html><script>alert(document.cookie)</script></html>");
    expect(code(makePng(2, 2, html), "image/png")).toBe("MALFORMED"); // bytes after IEND
    expect(code(Buffer.concat([makeJpeg().subarray(0, -2), html, Buffer.from([0xff, 0xd9])]), "image/jpeg")).toBe("ACTIVE_CONTENT");
    expect(code(Buffer.concat([makeJpeg(), html]), "image/jpeg")).toBe("MALFORMED"); // not ending in EOI
    expect(code(makePdf("% <script>alert(1)</script>"), "application/pdf")).toBe("ACTIVE_CONTENT");
    expect(code(Buffer.concat([Buffer.from("GIF89a/*"), html]), "image/gif")).toBe("ACTIVE_CONTENT"); // GIF/JS style polyglot: refused (and gif is not an allowed type anyway)
    const pngInTextChunk = makePng(2, 2);
    expect(code(Buffer.concat([pngInTextChunk.subarray(0, 20), Buffer.from("<svg onload=1>"), pngInTextChunk.subarray(20)]), "image/png")).toBe("MALFORMED"); // CRC breaks
  });

  it("PNG structure: bad CRC, bad lengths, missing IHDR or IEND, trailing bytes, truncation", () => {
    const good = makePng();
    const flip = Buffer.from(good);
    flip[good.length - 1] = (flip[good.length - 1] ?? 0) ^ 0xff; // IEND CRC
    expect(code(flip, "image/png")).toBe("MALFORMED");
    expect(code(good.subarray(0, good.length - 4), "image/png")).toBe("MALFORMED");
    expect(code(good.subarray(0, 40), "image/png")).toBe("MALFORMED");
    const big = Buffer.from(good);
    big.writeUInt32BE(0x7fffffff, 8); // IHDR length absurd
    expect(code(big, "image/png")).toBe("MALFORMED");
    expect(code(Buffer.concat([good, Buffer.from([0])]), "image/png")).toBe("MALFORMED");
  });

  it("PNG decompression bomb by dimensions is refused", () => {
    expect(code(makePng(20_000, 20_000), "image/png")).toBe("MALFORMED"); // 400 MP
    expect(code(makePng(30_000, 1), "image/png")).toBe("MALFORMED");
    expect(code(makePng(0, 5), "image/png")).toBe("MALFORMED");
    expect(code(makePng(6000, 6000), "image/png")).toBe("ok:png"); // 36 MP is still allowed
  });

  it("PDF: header and trailer needed, active content and obfuscated names refused", () => {
    expect(code(Buffer.from("%PDF-1.7\nno trailer"), "application/pdf")).toBe("MALFORMED");
    expect(code(Buffer.from("%PDF-9.9\n%%EOF"), "application/pdf")).toBe("MALFORMED");
    for (const evil of ["/JavaScript", "/JS (app.alert(1))", "/Launch", "/EmbeddedFile", "/OpenAction", "/AA", "/RichMedia", "/XFA", "/SubmitForm", "/GoToR", "/J#61vaScript", "/#4A#53"]) {
      expect(code(makePdf(`<< ${evil} >>`), "application/pdf"), evil).toBe("ACTIVE_CONTENT");
    }
    expect(code(makePdf("<< /Author (JavaScripture) >>"), "application/pdf")).toBe("ok:pdf"); // a word that merely contains the letters is fine
  });

  it("text: no NUL, no controls, no bidi or invisible characters", () => {
    for (const bad of [cp(0), cp(7), cp(0x1b), cp(0x202e), cp(0x200b), cp(0xfeff), cp(0xad), cp(0x85)]) {
      expect(code(makeText(`a${bad}b`), "text/plain"), bad.codePointAt(0)!.toString(16)).toBe("UNSUPPORTED_TYPE");
    }
    expect(code(makeText("tab\tand\r\nnewlines\n"), "text/plain")).toBe("ok:text");
  });
});

describe("safeName: a display name that cannot be a path or a trick", () => {
  it.each([
    ["report.pdf", "pdf", "report.pdf"],
    ["invoice.pdf.exe", "pdf", "invoice_pdf.pdf"],
    ["../../etc/passwd", "text", "passwd.txt"],
    ["..\\..\\windows\\system32\\evil.exe", "png", "evil.png"],
    ["/absolute/path/photo.JPG", "jpeg", "photo.jpg"],
    ["", "pdf", "attachment.pdf"],
    [undefined, "pdf", "attachment.pdf"],
    ["....", "pdf", "attachment.pdf"],
    [".hidden", "text", "hidden.txt"],
    ["CON", "text", "CON.txt"], // device names are harmless: the name is never used as a path
    ["null\0byte.pdf", "pdf", "null_byte.pdf"],
    ["line\nbreak\r.pdf", "pdf", "line_break.pdf"],
    ["quote\"and'semi;colon.pdf", "pdf", "quote_and_semi_colon.pdf"],
    ["звіт за жовтень.pdf", "pdf", "звіт за жовтень.pdf"],
    ["a".repeat(500) + ".pdf", "pdf", "a".repeat(80) + ".pdf"],
  ])("%j -> %j", (raw, media, want) => {
    expect(safeName(raw as string | undefined, media as "pdf")).toBe(want);
  });

  it("right-to-left override and other invisible characters never survive", () => {
    const name = safeName(`invoice${cp(0x202e)}fdp.exe`, "pdf");
    expect(name).toBe("invoice_fdp.pdf");
    for (const c of [0x202e, 0x2066, 0x200b, 0x200f, 0xfeff, 0xad, 0x061c]) expect(safeName(`a${cp(c)}b.pdf`, "pdf")).toBe("a_b.pdf");
  });

  it("the extension is always the one of the detected type", () => {
    expect(safeName("x.png", "pdf")).toBe("x.pdf");
    expect(safeName("x.svg", "png")).toBe("x.png");
    expect(safeName("x.html", "text")).toBe("x.txt");
  });
});

describe("disposition and the name header", () => {
  it("is an attachment, with an ASCII fallback and the full name percent-encoded", () => {
    expect(disposition("report.pdf")).toBe("attachment; filename=\"report.pdf\"; filename*=UTF-8''report.pdf");
    expect(disposition("звіт (1).pdf")).toBe("attachment; filename=\"____ (1).pdf\"; filename*=UTF-8''%D0%B7%D0%B2%D1%96%D1%82%20%281%29.pdf");
    expect(disposition("a\"b.pdf")).not.toMatch(/filename="[^"]*"[^;]*"/);
  });
  it("decodes the header, and drops anything undecodable or long instead of failing", () => {
    expect(decodeNameHeader("%D0%B7%D0%B2%D1%96%D1%82.pdf")).toBe("звіт.pdf");
    expect(decodeNameHeader("%E0%A4%A")).toBeUndefined();
    expect(decodeNameHeader("a".repeat(901))).toBeUndefined();
    expect(decodeNameHeader(undefined)).toBeUndefined();
    expect(decodeNameHeader(["a", "b"] as unknown as string)).toBeUndefined();
  });
});
