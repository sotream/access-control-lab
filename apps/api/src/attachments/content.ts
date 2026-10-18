import { crc32 } from "node:zlib";

/**
 * What an upload really is, decided from its bytes. The declared type, the file name and the extension are never trusted.
 * Allow-list: PDF, PNG, JPEG, plain text. Everything else (SVG, HTML, archives, office files, executables, scripts) is refused,
 * so there is no decompression to bound. Not a sanitiser: see docs/hardening.md for what the checks do and do not promise.
 */
export type Media = "pdf" | "png" | "jpeg" | "text";
export const MEDIA_TYPE: Readonly<Record<Media, string>> = { pdf: "application/pdf", png: "image/png", jpeg: "image/jpeg", text: "text/plain" };
export const EXTENSION: Readonly<Record<Media, string>> = { pdf: "pdf", png: "png", jpeg: "jpg", text: "txt" };

export type Inspection = { ok: true; media: Media } | { ok: false; code: "EMPTY" | "TOO_LARGE" | "UNSUPPORTED_TYPE" | "MALFORMED" | "ACTIVE_CONTENT" | "MEDIA_MISMATCH" };

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const MAX_PIXELS = 40_000_000;
const MAX_SIDE = 20_000;

// Markup and script markers anywhere in the file, any type: a file that is also a web page is refused (polyglots).
const MARKUP = ["<script", "<html", "<svg", "<iframe", "<object", "<embed", "<?php", "<!doctype", "<?xml", "javascript:", "<body", "<meta"];
// PDF names that start code, launch programs or pull in files. Best effort: object streams can hide them, the scanner hook and the download headers are the real defences.
const PDF_ACTIVE = /\/(JavaScript|JS|Launch|EmbeddedFile|OpenAction|AA|RichMedia|XFA|SubmitForm|ImportData|GoToR|GoToE)\b/;
const PDF_OBFUSCATED_NAME = /\/[A-Za-z]*#[0-9A-Fa-f]{2}/;

function png(b: Buffer): boolean {
  if (b.length < 8 + 25 + 12 || !b.subarray(0, 8).equals(PNG_SIG)) return false;
  let off = 8;
  let first = true;
  let sawEnd = false;
  while (off < b.length) {
    if (off + 12 > b.length) return false;
    const len = b.readUInt32BE(off);
    if (len > b.length - off - 12) return false; // length would run past the end
    const type = b.subarray(off + 4, off + 8);
    if (!type.every((c) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122))) return false;
    if (crc32(b.subarray(off + 4, off + 8 + len)) !== b.readUInt32BE(off + 8 + len)) return false;
    const name = type.toString("latin1");
    if (first) {
      if (name !== "IHDR" || len !== 13) return false;
      const w = b.readUInt32BE(off + 8);
      const h = b.readUInt32BE(off + 12);
      if (w < 1 || h < 1 || w > MAX_SIDE || h > MAX_SIDE || w * h > MAX_PIXELS) return false; // decompression bomb by dimensions
      first = false;
    }
    off += 12 + len;
    if (name === "IEND") {
      sawEnd = true;
      break;
    }
  }
  return sawEnd && off === b.length; // nothing after IEND: no appended payload
}

function jpeg(b: Buffer): boolean {
  return b.length >= 125 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff && b[b.length - 2] === 0xff && b[b.length - 1] === 0xd9;
}

function pdf(b: Buffer): boolean {
  const head = b.subarray(0, 8).toString("latin1");
  if (!/^%PDF-[12]\.\d/.test(head)) return false;
  return b.subarray(Math.max(0, b.length - 1024)).toString("latin1").includes("%%EOF");
}

const BANNED_TEXT = (cp: number) =>
  (cp < 0x20 && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) || (cp >= 0x7f && cp <= 0x9f) || (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x2069) || cp === 0xfeff || cp === 0xad;

function text(b: Buffer): boolean {
  let s: string;
  try {
    s = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(b);
  } catch {
    return false;
  }
  for (const ch of s) if (BANNED_TEXT(ch.codePointAt(0) as number)) return false;
  return true;
}

export function inspect(bytes: Buffer, declared: string | undefined, maxBytes: number): Inspection {
  if (bytes.length === 0) return { ok: false, code: "EMPTY" };
  if (bytes.length > maxBytes) return { ok: false, code: "TOO_LARGE" };
  const sniffed: Media | undefined = bytes.subarray(0, 8).equals(PNG_SIG)
    ? "png"
    : bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff
      ? "jpeg"
      : bytes.subarray(0, 5).toString("latin1") === "%PDF-"
        ? "pdf"
        : undefined;
  // no recognisable signature: only plain text can remain (anything binary fails the text check), never an executable, archive or markup
  const media: Media = sniffed ?? "text";
  const wellFormed = media === "png" ? png(bytes) : media === "jpeg" ? jpeg(bytes) : media === "pdf" ? pdf(bytes) : text(bytes);
  if (!wellFormed) return { ok: false, code: sniffed ? "MALFORMED" : "UNSUPPORTED_TYPE" };
  const lower = bytes.toString("latin1").toLowerCase();
  if (MARKUP.some((m) => lower.includes(m))) return { ok: false, code: "ACTIVE_CONTENT" };
  if (media === "pdf") {
    const raw = bytes.toString("latin1");
    if (PDF_ACTIVE.test(raw) || PDF_OBFUSCATED_NAME.test(raw)) return { ok: false, code: "ACTIVE_CONTENT" };
  }
  if (declared !== MEDIA_TYPE[media]) return { ok: false, code: "MEDIA_MISMATCH" }; // the client said one thing, the bytes say another
  return { ok: true, media };
}

/**
 * The name shown to people: letters, digits, marks, space, hyphen, underscore and parentheses of any script; everything else (separators,
 * dots, controls, bidi and invisible characters) becomes an underscore. The extension always comes from the detected type, so `invoice.pdf.exe`
 * can never read as anything but `invoice_pdf.pdf`. The name is never used as a path.
 */
export function safeName(raw: string | undefined, media: Media): string {
  let base = (raw ?? "").normalize("NFC");
  base = base.slice(Math.max(base.lastIndexOf("/"), base.lastIndexOf("\\")) + 1);
  const dot = base.lastIndexOf(".");
  if (dot > 0) base = base.slice(0, dot); // the claimed extension goes
  let stem = "";
  for (const ch of base) stem += /[\p{L}\p{N}\p{M} _()-]/u.test(ch) ? ch : "_";
  stem = [...stem.replace(/[_ ]{2,}/g, "_").replace(/^[-_ ]+|[-_ ]+$/g, "")].slice(0, 80).join("");
  return `${stem || "attachment"}.${EXTENSION[media]}`;
}

/** `attachment` with an ASCII fallback and the full name in RFC 5987 form. Both parts come from `safeName`, which cannot produce quotes or separators. */
export function disposition(name: string): string {
  const ascii = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
  const star = encodeURIComponent(name).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return `attachment; filename="${ascii}"; filename*=UTF-8''${star}`;
}

/** The `x-attachment-name` header carries UTF-8 percent-encoded; a bad encoding is not an error, the name is just replaced. */
export function decodeNameHeader(h: string | string[] | undefined): string | undefined {
  if (typeof h !== "string" || h.length > 900) return undefined;
  try {
    return decodeURIComponent(h);
  } catch {
    return undefined;
  }
}
