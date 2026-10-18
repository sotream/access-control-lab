// Fails when a tracked text file contains bidi controls or zero-width characters (Trojan Source and friends).
// Hostile payloads in tests must be written as escape sequences, never as raw characters.
// The forbidden code points are listed as numbers on purpose: this file itself must be plain printable text.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const RANGES = [
  [0x200b, 0x200f], // zero-width space, joiners, direction marks
  [0x202a, 0x202e], // embedding and override controls
  [0x2060, 0x2064], // word joiner and invisible operators
  [0x2066, 0x2069], // isolates
  [0xfeff, 0xfeff], // byte order mark / zero-width no-break space
  [0x00ad, 0x00ad], // soft hyphen
  [0x180e, 0x180e], // Mongolian vowel separator
  [0x01, 0x08], // C0 control characters (tab, newline and carriage return are fine)
  [0x0b, 0x0c],
  [0x0e, 0x1f],
  [0x7f, 0x9f], // delete and C1 controls
];
const forbidden = (cp) => RANGES.some(([a, b]) => cp >= a && cp <= b);

const files = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" }).split("\0").filter(Boolean);
const hits = [];
for (const f of files) {
  let buf;
  try {
    buf = readFileSync(f);
  } catch {
    continue; // deleted in the working tree
  }
  if (buf.includes(0)) continue; // binary
  buf.toString("utf8").split("\n").forEach((line, i) => {
    for (const ch of line) {
      if (forbidden(ch.codePointAt(0))) {
        hits.push(`${f}:${i + 1}: U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`);
        break;
      }
    }
  });
}
if (hits.length) {
  console.error(`invisible or bidi characters found:\n${hits.join("\n")}`);
  process.exit(1);
}
console.log(`ok: ${files.length} tracked files, no bidi or zero-width characters`);
