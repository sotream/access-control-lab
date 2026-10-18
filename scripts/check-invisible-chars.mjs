// Fails when a tracked text file contains bidi controls or zero-width characters (Trojan Source and friends).
// Hostile payloads in tests must be written as escapes ("‮"), never as raw characters.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const BAD = /[​-‏‪-‮⁠-⁤⁦-⁩﻿­᠎]/u;
const files = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" }).split("\0").filter(Boolean);
const hits = [];
for (const f of files) {
  let text;
  try {
    text = readFileSync(f);
  } catch {
    continue; // deleted in the working tree
  }
  if (text.includes(0)) continue; // binary
  text.toString("utf8").split("\n").forEach((line, i) => {
    const m = BAD.exec(line);
    if (m) hits.push(`${f}:${i + 1}: U+${m[0].codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`);
  });
}
if (hits.length) {
  console.error(`invisible or bidi characters found:\n${hits.join("\n")}`);
  process.exit(1);
}
console.log(`ok: ${files.length} tracked files, no bidi or zero-width characters`);
