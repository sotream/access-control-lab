#!/usr/bin/env node
// docs/asvs.md states per-chapter and total tallies. This counts the rows of the chapter tables and fails when the summary table disagrees.
// `node scripts/count-asvs.mjs --fix` rewrites the summary table from the rows (the only way the numbers should change).
import { readFileSync, writeFileSync } from "node:fs";

const path = new URL("../docs/asvs.md", import.meta.url).pathname;
const text = readFileSync(path, "utf8");
const STATUSES = ["met", "partial", "delegated", "n/a", "not met"];

const chapters = new Map(); // "V1 Architecture..." -> counts
let current;
for (const line of text.split("\n")) {
  const h = /^## (V\d+ .+)$/.exec(line);
  if (h) {
    current = h[1].trim();
    chapters.set(current, Object.fromEntries(STATUSES.map((s) => [s, 0])));
    continue;
  }
  if (/^## /.test(line)) current = undefined;
  const row = /^\| (?!ID \|)(?!-)([^|]+) \|(.*)\|\s*$/.exec(line);
  if (!row || !current) continue;
  const status = row[2].split("|")[1]?.trim();
  if (!STATUSES.includes(status)) {
    console.error(`asvs.md: row ${row[1]} has status "${status}" (expected one of ${STATUSES.join(", ")})`);
    process.exit(1);
  }
  chapters.get(current)[status]++;
}

const total = Object.fromEntries(STATUSES.map((s) => [s, [...chapters.values()].reduce((n, c) => n + c[s], 0)]));
const cells = (c) => STATUSES.map((s) => c[s]).join(" | ");
const wanted = [...chapters].map(([name, c]) => `| ${name} | ${cells(c)} |`);
wanted.push(`| **Total** | ${STATUSES.map((s) => total[s]).join(" | ")} |`);

const lines = text.split("\n");
const start = lines.findIndex((l) => /^\| Chapter \|/.test(l)) + 2; // header and separator
let end = start;
while (end < lines.length && /^\| /.test(lines[end])) end++;
const stated = lines.slice(start, end);

if (process.argv.includes("--fix")) {
  lines.splice(start, end - start, ...wanted);
  writeFileSync(path, lines.join("\n"));
  console.log("asvs.md summary rewritten from the rows");
  process.exit(0);
}
const problems = [];
if (stated.length !== wanted.length) problems.push(`summary has ${stated.length} rows, the chapters give ${wanted.length}`);
for (let i = 0; i < Math.min(stated.length, wanted.length); i++) if (stated[i].replace(/\s+/g, " ").trim() !== wanted[i]) problems.push(`stated: ${stated[i].trim()}\n  counted: ${wanted[i]}`);
if (problems.length) {
  console.error(`asvs.md: the summary table does not match the rows (run: node scripts/count-asvs.mjs --fix)\n  ${problems.join("\n  ")}`);
  process.exit(1);
}
const all = STATUSES.reduce((n, s) => n + total[s], 0);
console.log(`ok: ASVS summary matches ${all} rows (${STATUSES.map((s) => `${s} ${total[s]}`).join(", ")})`);
