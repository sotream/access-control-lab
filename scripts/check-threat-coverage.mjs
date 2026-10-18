#!/usr/bin/env node
// The threat model is only worth something if each threat points at something that can fail. This script reads docs/threat-model.md and fails when:
//  - a threat (T-nn) has no reference to an existing test or check, and no "Accepted risk AR-nn" that exists in docs/accepted-risks.md with an owner, a rationale and an upgrade path;
//  - a file the threat model refers to does not exist;
//  - an attack ID in tests/attack/src/*.test.ts is missing from docs/attack-catalogue.md, a catalogue row points at a missing test file or at one that does not contain its ID,
//    or an attack names a threat that is not in the threat model.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { basename } from "node:path";

const root = new URL("../", import.meta.url).pathname;
const read = (p) => readFileSync(root + p, "utf8");
const tracked = execFileSync("git", ["ls-files"], { cwd: root, encoding: "utf8" }).split("\n").filter(Boolean);
const byBase = new Map();
for (const f of tracked) byBase.set(basename(f), [...(byBase.get(basename(f)) ?? []), f]);
const problems = [];

// ---- accepted risks
const risks = new Map();
{
  const text = read("docs/accepted-risks.md");
  for (const block of text.split(/^## /m).slice(1)) {
    const id = /^(AR-\d+)/.exec(block)?.[1];
    if (!id) continue;
    // each of the three fields is a line of its own, with real content (a bare label does not count)
    for (const [label, min] of [["Owner", 3], ["Rationale", 30], ["Upgrade path", 20]]) if (!new RegExp(`\\*\\*${label}:\\*\\*[ \\t]*[^\\n]{${min},}`).test(block)) problems.push(`accepted-risks.md ${id}: missing or empty **${label}:**`);
    risks.set(id, true);
  }
}

// ---- threats
const threats = new Map();
const model = read("docs/threat-model.md");
for (const line of model.split("\n")) {
  const m = /^\| (T-\d+) \|(.*)\|\s*$/.exec(line);
  if (!m) continue;
  const cells = m[2].split("|").map((c) => c.trim());
  // columns after the id: threat | mitigation | stage | evidence (a "|" inside backticks would break this; none is used)
  threats.set(m[1], { evidence: cells.slice(3).join(" | "), line });
}
if (threats.size < 40) problems.push(`only ${threats.size} threats parsed from the threat model: the table format changed?`);

const FILE = /`([^`\s=]+\.(?:ts|tsx|mjs|js|json|md|yml|yaml|sql|sh|toml|ignore))`/g;
const resolve = (ref) => {
  if (ref.includes("/")) return existsSync(root + ref) ? ref : undefined;
  const hits = byBase.get(ref) ?? [];
  return hits.length === 1 ? hits[0] : hits.length > 1 ? hits[0] : undefined;
};
const isCheck = (p) => /\.test\.(ts|tsx)$/.test(p) || /^tests\//.test(p) || /^scripts\/.*(test|check)/.test(p) || /^\.github\/workflows\//.test(p);

let tested = 0;
let accepted = 0;
for (const [id, t] of threats) {
  const refs = [...t.evidence.matchAll(FILE)].map((m) => m[1]);
  const resolved = [];
  for (const r of refs) {
    const p = resolve(r);
    if (!p) problems.push(`${id}: refers to \`${r}\`, which does not exist`);
    else resolved.push(p);
  }
  const ar = [...t.evidence.matchAll(/Accepted risk (AR-\d+(?:, AR-\d+)*)/g)].flatMap((m) => m[1].split(", "));
  for (const a of ar) if (!risks.has(a)) problems.push(`${id}: Accepted risk ${a} is not in docs/accepted-risks.md`);
  const hasTest = resolved.some(isCheck);
  const hasAccepted = ar.some((a) => risks.has(a));
  if (!hasTest && !hasAccepted) problems.push(`${id}: no existing test or check and no accepted risk`);
  if (hasTest) tested++;
  if (!hasTest && hasAccepted) accepted++;
}

// ---- the catalogue
const catalogue = read("docs/attack-catalogue.md");
const rows = new Map();
for (const line of catalogue.split("\n")) {
  const m = /^\| (A-\d+) \|(.*)\|\s*$/.exec(line);
  if (!m) continue;
  const cells = m[2].split("|").map((c) => c.trim());
  rows.set(m[1], { threats: cells[4] ?? "", file: /`([^`]+)`/.exec(cells[5] ?? "")?.[1] });
}
const inTests = new Map();
for (const f of readdirSync(root + "tests/attack/src").filter((x) => x.endsWith(".test.ts"))) {
  const text = read(`tests/attack/src/${f}`);
  for (const m of text.matchAll(/describe(?:\.skipIf\([^)]*\))?\("(A-\d+)\b/g)) inTests.set(m[1], `tests/attack/src/${f}`);
}
for (const [id, file] of inTests) {
  const row = rows.get(id);
  if (!row) problems.push(`${id}: in ${file} but not in docs/attack-catalogue.md`);
  else if (row.file !== file) problems.push(`${id}: the catalogue says ${row.file}, the test is in ${file}`);
}
for (const [id, row] of rows) {
  if (!inTests.has(id)) problems.push(`${id}: in the catalogue but no test declares it`);
  if (!row.file || !existsSync(root + row.file)) problems.push(`${id}: test file ${row.file} does not exist`);
  for (const t of row.threats.split(/[,\s]+/).filter(Boolean)) if (!threats.has(t)) problems.push(`${id}: names threat ${t}, which is not in the threat model`);
}
const attacked = new Set([...rows.values()].flatMap((r) => r.threats.split(/[,\s]+/).filter(Boolean)));

if (problems.length) {
  console.error(`threat coverage:\n${problems.map((p) => `  ${p}`).join("\n")}`);
  process.exit(1);
}
console.log(`ok: ${threats.size} threats (${tested} with an existing test or check, ${accepted} resting on an accepted risk), ${attacked.size} of them attacked by ${rows.size} catalogued attacks, ${risks.size} accepted risks`);
