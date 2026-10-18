#!/usr/bin/env node
// Every exception in .trivyignore.yaml needs a reason and an expiry that is neither past nor more than 90 days away.
// Reads the small subset of YAML the file uses (a list under `vulnerabilities:` of `- id:` blocks) so it needs no dependency.
import { readFileSync } from "node:fs";

const file = new URL("../.trivyignore.yaml", import.meta.url);
const lines = readFileSync(file, "utf8").split("\n");
const entries = [];
for (const raw of lines) {
  if (raw.trim().startsWith("#")) continue;
  const m = /^\s*-\s+id:\s*(\S+)/.exec(raw);
  if (m) entries.push({ id: m[1] });
  else if (entries.length) {
    const f = /^\s+(statement|expired_at):\s*(.+?)\s*$/.exec(raw);
    if (f) entries.at(-1)[f[1]] = f[2].replace(/^["']|["']$/g, "");
  }
}
const now = Date.now();
const problems = [];
for (const e of entries) {
  if (!e.statement || e.statement.length < 20) problems.push(`${e.id}: needs a statement (the reason) of at least 20 characters`);
  const t = Date.parse(e.expired_at ?? "");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(e.expired_at ?? "") || Number.isNaN(t)) problems.push(`${e.id}: needs expired_at as YYYY-MM-DD`);
  else if (t < now) problems.push(`${e.id}: expired on ${e.expired_at}`);
  else if (t > now + 90 * 86_400_000) problems.push(`${e.id}: expires ${e.expired_at}, more than 90 days away`);
}
if (problems.length) {
  console.error(`.trivyignore.yaml:\n${problems.join("\n")}`);
  process.exit(1);
}
console.log(`ok: ${entries.length} Trivy exception(s), each with a reason and a valid expiry`);
