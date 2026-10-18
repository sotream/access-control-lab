#!/usr/bin/env node
// Every exception in .zap-allow.json needs a plugin id, a reason and an expiry that is neither past nor more than 90 days away (same discipline as .trivyignore.yaml).
import { readFileSync } from "node:fs";

const file = JSON.parse(readFileSync(new URL("../.zap-allow.json", import.meta.url), "utf8"));
const now = Date.now();
const problems = [];
for (const e of file.allow ?? []) {
  const id = e.pluginid ?? "(no plugin id)";
  if (!/^\d+$/.test(String(e.pluginid ?? ""))) problems.push(`${id}: needs a numeric pluginid`);
  if (typeof e.reason !== "string" || e.reason.length < 20) problems.push(`${id}: needs a reason of at least 20 characters`);
  const t = Date.parse(e.expires ?? "");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(e.expires ?? "") || Number.isNaN(t)) problems.push(`${id}: needs expires as YYYY-MM-DD`);
  else if (t < now) problems.push(`${id}: expired on ${e.expires}`);
  else if (t > now + 90 * 86_400_000) problems.push(`${id}: expires ${e.expires}, more than 90 days away`);
}
if (problems.length) {
  console.error(`.zap-allow.json:\n${problems.join("\n")}`);
  process.exit(1);
}
console.log(`ok: ${(file.allow ?? []).length} ZAP exception(s), each with a reason and a valid expiry`);
