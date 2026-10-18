import { readFileSync } from "node:fs";
import { parseAuditKeys, type Checkpoint } from "@acl/audit";
import pg from "pg";
import { verifyDatabase } from "./verify-db.js";

/**
 * pnpm audit:verify [--from N] [--to M] [--prev-hash HEX] [--checkpoint-file PATH]
 * Exit 0: chain verified. Exit 1: a problem was found (first bad row is printed). Exit 2: could not run (usage, connection, configuration).
 */
const args = process.argv.slice(2);
const arg = (name: string): string | undefined => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const known = new Set(["--from", "--to", "--prev-hash", "--checkpoint-file"]);
for (const a of args.filter((x) => x.startsWith("--"))) {
  if (!known.has(a)) {
    console.error(`unknown option ${a}`);
    process.exit(2);
  }
}

const url = process.env.AUDIT_DATABASE_URL;
const keys = process.env.AUDIT_HMAC_KEYS;
if (!url || !keys) {
  console.error("AUDIT_DATABASE_URL (casefile_audit) and AUDIT_HMAC_KEYS are required");
  process.exit(2);
}

function externalCheckpoints(path: string): Checkpoint[] {
  const text = readFileSync(path, "utf8");
  return text
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((l) => {
      const c = JSON.parse(l) as { ts: string; last_id: number; last_hash: string; key_id: string; mac: string };
      return { ts: new Date(c.ts), lastId: c.last_id, lastHash: Buffer.from(c.last_hash, "hex"), keyId: c.key_id, mac: Buffer.from(c.mac, "hex") };
    });
}

const pool = new pg.Pool({ connectionString: url, max: 1 });
try {
  const file = arg("checkpoint-file");
  const from = arg("from");
  const to = arg("to");
  const prev = arg("prev-hash");
  const res = await verifyDatabase(pool, parseAuditKeys(keys), {
    ...(from ? { fromId: Number(from) } : {}),
    ...(to ? { toId: Number(to) } : {}),
    ...(prev ? { prevHash: Buffer.from(prev, "hex") } : {}),
    ...(file ? { extraCheckpoints: externalCheckpoints(file) } : {}),
  });
  console.log(JSON.stringify({ ok: res.ok, checked: res.checked, lastId: res.lastId, lastHash: res.lastHash, firstBad: res.firstBad ?? null, issues: res.issues.slice(0, 50) }));
  if (!res.ok) console.error(`AUDIT CHAIN BROKEN at row ${res.firstBad?.id ?? "?"}: ${res.firstBad?.code} ${res.firstBad?.message}`);
  process.exitCode = res.ok ? 0 : 1;
} catch (e) {
  console.error(`cannot verify: ${e instanceof Error ? e.message : String(e)}`);
  process.exitCode = 2;
} finally {
  await pool.end();
}
