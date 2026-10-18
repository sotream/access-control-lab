import { appendFileSync } from "node:fs";
import { makeCheckpoint, parseAuditKeys } from "@acl/audit";
import pg from "pg";

/**
 * pnpm audit:checkpoint [--out PATH]
 * Writes a signed checkpoint of the current head into audit_checkpoints and, with --out, appends the same line to a file that should live OUTSIDE the
 * database host (that copy is what makes deleting the stored checkpoints detectable: pass it back with `audit:verify --checkpoint-file`).
 */
const url = process.env.AUDIT_DATABASE_URL;
const keys = process.env.AUDIT_HMAC_KEYS;
if (!url || !keys) {
  console.error("AUDIT_DATABASE_URL (casefile_audit) and AUDIT_HMAC_KEYS are required");
  process.exit(2);
}
const i = process.argv.indexOf("--out");
const out = i >= 0 ? process.argv[i + 1] : undefined;
const pool = new pg.Pool({ connectionString: url, max: 1 });
try {
  const h = (await pool.query("SELECT last_id, last_hash FROM audit_head WHERE singleton")).rows[0];
  const cp = makeCheckpoint({ lastId: Number(h.last_id), lastHash: h.last_hash as Buffer }, parseAuditKeys(keys));
  await pool.query("INSERT INTO audit_checkpoints (ts, last_id, last_hash, key_id, mac) VALUES ($1, $2, $3, $4, $5)", [cp.ts, cp.lastId, cp.lastHash, cp.keyId, cp.mac]);
  const line = JSON.stringify({ ts: cp.ts.toISOString(), last_id: cp.lastId, last_hash: cp.lastHash.toString("hex"), key_id: cp.keyId, mac: cp.mac.toString("hex") });
  if (out) appendFileSync(out, `${line}\n`, { mode: 0o600 });
  console.log(line);
} catch (e) {
  console.error(`cannot write checkpoint: ${e instanceof Error ? e.message : String(e)}`);
  process.exitCode = 2;
} finally {
  await pool.end();
}
