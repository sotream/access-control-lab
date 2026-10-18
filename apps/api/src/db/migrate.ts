import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import pg from "pg";

/** apps/api/migrations, reachable from both src/db and dist/db */
export const MIGRATIONS_DIR = fileURLToPath(new URL("../../migrations/", import.meta.url));

const FILE = /^(\d{3})_[a-z0-9_]+\.sql$/;
const LOCK_ID = 727_274_001; // arbitrary, fixed: serialises concurrent runners

export interface MigrationResult {
  applied: string[];
  alreadyApplied: string[];
}

/**
 * Forward-only SQL migrations. Each file runs in its own transaction and is recorded with its SHA-256;
 * an applied file that was edited, or a recorded file that disappeared, stops the run (no silent drift).
 * Run as casefile_migrator (the table owner), never as the application role.
 */
export async function migrate(connectionString: string, dir = MIGRATIONS_DIR): Promise<MigrationResult> {
  const files = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
  for (const f of files) if (!FILE.test(f)) throw new Error(`bad migration file name: ${f}`);
  const prefixes = files.map((f) => f.slice(0, 3));
  if (new Set(prefixes).size !== prefixes.length) throw new Error("duplicate migration number");

  const client = new pg.Client({ connectionString });
  await client.connect();
  try {
    await client.query("SELECT pg_advisory_lock($1)", [LOCK_ID]);
    await client.query(
      "CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())",
    );
    const recorded = new Map<string, string>(
      (await client.query<{ name: string; checksum: string }>("SELECT name, checksum FROM schema_migrations")).rows.map((r) => [r.name, r.checksum]),
    );
    for (const name of recorded.keys()) if (!files.includes(name)) throw new Error(`applied migration missing on disk: ${name}`);

    const result: MigrationResult = { applied: [], alreadyApplied: [] };
    for (const name of files) {
      const text = readFileSync(`${dir}/${name}`, "utf8");
      const checksum = createHash("sha256").update(text).digest("hex");
      const prior = recorded.get(name);
      if (prior !== undefined) {
        if (prior !== checksum) throw new Error(`migration ${name} was modified after it was applied`);
        result.alreadyApplied.push(name);
        continue;
      }
      await client.query("BEGIN");
      try {
        await client.query(text); // simple protocol: the file may hold many statements, none take parameters
        await client.query("INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)", [name, checksum]);
        await client.query("COMMIT");
      } catch (e) {
        await client.query("ROLLBACK");
        throw e;
      }
      result.applied.push(name);
    }
    return result;
  } finally {
    await client.query("SELECT pg_advisory_unlock($1)", [LOCK_ID]).catch(() => undefined);
    await client.end();
  }
}
