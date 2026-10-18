// Operator-side helpers: the stack's generated secrets, psql inside the postgres container (fixtures, evidence), docker.
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

export const ROOT = new URL("../../../", import.meta.url).pathname;
export const SECRETS = join(ROOT, "secrets-dev", "prod-like");
export const COMPOSE = ["compose", "-f", "docker-compose.prod-like.yml", "-f", "docker-compose.prod-like.test.yml"];

export const env: Record<string, string> = Object.fromEntries(
  (() => {
    try {
      return readFileSync(join(SECRETS, "compose.env"), "utf8").split("\n").filter(Boolean).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]);
    } catch {
      return [];
    }
  })(),
);

export const secret = (name: string): string => readFileSync(join(SECRETS, name), "utf8").trim();

export const dc = (...args: string[]): string => execFileSync("docker", [...COMPOSE, ...args], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

/** psql as the database superuser inside the postgres container: for fixtures and for looking at evidence, never as part of an attack */
export function psql(sqlText: string): string {
  const r = spawnSync("docker", [...COMPOSE, "exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "acl", "-At", "-v", "ON_ERROR_STOP=1", "-c", sqlText], { cwd: ROOT, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`psql failed: ${r.stderr}`);
  return r.stdout.trim();
}

/** psql as another database role (a stolen credential): returns the outcome instead of throwing */
export function psqlAs(user: string, password: string, sqlText: string, db = "acl"): { ok: boolean; out: string } {
  const r = spawnSync("docker", [...COMPOSE, "exec", "-T", "-e", `PGPASSWORD=${password}`, "postgres", "psql", "-h", "127.0.0.1", "-U", user, "-d", db, "-At", "-c", sqlText], { cwd: ROOT, encoding: "utf8" });
  return { ok: r.status === 0, out: `${r.stdout}${r.stderr}`.trim() };
}

export const q = (s: string): string => `'${s.replaceAll("'", "''")}'`;

export function insertCase(o: { title?: string; classification?: string; unit?: string; compartments?: string[]; status?: string; author?: string; body?: string }): string {
  const status = o.status ?? "draft";
  const comps = `ARRAY[${(o.compartments ?? []).map(q).join(",")}]::text[]`;
  const out = psql(
    `INSERT INTO case_files (title, body, classification, unit, compartments, status, author_id, submitted_by_id) VALUES (${q(o.title ?? "fixture")}, ${q(o.body ?? "fixture body")}, ${q(o.classification ?? "OFFICIAL")}::classification, ${q(o.unit ?? "alpha")}, ${comps}, ${q(status)}::case_status, ${q(o.author ?? "fixture-author")}, ${status === "draft" ? "NULL" : q("fixture-submitter")}) RETURNING id`,
  );
  return out.split("\n")[0]!;
}
