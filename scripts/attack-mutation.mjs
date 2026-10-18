#!/usr/bin/env node
// Mutation spot-check of the attack suite: break one defence at a time, rebuild what it lives in, run the attack file that is supposed to notice, and report whether it did.
// A mutant that SURVIVES is either a weak attack or a redundant layer (the table says which it is expected to be). Needs the prod-like stack to be up (pnpm test:attack
// with ATTACK_KEEP=1 leaves it so). Usage: node scripts/attack-mutation.mjs [M01 M05 ...]   (default: all). Slow: every mutant rebuilds images (minutes).
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("../", import.meta.url).pathname;
const compose = ["compose", "-f", "docker-compose.prod-like.yml", "-f", "docker-compose.prod-like.test.yml"];
const API = ["api", "api-lax"];
const WEB = ["web", "web-strict"];

/** edits: [file, find, replace]; expected: "killed" or "survives (reason)" */
const MUTANTS = [
  { id: "M01", what: "the API checks neither the audience nor the authorised party of a token", edits: [["apps/api/src/auth/token-verifier.ts", "        audience: this.cfg.audience,\n", ""], ["apps/api/src/auth/token-verifier.ts", 'if (typeof payload.azp !== "string" || !this.cfg.allowedAzp.includes(payload.azp)) throw new AuthError("bad_azp");', ""]], tests: ["jwt-api.test.ts"], rebuild: API, expected: "survives (redundant layers: the account-console token also lacks the application claims the API requires, clearance and unit, so it is refused three times over; the unit tests of stage 3 pin each check on its own)" },
  { id: "M02", what: "the audit list needs only the right to read case files", edits: [["apps/api/src/audit/audit-log.controller.ts", '@Policy({ action: "readAudit", resource: null })\n  @Get()', '@Policy({ action: "read", resource: null })\n  @Get()']], tests: ["authz.test.ts"], rebuild: API, expected: "killed" },
  { id: "M03", what: "the API no longer refuses prototype-pollution and empty keys", edits: [["apps/api/src/app.ts", "  app.use(rejectPollutingKeys);\n", ""]], tests: ["fuzz.test.ts", "authz.test.ts"], rebuild: API, expected: "killed" },
  { id: "M04", what: "uploads are stored without inspecting their bytes", edits: [["apps/api/src/attachments/attachment.service.ts", "const verdict = inspect(bytes, declaredType, this.cfg.attachmentMaxBytes);", 'const verdict = { ok: true, media: "text" } as ReturnType<typeof inspect>;']], tests: ["uploads.test.ts"], rebuild: API, expected: "killed" },
  { id: "M05", what: "a quarantined or pending attachment can be downloaded", edits: [["apps/api/src/attachments/attachment.service.ts", 'if (row.status !== "clean") throw new HttpException("Conflict", 409);', ""]], tests: ["uploads.test.ts"], rebuild: API, expected: "killed" },
  { id: "M06", what: "an attachment id works under any case file the user can read (IDOR)", edits: [["apps/api/src/db/attachment.repository.ts", "FROM attachments WHERE id = $1 AND case_file_id = $2`;", "FROM attachments WHERE id = $1 AND $2::uuid IS NOT NULL`;"]], tests: ["uploads.test.ts"], rebuild: API, expected: "killed" },
  { id: "M07", what: "the CSRF check of the BFF always passes", edits: [["apps/web/src/server/csrf.ts", '  const o = headers.get("origin");\n  if (!o) return "origin_missing";', '  if (true as boolean) return undefined;\n  const o = headers.get("origin");\n  if (!o) return "origin_missing";']], tests: ["session-bff.test.ts"], rebuild: WEB, expected: "killed" },
  { id: "M08", what: "the session cookie is not HttpOnly", edits: [["apps/web/src/server/cookies.ts", "({ httpOnly: true, secure:", "({ httpOnly: false as unknown as true, secure:"]], tests: ["session-bff.test.ts"], rebuild: WEB, expected: "killed" },
  { id: "M09", what: "the post-login redirect accepts any returnTo", edits: [["apps/web/src/server/redirect.ts", "  if (typeof raw !== \"string\" || raw.length === 0 || raw.length > 200) return DEFAULT;\n  const decoded", "  if (typeof raw === \"string\" && raw.length > 0) return raw;\n  if (typeof raw !== \"string\" || raw.length === 0 || raw.length > 200) return DEFAULT;\n  const decoded"]], tests: ["session-bff.test.ts"], rebuild: WEB, expected: "killed" },
  { id: "M10", what: "the callback checks the state against the one in the URL itself instead of the one in the pre-auth cookie", edits: [["apps/web/app/api/auth/callback/route.ts", "expectedState: pre.state, ", "expectedState: current.searchParams.get(\"state\") ?? undefined, "]], tests: ["session-bff.test.ts"], rebuild: WEB, expected: "killed" },
  { id: "M11", what: "the login endpoint has no rate limit", edits: [["apps/web/app/api/auth/login/route.ts", '  const slow = await limited("auth");\n  if (slow) return slow;\n', ""]], tests: ["ratelimit-proxy.test.ts"], rebuild: WEB, expected: "killed" },
  { id: "M12", what: "the API's failed-authentication budget is off", edits: [["apps/api/src/auth/auth.guard.ts", "if (this.limiter.blocked(key)) {", "if (false as boolean) {"]], tests: ["ratelimit-proxy.test.ts"], rebuild: API, expected: "killed" },
  { id: "M13", what: "the generic proxy forwards a break-glass header from the browser", edits: [["apps/web/app/bff/[...path]/route.ts", "{ ...(jsonBody === undefined ? {} : { json: jsonBody }), ...(query ? { query } : {}) }", '{ ...(jsonBody === undefined ? {} : { json: jsonBody }), ...(query ? { query } : {}), ...(req.headers.get("x-break-glass-justification") ? { breakGlass: req.headers.get("x-break-glass-justification") as string } : {}) }']], tests: ["breakglass-stepup.test.ts"], rebuild: WEB, expected: "killed" },
  { id: "M14", what: "a break-glass justification is not cleaned before the policy and the audit row", edits: [["apps/api/src/policy/policy.enforcer.ts", "sanitizeText(decodedHeader(Array.isArray(header) ? header.join(\", \") : header), MAX_JUSTIFICATION) ?? \"\"", "(decodedHeader(Array.isArray(header) ? header.join(\", \") : header) ?? \"\").slice(0, 100000)"]], tests: ["breakglass-stepup.test.ts"], rebuild: API, expected: "killed" },
  { id: "M15", what: "the BFF answers an invalid percent-escape in a path with a 500 again", edits: [["apps/web/proxy.ts", "    decodeURIComponent(new URL(request.url).pathname);", "    new URL(request.url).pathname;"]], tests: ["leakage.test.ts"], rebuild: WEB, expected: "killed" },
  { id: "M16", what: "the proxy lets unused methods through", edits: [["infra/caddy/Caddyfile", '	respond @unknown_method "Method Not Allowed" 405\n	request_body {', "	request_body {"]], tests: ["ratelimit-proxy.test.ts", "session-bff.test.ts"], rebuild: [], restartCaddy: true, expected: "killed" },
  { id: "M17", what: "the policy engine no longer checks the clearance floor", edits: [["packages/policy/src/evaluate.ts", 'check("CLEARANCE_TOO_LOW", clearanceRank(subject.clearance) >= clearanceRank(res.classification));', 'check("CLEARANCE_TOO_LOW", true);']], tests: ["authz.test.ts"], rebuild: API, expected: "survives (redundant layer: row-level security hides the row before the policy is asked; the parity tests of stage 5 are what kill this one)" },
];

const run = (cmd, args, o = {}) => spawnSync(cmd, args, { cwd: root, encoding: "utf8", ...o });
const dc = (...a) => run("docker", [...compose, ...a]);
const only = process.argv.slice(2).concat((process.env.MUTANTS ?? "").split(/\s+/).filter(Boolean));
const results = [];

function rebuild(services, caddy) {
  if (services.length) {
    const r = dc("up", "-d", "--build", "--wait", "--wait-timeout", "600", ...services);
    if (r.status !== 0) return `rebuild failed: ${r.stderr.slice(-200)}`;
  }
  if (caddy) dc("restart", "caddy");
  return undefined;
}

for (const m of MUTANTS) {
  if (only.length && !only.includes(m.id)) continue;
  const files = [...new Set(m.edits.map((e) => e[0]))];
  const dirty = run("git", ["diff", "--quiet", "--", ...files]);
  if (dirty.status !== 0) {
    console.error(`${m.id}: ${files.join(", ")} has uncommitted changes: refusing to mutate it`);
    process.exit(2);
  }
  const originals = new Map(files.map((f) => [f, readFileSync(join(root, f), "utf8")]));
  let outcome;
  try {
    for (const [f, find, replace] of m.edits) {
      const text = readFileSync(join(root, f), "utf8");
      if (!text.includes(find)) throw new Error(`pattern not found in ${f}`);
      writeFileSync(join(root, f), text.replace(find, replace));
    }
    const failed = rebuild(m.rebuild, m.restartCaddy);
    if (failed) throw new Error(failed);
    const t = run("pnpm", ["--filter", "@acl/attack-tests", "exec", "vitest", "run", ...m.tests.map((x) => `src/${x}`)], { env: { ...process.env, NO_COLOR: "1", FORCE_COLOR: "0", ATTACK_NO_UP: "1", NODE_EXTRA_CA_CERTS: join(root, "secrets-dev/prod-like/ca.crt") } });
    const plain = `${t.stdout}\n${t.stderr}`.replace(/\u001b\[[0-9;]*m/g, "");
    const summary = /Tests\s+(.*)/.exec(plain)?.[1]?.trim() ?? `no summary; ${plain.split("\n").filter((l) => /FAIL|Error|×|✗|❯/.test(l) && !/ERR_PNPM|pnpm recursive/.test(l)).slice(0, 8).join(" | ").slice(0, 700)}`;
    outcome = { verdict: t.status === 0 ? "SURVIVED" : "killed", summary };
  } catch (e) {
    outcome = { verdict: "ERROR", summary: String(e.message) };
  } finally {
    for (const [f, text] of originals) writeFileSync(join(root, f), text);
    // put the stack back as the source is BEFORE the next mutant: a mutant that stays built poisons the next one (found the hard way: one broken login failed every later run)
    rebuild(m.rebuild, m.restartCaddy);
  }
  const ok = outcome.verdict === "killed" ? m.expected === "killed" : outcome.verdict === "SURVIVED" && m.expected.startsWith("survives");
  console.log(`${m.id} ${outcome.verdict.padEnd(8)} ${ok ? "as expected" : "UNEXPECTED"}  ${m.what}  [${outcome.summary}]`);
  results.push({ ...m, outcome, ok });
}
// leave the stack as the source is
execFileSync("docker", [...compose, "up", "-d", "--build", "--wait", "--wait-timeout", "600"], { cwd: root, stdio: "ignore" });
dc("restart", "caddy");
const bad = results.filter((r) => !r.ok);
console.log(`\n${results.length} mutants, ${results.filter((r) => r.outcome.verdict === "killed").length} killed, ${results.filter((r) => r.outcome.verdict === "SURVIVED").length} survived, ${bad.length} not as expected`);
process.exit(bad.length ? 1 : 0);
