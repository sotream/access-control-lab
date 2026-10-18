// A-97: OWASP ZAP baseline (spider plus passive rules) against the prod-like stack through the proxy, signed in as a normal user, so that the pages behind the login are
// crawled too. Medium and High alerts fail the run unless .zap-allow.json lists them with a reason and an expiry. Slow (minutes): ATTACK_ZAP=1, a separate CI job.
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { session } from "./sessions.js";
import { COMPOSE, ROOT } from "./stack.js";

const IMAGE = "ghcr.io/zaproxy/zaproxy@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6"; // stable, checked 2026-10-18
const OUT = join(new URL("../.cache/zap", import.meta.url).pathname);

interface Alert {
  pluginid: string;
  name: string;
  riskcode: string;
  riskdesc: string;
  instances?: { uri: string }[];
}

describe.skipIf(process.env.ATTACK_ZAP !== "1")("A-97 dynamic scan", () => {
  it("the baseline finds nothing of medium or high risk that is not on the expiring allow-list", async () => {
    const s = await session("unit-admin-alpha");
    mkdirSync(OUT, { recursive: true });
    chmodSync(OUT, 0o777);
    const caddy = spawnSync("docker", [...COMPOSE, "ps", "-q", "caddy"], { cwd: ROOT, encoding: "utf8" }).stdout.trim();
    const ip = spawnSync("docker", ["inspect", "-f", "{{ (index .NetworkSettings.Networks \"casefile-prod-like_edge\").IPAddress }}", caddy], { encoding: "utf8" }).stdout.trim();
    expect(ip).toMatch(/^\d+\.\d+\.\d+\.\d+$/);
    const zapOptions = [
      "-config replacer.full_list(0).description=session",
      "-config replacer.full_list(0).enabled=true",
      "-config replacer.full_list(0).matchtype=REQ_HEADER",
      "-config replacer.full_list(0).matchstr=Cookie",
      "-config replacer.full_list(0).regex=false",
      `-config replacer.full_list(0).replacement=__Host-casefile_session=${s.cookie}`,
    ].join(" ");
    const run = spawnSync("docker", ["run", "--rm", "--network", "casefile-prod-like_edge", "--add-host", `vault.localhost:${ip}`, "-v", `${OUT}:/zap/wrk:rw`, IMAGE, "zap-baseline.py", "-t", "https://vault.localhost/cases", "-J", "report.json", "-r", "report.html", "-I", "-m", "2", "-T", "10", "-z", zapOptions], { cwd: ROOT, encoding: "utf8", timeout: 900_000 });
    console.log(run.stdout.split("\n").filter((l) => /WARN-NEW|FAIL-NEW|PASS|Total|URLs/.test(l)).slice(-60).join("\n"));
    const report = JSON.parse(readFileSync(join(OUT, "report.json"), "utf8")) as { site: { alerts: Alert[] }[] };
    const alerts = report.site.flatMap((x) => x.alerts);
    const allow = (JSON.parse(readFileSync(join(ROOT, ".zap-allow.json"), "utf8")) as { allow: { pluginid: string; expires: string }[] }).allow.filter((a) => Date.parse(a.expires) > Date.now());
    const serious = alerts.filter((a) => Number(a.riskcode) >= 2 && !allow.some((x) => x.pluginid === a.pluginid));
    const low = alerts.filter((a) => Number(a.riskcode) < 2);
    console.log(`ZAP: ${alerts.length} alert(s): ${serious.length} medium or high not allowed, ${low.length} low or informational`);
    for (const a of low) console.log(`  low/info: [${a.pluginid}] ${a.name} (${a.riskdesc})`);
    expect(serious.map((a) => `[${a.pluginid}] ${a.name} (${a.riskdesc}) e.g. ${a.instances?.[0]?.uri}`)).toEqual([]);
    expect(run.status === 0 || run.status === 2, `zap exit ${run.status}: ${run.stderr.slice(-300)}`).toBe(true);
  }, 1_000_000);
});
