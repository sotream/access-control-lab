#!/usr/bin/env node
// Regenerates docs/screenshots/*.png from a FRESH prod-like stack, so the images show the demo data of tests/e2e/src/screenshots.spec.ts and nothing
// left over from other suites. Starts the stack, renders, tears it down (volumes included). Needs Docker and `pnpm install`.
import { execFileSync } from "node:child_process";

const root = new URL("../", import.meta.url).pathname;
const compose = ["compose", "-f", "docker-compose.prod-like.yml", "-f", "docker-compose.prod-like.test.yml"];
const run = (cmd, args, env = {}) => execFileSync(cmd, args, { cwd: root, stdio: "inherit", env: { ...process.env, ...env } });

run("node", ["scripts/prod-like-setup.mjs"]); // creates the throw-away secrets and certificates once; leaves existing ones alone
run("docker", [...compose, "down", "-v"]);
try {
  run("docker", [...compose, "up", "-d", "--build", "--wait", "--wait-timeout", "900"]);
  run("docker", [...compose, "restart", "caddy"]); // picks up regenerated bind-mounted files on hosts that keep the old inode
  run("pnpm", ["--filter", "@acl/e2e-tests", "screenshots:render"]);
} finally {
  run("docker", [...compose, "down", "-v"]);
}
console.log("docs/screenshots regenerated");
