// Brings the prod-like stack up once (with the test-only routes) and tears it down at the end. ATTACK_KEEP=1 leaves it running, ATTACK_NO_UP=1 assumes it is.
import { execFileSync } from "node:child_process";
import { COMPOSE, ROOT, dc } from "./stack.js";

export default async function setup() {
  if (process.env.ATTACK_NO_UP !== "1") {
    console.log("attack suite: starting the prod-like stack (first run builds the images)...");
    dc("up", "-d", "--build", "--wait", "--wait-timeout", "900");
    dc("restart", "caddy"); // picks up regenerated bind-mounted files on hosts that keep the old inode
    await new Promise((r) => setTimeout(r, 3000));
  }
  return async () => {
    if (process.env.ATTACK_KEEP === "1" || process.env.ATTACK_NO_UP === "1") return;
    execFileSync("docker", [...COMPOSE, "down", "-v"], { cwd: ROOT, stdio: "ignore" });
  };
}
