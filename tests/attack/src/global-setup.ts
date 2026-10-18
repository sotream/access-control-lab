// Brings the prod-like stack up once (with the test-only routes), signs the seed users in once and hands the sessions to the test files, and tears the stack down at the end.
// ATTACK_KEEP=1 leaves it running, ATTACK_NO_UP=1 assumes it is.
import { execFileSync } from "node:child_process";
import type { TestProject } from "vitest/node";
import { bffLogin, otpSteps, SEED_USERS } from "./kc.js";
import { COMPOSE, ROOT, dc } from "./stack.js";

export interface SavedSession {
  cookie: string;
  csrf: string;
  sub: string;
}

declare module "vitest" {
  export interface ProvidedContext {
    sessions: Record<string, SavedSession>;
    otpSteps: Record<string, number>;
  }
}

export default async function setup(project: TestProject) {
  if (process.env.ATTACK_NO_UP !== "1") {
    console.log("attack suite: starting the prod-like stack (first run builds the images)...");
    dc("up", "-d", "--build", "--wait", "--wait-timeout", "900");
    dc("restart", "caddy"); // picks up regenerated bind-mounted files on hosts that keep the old inode
    await new Promise((r) => setTimeout(r, 3000));
  }
  // one sign-in per seed user for the whole run, kept in memory and handed over by the test runner (Keycloak refuses a TOTP step twice, and a sign-in costs seconds)
  const sessions: Record<string, SavedSession> = {};
  for (const user of SEED_USERS) {
    const s = await bffLogin(user);
    sessions[user] = { cookie: s.cookie, csrf: s.csrf, sub: s.sub };
  }
  project.provide("sessions", sessions);
  project.provide("otpSteps", otpSteps());
  return async () => {
    if (process.env.ATTACK_KEEP === "1" || process.env.ATTACK_NO_UP === "1") return;
    execFileSync("docker", [...COMPOSE, "down", "-v"], { cwd: ROOT, stdio: "ignore" });
  };
}
