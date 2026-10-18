// The stack's generated dev secrets (secrets-dev/ is gitignored): seed password and TOTP secret.
import { readFileSync } from "node:fs";
import { createHmac } from "node:crypto";

const root = new URL("../../../", import.meta.url).pathname;
const kv: Record<string, string> = Object.fromEntries(
  (() => {
    try {
      return readFileSync(`${root}secrets-dev/prod-like/compose.env`, "utf8").split("\n").filter(Boolean).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]);
    } catch {
      return [];
    }
  })(),
);
export const PASSWORD = kv.DEV_USER_PASSWORD ?? "";
const TOTP_SECRET = kv.DEV_TOTP_SECRET ?? "";

export const USERS = ["analyst-official", "analyst-secret-a", "analyst-secret-b", "reviewer", "unit-admin-alpha", "unit-admin-beta", "auditor", "platform-admin"] as const;
export type User = (typeof USERS)[number];
export const authFile = (u: string) => `${new URL("../.auth/", import.meta.url).pathname}${u}.json`;

function totp(at: number, offsetSteps: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30) + offsetSteps));
  const h = createHmac("sha1", Buffer.from(TOTP_SECRET, "utf8")).update(msg).digest();
  const o = h[h.length - 1]! & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}
const lastStep = new Map<string, number>();
/** Keycloak refuses a step it has seen for the user: the first unused step, waiting for the clock when none is left */
export async function nextOtp(user: string): Promise<string> {
  for (;;) {
    const now = Math.floor(Date.now() / 1000 / 30);
    const step = Math.max(now, (lastStep.get(user) ?? 0) + 1);
    if (step <= now + 1) {
      lastStep.set(user, step);
      return totp(Date.now(), step - now);
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
}
