// Logged-in browser sessions for the seed users, cached on disk while the stack lives (Keycloak refuses a TOTP step twice, and a login costs seconds).
// Tests that END a session (logout, replay, fixation) never use these: they log in themselves.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Jar, vault } from "./http.js";
import { bffLogin, type BffSession } from "./kc.js";

const DIR = new URL("../.cache/", import.meta.url).pathname;
const FILE = join(DIR, "sessions.json");
type Saved = Record<string, { cookie: string; csrf: string; sub: string }>;
const read = (): Saved => {
  try {
    return JSON.parse(readFileSync(FILE, "utf8")) as Saved;
  } catch {
    return {};
  }
};

const live = new Map<string, BffSession>();

export async function session(user: string): Promise<BffSession> {
  const hit = live.get(user);
  if (hit) return hit;
  const saved = read()[user];
  if (saved) {
    const jar = new Jar();
    jar.cookies.set("__Host-casefile_session", saved.cookie);
    const r = await vault("/api/auth/session", { jar });
    if ((r.json as { authenticated?: boolean } | undefined)?.authenticated) {
      const s = { user, jar, csrf: saved.csrf, cookie: saved.cookie, sub: saved.sub };
      live.set(user, s);
      return s;
    }
  }
  const s = await bffLogin(user);
  mkdirSync(DIR, { recursive: true });
  writeFileSync(FILE, JSON.stringify({ ...read(), [user]: { cookie: s.cookie, csrf: s.csrf, sub: s.sub } }), { mode: 0o600 });
  live.set(user, s);
  return s;
}

/** a test ended this user's sessions (logout kills all of them): forget the cached one so the next test signs in again */
export function forget(user: string): void {
  live.delete(user);
  const all = read();
  delete all[user];
  mkdirSync(DIR, { recursive: true });
  writeFileSync(FILE, JSON.stringify(all), { mode: 0o600 });
}

/** same-origin JSON call through the BFF proxy, as the page scripts would make it */
export function bff(s: BffSession, method: string, path: string, body?: unknown, extra: Record<string, string> = {}) {
  return vault(`/bff${path}`, {
    method,
    jar: s.jar,
    headers: { origin: "https://vault.localhost", "sec-fetch-site": "same-origin", ...(method === "GET" ? {} : { "x-csrf-token": s.csrf, "content-type": "application/json" }), ...extra },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
