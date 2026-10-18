// Logged-in browser sessions for the seed users: one sign-in per user for the whole run (global-setup.ts), handed to every test file by the runner.
// Tests that END a session (logout, replay, fixation) never use these: they log in themselves, as a user nothing else depends on or ends the shared one on purpose (forget).
import { inject } from "vitest";
import { Jar, vault } from "./http.js";
import { bffLogin, type BffSession } from "./kc.js";

const COOKIE = "__Host-casefile_session";
const mine = new Map<string, BffSession>();

export async function session(user: string): Promise<BffSession> {
  const known = mine.get(user);
  if (known) return known;
  const saved = inject("sessions")[user];
  if (saved) {
    const jar = new Jar();
    jar.cookies.set(COOKIE, saved.cookie);
    const r = await vault("/api/auth/session", { jar });
    if ((r.json as { authenticated?: boolean } | undefined)?.authenticated) {
      const s = { user, jar, csrf: saved.csrf, cookie: saved.cookie, sub: saved.sub };
      mine.set(user, s);
      return s;
    }
  }
  const s = await bffLogin(user); // a test ended the shared session: sign in again
  mine.set(user, s);
  return s;
}

/** a test ended this user's sessions (a logout kills all of them): the next call signs in again */
export function forget(user: string): void {
  mine.delete(user);
  const shared = inject("sessions");
  delete shared[user];
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
