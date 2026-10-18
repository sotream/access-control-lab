import pg from "pg";
import { config } from "./config";
import { parseKeyRing } from "./crypto";
import { SessionStore } from "./session-store";

const g = globalThis as unknown as { __casefilePool?: pg.Pool; __casefileStore?: SessionStore };

/** One pool and one store per process (also across dev reloads). Connects as casefile_web: it can only touch bff_sessions. */
export function sessionStore(): SessionStore {
  if (!g.__casefileStore) {
    const c = config();
    g.__casefilePool ??= new pg.Pool({ connectionString: c.databaseUrl, max: 10, connectionTimeoutMillis: 5000, idleTimeoutMillis: 30_000, application_name: "casefile-web" });
    g.__casefilePool.on("error", () => undefined);
    g.__casefileStore = new SessionStore(g.__casefilePool, parseKeyRing(c.keyRing), { idleSeconds: c.idleSeconds, absoluteSeconds: c.absoluteSeconds, maxSessionsPerUser: c.maxSessionsPerUser });
  }
  return g.__casefileStore;
}
