// The server-side session store against the real Postgres (T-04, T-05, T-21, T-36).
import { randomBytes } from "node:crypto";
import pg from "pg";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { parseKeyRing, sha256 } from "../../../apps/web/src/server/crypto";
import { SessionStore, type TokenSet } from "../../../apps/web/src/server/session-store";
import { TEST_DB, adminPool, appUrl, migratorUrl, withDb } from "../../api-db/src/db.js";

const ring = parseKeyRing(`k1:${randomBytes(32).toString("base64")}`);
const webUrl = withDb(process.env.WEB_DATABASE_URL ?? "", TEST_DB);
const webPool = new pg.Pool({ connectionString: webUrl, max: 8 });
const admin = adminPool();
const opts = { idleSeconds: 1800, absoluteSeconds: 28_800, maxSessionsPerUser: 3 };
const store = new SessionStore(webPool, ring, opts);
const tokens = (n = "a"): TokenSet => ({ accessToken: `access-${n}-${"x".repeat(40)}`, refreshToken: `refresh-${n}-${"y".repeat(40)}`, idToken: `id-${n}-${"z".repeat(40)}`, accessExpiresAt: Math.floor(Date.now() / 1000) + 300 });
const row = async (sid: string) => (await admin.query("SELECT * FROM bff_sessions WHERE sid_hash = $1", [sha256(sid)])).rows[0];

afterAll(async () => {
  await admin.query("DELETE FROM bff_sessions");
  await admin.end();
  await webPool.end();
});
beforeEach(() => admin.query("DELETE FROM bff_sessions"));

describe("storage", () => {
  it("never stores the cookie value or any token in clear; csrf token and key id are recorded", async () => {
    const { sid, session } = await store.create("user-1", tokens());
    const r = await row(sid);
    const dump = JSON.stringify(r) + r.tokens_enc.toString("latin1") + r.tokens_enc.toString("base64");
    for (const secret of [sid, "access-a", "refresh-a", "id-a"]) expect(dump).not.toContain(secret);
    expect(r.sid_hash).toEqual(sha256(sid));
    expect(r.key_id).toBe("k1");
    expect(r.csrf_token).toBe(session.csrfToken);
    expect(sid).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("a stored blob moved to another row does not decrypt (AAD binds it to the row)", async () => {
    const a = await store.create("user-1", tokens("a"));
    const b = await store.create("user-2", tokens("b"));
    const ra = await row(a.sid);
    await admin.query("UPDATE bff_sessions SET tokens_enc = $2 WHERE sid_hash = $1", [sha256(b.sid), ra.tokens_enc]);
    expect(await store.get(b.sid)).toBeUndefined();
    expect(await row(b.sid)).toBeUndefined(); // an undecryptable session is removed
  });

  it("a flipped ciphertext byte means no session", async () => {
    const { sid } = await store.create("user-1", tokens());
    await admin.query("UPDATE bff_sessions SET tokens_enc = set_byte(tokens_enc, 30, get_byte(tokens_enc, 30) # 1) WHERE sid_hash = $1", [sha256(sid)]);
    expect(await store.get(sid)).toBeUndefined();
  });

  it("two sessions never share an id or a csrf token", async () => {
    const a = await store.create("user-1", tokens());
    const b = await store.create("user-1", tokens());
    expect(a.sid).not.toBe(b.sid);
    expect(a.session.csrfToken).not.toBe(b.session.csrfToken);
  });
});

describe("lookup", () => {
  it("returns the tokens for a valid cookie value and nothing for anything else", async () => {
    const { sid } = await store.create("user-1", tokens());
    expect((await store.get(sid))?.tokens.accessToken).toContain("access-a");
    for (const bad of ["", "x", sid.slice(1), `${sid}x`, sid.replace(/.$/, sid.endsWith("A") ? "B" : "A"), "A".repeat(43), "' OR 1=1 --", "../../etc", "\u0000".repeat(43)]) {
      expect(await store.get(bad), bad.slice(0, 12)).toBeUndefined();
    }
  });

  it("idle timeout and absolute lifetime", async () => {
    const { sid } = await store.create("user-1", tokens());
    await admin.query("UPDATE bff_sessions SET idle_expires_at = now() - interval '1 second' WHERE sid_hash = $1", [sha256(sid)]);
    expect(await store.get(sid)).toBeUndefined();
    const b = await store.create("user-1", tokens());
    await admin.query("UPDATE bff_sessions SET expires_at = now() - interval '1 second' WHERE sid_hash = $1", [sha256(b.sid)]);
    expect(await store.get(b.sid)).toBeUndefined();
  });

  it("use slides the idle timeout but never past the absolute lifetime", async () => {
    const { sid } = await store.create("user-1", tokens());
    await admin.query("UPDATE bff_sessions SET idle_expires_at = now() + interval '5 seconds', expires_at = now() + interval '60 seconds' WHERE sid_hash = $1", [sha256(sid)]);
    await store.get(sid);
    const r = await row(sid);
    expect(new Date(r.idle_expires_at).getTime()).toBeGreaterThan(Date.now() + 30_000);
    expect(new Date(r.idle_expires_at).getTime()).toBeLessThanOrEqual(new Date(r.expires_at).getTime());
  });
});

describe("limits and revocation", () => {
  it("at most N sessions per user: the oldest go first; other users are untouched", async () => {
    const other = await store.create("user-2", tokens("o"));
    const sids: string[] = [];
    for (let i = 0; i < 5; i++) sids.push((await store.create("user-1", tokens(String(i)))).sid);
    const alive = await Promise.all(sids.map(async (s) => (await store.get(s)) !== undefined));
    expect(alive).toEqual([false, false, true, true, true]);
    expect(await store.get(other.sid)).toBeDefined();
  });

  it("concurrent logins of one user still respect the cap", async () => {
    await Promise.all(Array.from({ length: 10 }, (_, i) => store.create("user-1", tokens(String(i)))));
    const n = (await admin.query("SELECT count(*)::int AS n FROM bff_sessions WHERE user_sub = 'user-1'")).rows[0].n;
    expect(n).toBe(3);
  });

  it("destroy and destroyAllForUser", async () => {
    const a = await store.create("user-1", tokens());
    const b = await store.create("user-1", tokens());
    const c = await store.create("user-2", tokens());
    await store.destroy(a.sid);
    expect(await store.get(a.sid)).toBeUndefined();
    expect(await store.destroyAllForUser("user-1")).toBe(1);
    expect(await store.get(b.sid)).toBeUndefined();
    expect(await store.get(c.sid)).toBeDefined();
  });
});

describe("refresh under a per-session lock (T-21)", () => {
  const stale = (): TokenSet => ({ ...tokens(), accessExpiresAt: Math.floor(Date.now() / 1000) - 5 });
  const needs = (t: TokenSet) => t.accessExpiresAt - Math.floor(Date.now() / 1000) < 30;

  it("six concurrent requests cause exactly one refresh; all see the new tokens", async () => {
    const { sid } = await store.create("user-1", stale());
    let calls = 0;
    const results = await Promise.all(
      Array.from({ length: 6 }, () =>
        store.withRefresh(sid, needs, async () => {
          calls++;
          await new Promise((r) => setTimeout(r, 100));
          return tokens("new");
        }),
      ),
    );
    expect(calls).toBe(1);
    for (const r of results) expect(r?.tokens.accessToken).toContain("access-new");
    expect((await store.get(sid))?.tokens.refreshToken).toContain("refresh-new");
  });

  it("a fresh token is not refreshed at all", async () => {
    const { sid } = await store.create("user-1", tokens());
    let calls = 0;
    await store.withRefresh(sid, needs, async () => (calls++, tokens("new")));
    expect(calls).toBe(0);
  });

  it("a refused refresh (expired, revoked, REUSED) destroys the session", async () => {
    const { sid } = await store.create("user-1", stale());
    const r = await store.withRefresh(sid, needs, async () => {
      throw new Error("invalid_grant");
    });
    expect(r).toBeUndefined();
    expect(await row(sid)).toBeUndefined();
  });

  it("unknown, expired or malformed session ids refresh nothing", async () => {
    let calls = 0;
    for (const sid of ["", "nope", "A".repeat(43)]) expect(await store.withRefresh(sid, needs, async () => (calls++, tokens()))).toBeUndefined();
    expect(calls).toBe(0);
  });
});

describe("database isolation (T-15, T-37)", () => {
  it("the web role sees sessions and nothing else; the API role sees no sessions", async () => {
    await store.create("user-1", tokens());
    await expect(webPool.query("SELECT * FROM case_files")).rejects.toMatchObject({ code: "42501" });
    await expect(webPool.query("SELECT * FROM role_grants")).rejects.toMatchObject({ code: "42501" });
    await expect(webPool.query("DROP TABLE bff_sessions")).rejects.toMatchObject({ code: "42501" });
    await expect(webPool.query("TRUNCATE bff_sessions")).rejects.toMatchObject({ code: "42501" });
    await expect(webPool.query("ALTER TABLE bff_sessions DISABLE ROW LEVEL SECURITY")).rejects.toMatchObject({ code: "42501" });
    const app = new pg.Client({ connectionString: appUrl() });
    await app.connect();
    await expect(app.query("SELECT * FROM bff_sessions")).rejects.toMatchObject({ code: "42501" });
    await app.end();
    const mig = new pg.Client({ connectionString: migratorUrl() });
    await mig.connect();
    expect((await mig.query("SELECT count(*)::int AS n FROM bff_sessions")).rows[0].n).toBe(1); // the owner can, the app roles cannot
    await mig.end();
  });

  it("role attributes: not superuser, no BYPASSRLS, bounded", async () => {
    const r = (await admin.query("SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolconnlimit FROM pg_roles WHERE rolname = 'casefile_web'")).rows[0];
    expect(r).toEqual({ rolsuper: false, rolbypassrls: false, rolcreatedb: false, rolcreaterole: false, rolconnlimit: 25 });
  });
});
