import type pg from "pg";
import { decrypt, encrypt, randomToken, sha256, type KeyRing } from "./crypto";

export interface TokenSet {
  accessToken: string;
  refreshToken: string;
  idToken: string;
  /** seconds since epoch */
  accessExpiresAt: number;
}

export interface Session {
  /** sha256 of the cookie value: the database key; the cookie value itself is never stored or logged */
  sidHash: Buffer;
  userSub: string;
  csrfToken: string;
  tokens: TokenSet;
  createdAt: Date;
  expiresAt: Date;
}

export interface StoreOptions {
  idleSeconds: number;
  absoluteSeconds: number;
  maxSessionsPerUser: number;
}

interface Row {
  sid_hash: Buffer;
  user_sub: string;
  csrf_token: string;
  tokens_enc: Buffer;
  key_id: string;
  created_at: Date;
  expires_at: Date;
}

const SELECT_LIVE = "SELECT sid_hash, user_sub, csrf_token, tokens_enc, key_id, created_at, expires_at FROM bff_sessions WHERE sid_hash = $1 AND expires_at > now() AND idle_expires_at > now()";
const SELECT_LIVE_LOCK = SELECT_LIVE + " FOR UPDATE";
const INSERT = "INSERT INTO bff_sessions (sid_hash, user_sub, csrf_token, tokens_enc, key_id, expires_at, idle_expires_at) VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6), now() + make_interval(secs => $7))";
const TOUCH = "UPDATE bff_sessions SET last_seen_at = now(), idle_expires_at = LEAST(expires_at, now() + make_interval(secs => $2)) WHERE sid_hash = $1";
const UPDATE_TOKENS = "UPDATE bff_sessions SET tokens_enc = $2, key_id = $3 WHERE sid_hash = $1";
const DELETE_ONE = "DELETE FROM bff_sessions WHERE sid_hash = $1";
const DELETE_USER = "DELETE FROM bff_sessions WHERE user_sub = $1";
const DELETE_EXPIRED = "DELETE FROM bff_sessions WHERE expires_at <= now() OR idle_expires_at <= now()";
// keep the newest N-1 so that, after inserting the new one, there are at most N
const CAP = "DELETE FROM bff_sessions WHERE user_sub = $1 AND sid_hash NOT IN (SELECT sid_hash FROM bff_sessions WHERE user_sub = $1 ORDER BY created_at DESC, sid_hash LIMIT $2)";

/**
 * Server-side sessions in Postgres (role casefile_web). Tokens are AES-256-GCM encrypted with the row's key hash as AAD.
 * No SQL here is built from values: everything is a $n parameter.
 */
export class SessionStore {
  constructor(
    private readonly pool: pg.Pool,
    private readonly ring: KeyRing,
    private readonly opts: StoreOptions,
  ) {}

  private seal(sidHash: Buffer, tokens: TokenSet) {
    return encrypt(this.ring, Buffer.from(JSON.stringify(tokens)), sidHash);
  }

  private open(row: Row): Session | undefined {
    try {
      const tokens = JSON.parse(decrypt(this.ring, row.key_id, row.tokens_enc, row.sid_hash).toString("utf8")) as TokenSet;
      if (typeof tokens.accessToken !== "string" || typeof tokens.refreshToken !== "string" || typeof tokens.accessExpiresAt !== "number") return undefined;
      return { sidHash: row.sid_hash, userSub: row.user_sub, csrfToken: row.csrf_token, tokens, createdAt: row.created_at, expiresAt: row.expires_at };
    } catch {
      return undefined; // tampered or undecryptable: treated as no session
    }
  }

  /** New session with a fresh random id (the caller sets the cookie). Enforces the per-user cap. */
  async create(userSub: string, tokens: TokenSet): Promise<{ sid: string; session: Session }> {
    const sid = randomToken(32);
    const sidHash = sha256(sid);
    const csrfToken = randomToken(32);
    const sealed = this.seal(sidHash, tokens);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(DELETE_EXPIRED);
      // serialise concurrent logins of one user so the cap holds
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [userSub]);
      await client.query(CAP, [userSub, this.opts.maxSessionsPerUser - 1]);
      await client.query(INSERT, [sidHash, userSub, csrfToken, sealed.data, sealed.keyId, this.opts.absoluteSeconds, Math.min(this.opts.idleSeconds, this.opts.absoluteSeconds)]);
      await client.query("COMMIT");
    } catch (e) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw e;
    } finally {
      client.release();
    }
    return { sid, session: { sidHash, userSub, csrfToken, tokens, createdAt: new Date(), expiresAt: new Date(Date.now() + this.opts.absoluteSeconds * 1000) } };
  }

  /** The live session for a cookie value, sliding the idle timeout. Expired, unknown or undecryptable: undefined. */
  async get(sid: string): Promise<Session | undefined> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(sid)) return undefined; // 32 random bytes in base64url; anything else cannot be ours
    const sidHash = sha256(sid);
    const r = await this.pool.query<Row>(SELECT_LIVE, [sidHash]);
    const row = r.rows[0];
    if (!row) return undefined;
    const s = this.open(row);
    if (!s) {
      await this.pool.query(DELETE_ONE, [sidHash]);
      return undefined;
    }
    await this.pool.query(TOUCH, [sidHash, this.opts.idleSeconds]);
    return s;
  }

  /**
   * Runs `refresh` with the session row locked, so two requests of one session can never refresh at once (a refresh token is single use).
   * Returns the session with current tokens, or undefined if it is gone or the refresh failed (the session is then destroyed).
   */
  async withRefresh(sid: string, needsRefresh: (t: TokenSet) => boolean, refresh: (t: TokenSet) => Promise<TokenSet>, onKilled?: (s: Session) => void): Promise<Session | undefined> {
    if (!/^[A-Za-z0-9_-]{43}$/.test(sid)) return undefined;
    const sidHash = sha256(sid);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const row = (await client.query<Row>(SELECT_LIVE_LOCK, [sidHash])).rows[0];
      if (!row) {
        await client.query("COMMIT");
        return undefined;
      }
      const s = this.open(row);
      if (!s) {
        await client.query(DELETE_ONE, [sidHash]);
        await client.query("COMMIT");
        return undefined;
      }
      if (!needsRefresh(s.tokens)) {
        await client.query("COMMIT");
        return s; // another request refreshed while we waited for the lock
      }
      let fresh: TokenSet;
      try {
        fresh = await refresh(s.tokens);
      } catch {
        await client.query(DELETE_ONE, [sidHash]); // refresh refused (expired, revoked or REUSED): the session ends
        await client.query("COMMIT");
        onKilled?.(s);
        return undefined;
      }
      const sealed = this.seal(sidHash, fresh);
      await client.query(UPDATE_TOKENS, [sidHash, sealed.data, sealed.keyId]);
      await client.query("COMMIT");
      return { ...s, tokens: fresh };
    } catch (e) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw e;
    } finally {
      client.release();
    }
  }

  async destroy(sid: string): Promise<void> {
    if (/^[A-Za-z0-9_-]{43}$/.test(sid)) await this.pool.query(DELETE_ONE, [sha256(sid)]);
  }

  /** logout: every session of the user, in every browser */
  async destroyAllForUser(userSub: string): Promise<number> {
    return (await this.pool.query(DELETE_USER, [userSub])).rowCount ?? 0;
  }
}
