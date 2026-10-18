import { Inject, Injectable, type OnApplicationBootstrap, type OnModuleDestroy } from "@nestjs/common";
import { makeCheckpoint, type AuditKeys, type Checkpoint } from "@acl/audit";
import type pg from "pg";
import { CONFIG, type AppConfig } from "../config.js";
import { DB_POOL } from "../db/tokens.js";
import { sql } from "../db/sql.js";
import { JsonLogger } from "../http/logger.js";
import { LOGGER } from "../policy/policy.enforcer.js";
import { AUDIT_KEYS } from "./audit.js";

const HEAD = sql`SELECT last_id, last_hash FROM audit_head WHERE singleton`;
const INSERT = sql`INSERT INTO audit_checkpoints (ts, last_id, last_hash, key_id, mac) VALUES ($1, $2, $3, $4, $5)`;

/**
 * Signed snapshots of the chain head. A checkpoint makes a deleted tail detectable (the chain would end before it). The API writes one on a timer
 * and before every export; `pnpm audit:checkpoint` can write one and save a copy outside the database.
 */
@Injectable()
export class CheckpointService implements OnApplicationBootstrap, OnModuleDestroy {
  private lastCheckpointed = -1;
  private timer: NodeJS.Timeout | undefined;

  constructor(
    @Inject(DB_POOL) private readonly pool: pg.Pool,
    @Inject(AUDIT_KEYS) private readonly keys: AuditKeys,
    @Inject(CONFIG) private readonly cfg: AppConfig,
    @Inject(LOGGER) private readonly logger: JsonLogger,
  ) {}

  /** Writes a checkpoint unless the head has not moved since the last one this process wrote. */
  async writeIfAdvanced(): Promise<Checkpoint | undefined> {
    const h = (await this.pool.query(HEAD)).rows[0];
    if (!h) return undefined;
    const lastId = Number(h.last_id);
    if (lastId === this.lastCheckpointed) return undefined;
    const cp = makeCheckpoint({ lastId, lastHash: h.last_hash as Buffer }, this.keys);
    await this.pool.query(INSERT, [cp.ts, cp.lastId, cp.lastHash, cp.keyId, cp.mac]);
    this.lastCheckpointed = lastId;
    return cp;
  }

  onApplicationBootstrap(): void {
    const every = this.cfg.auditCheckpointSeconds;
    if (every <= 0) return;
    const tick = () => this.writeIfAdvanced().catch(() => this.logger.event("error", "audit_checkpoint_failed", {}));
    void tick();
    this.timer = setInterval(tick, every * 1000);
    this.timer.unref();
  }

  onModuleDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }
}
