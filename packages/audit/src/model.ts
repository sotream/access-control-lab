/** Chain format version. It is part of every hashed record, so a record can never be re-labelled as another format. */
export const CHAIN_VERSION = "acl-audit/v1";
export const CHECKPOINT_VERSION = "acl-audit-checkpoint/v1";

/** SHA-256 of the ASCII string `acl-audit/v1 genesis`: the `prev_hash` of the first row (id 1). Fixed, public, not secret. */
export const GENESIS_HASH_HEX = "4c28ebab5bc198ff48266a7625eaaeddd4f860656eaa34dd2f89b8579441a465";

export type Effect = "allow" | "deny";
export type Source = "api" | "bff";

/** What a writer supplies. Everything else (id, hash links, key id) is assigned by the chain. */
export interface AuditEntry {
  actorSub: string;
  actorRoles: readonly string[];
  action: string;
  resourceType: string;
  resourceId: string | null;
  effect: Effect;
  reasonCode: string;
  obligations: readonly string[];
  requestId: string;
  source: Source;
  details: Readonly<Record<string, unknown>>;
}

export interface AuditRow extends AuditEntry {
  /** assigned by the chain: 1, 2, 3, ... with no gaps (not a database identity column: sequences leave gaps on rollback) */
  id: number;
  /** millisecond precision, UTC */
  ts: Date;
  prevHash: Buffer;
  keyId: string;
  hash: Buffer;
}

export interface Head {
  lastId: number;
  lastHash: Buffer;
}

export interface Checkpoint {
  id?: number;
  ts: Date;
  lastId: number;
  lastHash: Buffer;
  keyId: string;
  mac: Buffer;
}
