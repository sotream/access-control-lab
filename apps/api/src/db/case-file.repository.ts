import type { Resource } from "@acl/policy";
import type { Tx } from "./context.js";
import { sql } from "./sql.js";

export interface CaseFileRow {
  id: string;
  title: string;
  body: string;
  classification: string;
  unit: string;
  compartments: string[];
  status: string;
  authorId: string;
  submittedById: string | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
}

interface DbRow {
  id: string;
  title: string;
  body: string;
  classification: string;
  unit: string;
  compartments: string[];
  status: string;
  author_id: string;
  submitted_by_id: string | null;
  version: number;
  created_at: Date;
  updated_at: Date;
}

const map = (r: DbRow): CaseFileRow => ({
  id: r.id,
  title: r.title,
  body: r.body,
  classification: r.classification,
  unit: r.unit,
  compartments: r.compartments,
  status: r.status,
  authorId: r.author_id,
  submittedById: r.submitted_by_id,
  version: r.version,
  createdAt: r.created_at,
  updatedAt: r.updated_at,
});

export const toResource = (r: CaseFileRow): Resource => ({
  id: r.id,
  classification: r.classification,
  ownerUnit: r.unit,
  compartments: r.compartments,
  status: r.status,
  authorId: r.authorId,
  submittedById: r.submittedById,
});

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const SELECT_ONE = sql`SELECT id, title, body, classification::text AS classification, unit, compartments, status::text AS status,
  author_id, submitted_by_id, version, created_at, updated_at FROM case_files WHERE id = $1`;
const SELECT_ONE_LOCK = sql`SELECT id, title, body, classification::text AS classification, unit, compartments, status::text AS status,
  author_id, submitted_by_id, version, created_at, updated_at FROM case_files WHERE id = $1 FOR UPDATE`;
const SELECT_ALL = sql`SELECT id, title, body, classification::text AS classification, unit, compartments, status::text AS status,
  author_id, submitted_by_id, version, created_at, updated_at FROM case_files ORDER BY created_at, id LIMIT $1`;
const INSERT = sql`INSERT INTO case_files (title, body, classification, unit, compartments, author_id, status)
  VALUES ($1, $2, $3::classification, $4, $5::text[], $6, 'draft')
  RETURNING id, title, body, classification::text AS classification, unit, compartments, status::text AS status,
  author_id, submitted_by_id, version, created_at, updated_at`;
// optimistic check on top of the row lock: the version the decision was made on
const UPDATE_TEXT = sql`UPDATE case_files SET title = $2, body = $3 WHERE id = $1 AND version = $4
  RETURNING id, title, body, classification::text AS classification, unit, compartments, status::text AS status,
  author_id, submitted_by_id, version, created_at, updated_at`;
const UPDATE_STATUS = sql`UPDATE case_files SET status = $2::case_status WHERE id = $1 AND version = $3
  RETURNING id, title, body, classification::text AS classification, unit, compartments, status::text AS status,
  author_id, submitted_by_id, version, created_at, updated_at`;
const DELETE = sql`DELETE FROM case_files WHERE id = $1 AND version = $2`;

/** Every method assumes `tx` carries the request context (withContext). All values travel as parameters. */
export class CaseFileRepository {
  /** Visible to the caller under row-level security, or undefined. */
  async get(tx: Tx, id: string): Promise<CaseFileRow | undefined> {
    if (!UUID.test(id)) return undefined;
    const r = await tx.query<DbRow>(SELECT_ONE, [id]);
    return r.rows[0] ? map(r.rows[0]) : undefined;
  }

  /** Locks the row if the UPDATE policy lets the caller see it for update; undefined otherwise. */
  async lock(tx: Tx, id: string): Promise<CaseFileRow | undefined> {
    if (!UUID.test(id)) return undefined;
    const r = await tx.query<DbRow>(SELECT_ONE_LOCK, [id]);
    return r.rows[0] ? map(r.rows[0]) : undefined;
  }

  async list(tx: Tx, limit: number): Promise<CaseFileRow[]> {
    return (await tx.query<DbRow>(SELECT_ALL, [limit])).rows.map(map);
  }

  async insert(tx: Tx, v: { title: string; body: string; classification: string; unit: string; compartments: readonly string[]; authorId: string }): Promise<CaseFileRow> {
    const r = await tx.query<DbRow>(INSERT, [v.title, v.body, v.classification, v.unit, [...v.compartments], v.authorId]);
    return map(r.rows[0] as DbRow);
  }

  async updateText(tx: Tx, id: string, title: string, body: string, version: number): Promise<CaseFileRow | undefined> {
    const r = await tx.query<DbRow>(UPDATE_TEXT, [id, title, body, version]);
    return r.rows[0] ? map(r.rows[0]) : undefined;
  }

  async updateStatus(tx: Tx, id: string, status: "submitted" | "approved", version: number): Promise<CaseFileRow | undefined> {
    const r = await tx.query<DbRow>(UPDATE_STATUS, [id, status, version]);
    return r.rows[0] ? map(r.rows[0]) : undefined;
  }

  async delete(tx: Tx, id: string, version: number): Promise<boolean> {
    return (await tx.query(DELETE, [id, version])).rowCount === 1;
  }
}
