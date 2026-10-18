import { Injectable } from "@nestjs/common";
import type { Tx } from "./context.js";
import { sql } from "./sql.js";

export interface AttachmentRow {
  id: string;
  caseFileId: string;
  displayName: string;
  mediaType: string;
  sizeBytes: number;
  sha256: string;
  storageKey: string;
  status: "pending" | "clean" | "quarantined";
  scanDetail: string | null;
  uploadedById: string;
  createdAt: Date;
  scannedAt: Date | null;
}

interface Db {
  id: string;
  case_file_id: string;
  display_name: string;
  media_type: string;
  size_bytes: number;
  sha256: Buffer;
  storage_key: string;
  status: AttachmentRow["status"];
  scan_detail: string | null;
  uploaded_by_id: string;
  created_at: Date;
  scanned_at: Date | null;
}

const map = (r: Db): AttachmentRow => ({
  id: r.id,
  caseFileId: r.case_file_id,
  displayName: r.display_name,
  mediaType: r.media_type,
  sizeBytes: r.size_bytes,
  sha256: r.sha256.toString("hex"),
  storageKey: r.storage_key,
  status: r.status,
  scanDetail: r.scan_detail,
  uploadedById: r.uploaded_by_id,
  createdAt: r.created_at,
  scannedAt: r.scanned_at,
});

const INSERT = sql`INSERT INTO attachments (case_file_id, display_name, media_type, size_bytes, sha256, storage_key, uploaded_by_id)
  VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, case_file_id, display_name, media_type, size_bytes, sha256, storage_key, status, scan_detail, uploaded_by_id, created_at, scanned_at`;
const LIST = sql`SELECT id, case_file_id, display_name, media_type, size_bytes, sha256, storage_key, status, scan_detail, uploaded_by_id, created_at, scanned_at
  FROM attachments WHERE case_file_id = $1 ORDER BY created_at, id LIMIT 100`;
// the attachment must belong to the case file in the path: an id of another file's attachment is simply not found (no IDOR, no existence oracle)
const GET = sql`SELECT id, case_file_id, display_name, media_type, size_bytes, sha256, storage_key, status, scan_detail, uploaded_by_id, created_at, scanned_at
  FROM attachments WHERE id = $1 AND case_file_id = $2`;
const VERDICT = sql`UPDATE attachments SET status = $2::attachment_status, scan_detail = $3, scanned_at = now() WHERE id = $1 AND status = 'pending'
  RETURNING id, case_file_id, display_name, media_type, size_bytes, sha256, storage_key, status, scan_detail, uploaded_by_id, created_at, scanned_at`;

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

@Injectable()
export class AttachmentRepository {
  async insert(tx: Tx, v: { caseFileId: string; displayName: string; mediaType: string; sizeBytes: number; sha256: Buffer; storageKey: string; uploadedById: string }): Promise<AttachmentRow> {
    return map((await tx.query<Db>(INSERT, [v.caseFileId, v.displayName, v.mediaType, v.sizeBytes, v.sha256, v.storageKey, v.uploadedById])).rows[0] as Db);
  }
  async list(tx: Tx, caseFileId: string): Promise<AttachmentRow[]> {
    return (await tx.query<Db>(LIST, [caseFileId])).rows.map(map);
  }
  async get(tx: Tx, id: string, caseFileId: string): Promise<AttachmentRow | undefined> {
    if (!UUID_RE.test(id) || !UUID_RE.test(caseFileId)) return undefined;
    const r = (await tx.query<Db>(GET, [id, caseFileId])).rows[0];
    return r ? map(r) : undefined;
  }
  async setVerdict(tx: Tx, id: string, status: "clean" | "quarantined", detail: string): Promise<AttachmentRow | undefined> {
    const r = (await tx.query<Db>(VERDICT, [id, status, detail])).rows[0];
    return r ? map(r) : undefined;
  }
}
