import { createHash } from "node:crypto";
import { HttpException, Inject, Injectable, NotFoundException, PayloadTooLargeException, ServiceUnavailableException, UnprocessableEntityException, UnsupportedMediaTypeException } from "@nestjs/common";
import type { AuditEntry } from "@acl/audit";
import { AUDIT_WRITER, type AuditWriter } from "../audit/audit.js";
import { CaseFileService, type Caller } from "../casefiles/case-file.service.js";
import { CONFIG, type AppConfig } from "../config.js";
import { AttachmentRepository, UUID_RE, type AttachmentRow } from "../db/attachment.repository.js";
import { JsonLogger } from "../http/logger.js";
import { LOGGER } from "../policy/policy.enforcer.js";
import { MEDIA_TYPE, inspect, safeName, type Media } from "./content.js";
import { SCANNER, type Scanner } from "./scanner.js";
import { AttachmentStore } from "./storage.js";

export interface AttachmentView {
  id: string;
  name: string;
  mediaType: string;
  size: number;
  sha256: string;
  status: AttachmentRow["status"];
  uploadedBy: string;
  createdAt: string;
}

const view = (r: AttachmentRow): AttachmentView => ({ id: r.id, name: r.displayName, mediaType: r.mediaType, size: r.sizeBytes, sha256: r.sha256, status: r.status, uploadedBy: r.uploadedById, createdAt: r.createdAt.toISOString() });
const MEDIA_OF: Readonly<Record<string, Media>> = { "application/pdf": "pdf", "image/png": "png", "image/jpeg": "jpeg", "text/plain": "text" };

/**
 * Upload: inspect (bytes decide, not the name or the declared type) -> audit row -> bytes into quarantine -> metadata row (RLS: the caller may update the
 * parent draft) -> scan -> audit row -> verdict. Only `clean` is downloadable; a scanner that errors or times out leaves the file pending (fail closed).
 * Download: same visibility as the parent case file (RLS + the policy decision on the parent), audit row BEFORE the bytes leave.
 */
@Injectable()
export class AttachmentService {
  constructor(
    @Inject(CaseFileService) private readonly files: CaseFileService,
    @Inject(AttachmentRepository) private readonly repo: AttachmentRepository,
    @Inject(AttachmentStore) private readonly store: AttachmentStore,
    @Inject(SCANNER) private readonly scanner: Scanner,
    @Inject(AUDIT_WRITER) private readonly audit: AuditWriter,
    @Inject(LOGGER) private readonly logger: JsonLogger,
    @Inject(CONFIG) private readonly cfg: AppConfig,
  ) {}

  private entry(c: Caller, action: string, resourceId: string | null, effect: "allow" | "deny", reason: string, details: AuditEntry["details"]): AuditEntry {
    return { actorSub: c.subject.id, actorRoles: c.subject.roles.slice(0, 16), action, resourceType: "attachment", resourceId, effect, reasonCode: reason, obligations: effect === "allow" ? ["audit"] : [], requestId: c.reqId, source: "api", details };
  }

  /** fail closed: no audit row, no action */
  private async must(e: AuditEntry): Promise<void> {
    try {
      await this.audit.append(e);
    } catch {
      throw new ServiceUnavailableException();
    }
  }

  /** a refusal is already a safe outcome: record it if possible, never let the audit failure change the answer */
  private async tryAudit(e: AuditEntry): Promise<void> {
    try {
      await this.audit.append(e);
    } catch {
      this.logger.event("error", "audit_write_failed", { reqId: e.requestId, sub: e.actorSub, action: e.action, effect: e.effect });
    }
  }

  async upload(c: Caller, caseFileId: string, bytes: Buffer, declaredType: string | undefined, rawName: string | undefined): Promise<AttachmentView> {
    const verdict = inspect(bytes, declaredType, this.cfg.attachmentMaxBytes);
    if (!verdict.ok) {
      await this.tryAudit(this.entry(c, "attachment.rejected", caseFileId, "deny", verdict.code, { size: Math.min(bytes.length, 1_073_741_824), detail_code: verdict.code }));
      if (verdict.code === "TOO_LARGE") throw new PayloadTooLargeException();
      if (verdict.code === "UNSUPPORTED_TYPE" || verdict.code === "MEDIA_MISMATCH") throw new UnsupportedMediaTypeException();
      throw new UnprocessableEntityException();
    }
    const media = verdict.media;
    const sha = createHash("sha256").update(bytes).digest();
    const key = this.store.newKey();
    const name = safeName(rawName, media);

    // audit first: the upload is allowed to start only if its row exists
    await this.must(this.entry(c, "attachment.upload", caseFileId, "allow", "UPLOADED", { size: bytes.length, sha256: sha.toString("hex"), media }));
    await this.store.putQuarantined(key, bytes);

    let row: AttachmentRow;
    try {
      row = await this.files.guarded(c, "update", caseFileId, (tx) => this.repo.insert(tx, { caseFileId, displayName: name, mediaType: MEDIA_TYPE[media], sizeBytes: bytes.length, sha256: sha, storageKey: key, uploadedById: c.subject.id }));
    } catch (e) {
      await this.store.discardQuarantined(key).catch(() => undefined);
      throw e;
    }

    let result: Awaited<ReturnType<Scanner["scan"]>>;
    try {
      result = await this.scanner.scan(bytes);
    } catch {
      this.logger.event("error", "attachment_scan_unavailable", { reqId: c.reqId, sub: c.subject.id, attachmentId: row.id });
      await this.tryAudit(this.entry(c, "attachment.scan", row.id, "deny", "SCAN_UNAVAILABLE", { scan: "UNAVAILABLE" }));
      throw new ServiceUnavailableException(); // stays pending, never downloadable
    }

    if (result.verdict === "infected") {
      await this.tryAudit(this.entry(c, "attachment.scan", row.id, "deny", "QUARANTINED", { scan: "INFECTED", detail_code: result.signature }));
      await this.files.guarded(c, "update", caseFileId, (tx) => this.repo.setVerdict(tx, row.id, "quarantined", result.verdict === "infected" ? result.signature : "INFECTED"));
      throw new UnprocessableEntityException();
    }
    await this.must(this.entry(c, "attachment.scan", row.id, "allow", "CLEAN", { scan: "CLEAN" }));
    await this.store.promote(key);
    const done = await this.files.guarded(c, "update", caseFileId, (tx) => this.repo.setVerdict(tx, row.id, "clean", "CLEAN"));
    if (!done) throw new ServiceUnavailableException();
    return view(done);
  }

  list(c: Caller, caseFileId: string): Promise<AttachmentView[]> {
    return this.files.guarded(c, "read", caseFileId, async (tx) => (await this.repo.list(tx, caseFileId)).map(view));
  }

  async download(c: Caller, caseFileId: string, id: string): Promise<{ bytes: Buffer; name: string; mediaType: string }> {
    const row = await this.files.guarded(c, "read", caseFileId, (tx, parent) => this.repo.get(tx, id, parent.id));
    if (!row || !UUID_RE.test(id)) throw new NotFoundException();
    if (row.status !== "clean") throw new HttpException("Conflict", 409); // pending or quarantined: visible in the list, never served
    await this.must(this.entry(c, "attachment.download", row.id, "allow", "DOWNLOADED", { size: row.sizeBytes, sha256: row.sha256, media: MEDIA_OF[row.mediaType] ?? "text" }));
    const bytes = await this.store.read(row.storageKey);
    // the stored hash is checked on the way out: a file changed on disk is not served
    if (createHash("sha256").update(bytes).digest("hex") !== row.sha256) {
      this.logger.event("error", "attachment_hash_mismatch", { reqId: c.reqId, attachmentId: row.id });
      throw new ServiceUnavailableException();
    }
    return { bytes, name: row.displayName, mediaType: row.mediaType };
  }
}
