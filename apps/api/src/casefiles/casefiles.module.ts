import { Inject, Injectable, type OnModuleDestroy, type Provider, type Type } from "@nestjs/common";
import type pg from "pg";
import { CaseFileRepository } from "../db/case-file.repository.js";
import { assertSafeRole, createPool } from "../db/pool.js";
import type { AppConfig } from "../config.js";
import { parseAuditKeys } from "@acl/audit";
import { AUDIT_KEYS, AUDIT_WRITER, PgAuditWriter } from "../audit/audit.js";
import { AuditLogController } from "../audit/audit-log.controller.js";
import { AuditLogService } from "../audit/audit-log.service.js";
import { CheckpointService } from "../audit/checkpoint.js";
import { ExistingCaseFileLoader, NewCaseFileLoader } from "./case-file.loaders.js";
import { CaseFilesController } from "./case-file.controller.js";
import { DB_POOL } from "../db/tokens.js";
import { CaseFileService } from "./case-file.service.js";
import { AttachmentRepository } from "../db/attachment.repository.js";
import { AttachmentsController } from "../attachments/attachment.controller.js";
import { AttachmentService } from "../attachments/attachment.service.js";
import { ClamdScanner, SCANNER, StubScanner } from "../attachments/scanner.js";
import { AttachmentStore } from "../attachments/storage.js";

@Injectable()
class PoolLifecycle implements OnModuleDestroy {
  constructor(@Inject(DB_POOL) private readonly pool: pg.Pool) {}
  async onModuleDestroy() {
    await this.pool.end();
  }
}

/** Controllers and providers of the data layer. Mounted only when DATABASE_URL is configured. */
export function dataLayer(cfg: AppConfig): { controllers: Type[]; providers: Provider[] } {
  if (!cfg.databaseUrl) return { controllers: [], providers: [] };
  const url = cfg.databaseUrl;
  return {
    controllers: [CaseFilesController, AttachmentsController, AuditLogController],
    providers: [
      {
        provide: DB_POOL,
        useFactory: async () => {
          const pool = createPool({ connectionString: url, max: cfg.dbPoolMax });
          await assertSafeRole(pool); // refuse to start as superuser, BYPASSRLS or table owner
          return pool;
        },
      },
      PoolLifecycle,
      { provide: AUDIT_KEYS, useValue: parseAuditKeys(cfg.auditKeys as string) },
      PgAuditWriter,
      { provide: AUDIT_WRITER, useExisting: PgAuditWriter },
      CheckpointService,
      AuditLogService,
      CaseFileRepository,
      AttachmentRepository,
      AttachmentStore,
      AttachmentService,
      { provide: SCANNER, useClass: cfg.attachmentScanner === "clamd" ? ClamdScanner : StubScanner },
      CaseFileService,
      ExistingCaseFileLoader,
      NewCaseFileLoader,
    ],
  };
}
