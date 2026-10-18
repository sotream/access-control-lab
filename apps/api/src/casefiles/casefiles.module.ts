import { Inject, Injectable, type OnModuleDestroy, type Provider, type Type } from "@nestjs/common";
import type pg from "pg";
import { CaseFileRepository } from "../db/case-file.repository.js";
import { assertSafeRole, createPool } from "../db/pool.js";
import type { AppConfig } from "../config.js";
import { ExistingCaseFileLoader, NewCaseFileLoader } from "./case-file.loaders.js";
import { CaseFilesController } from "./case-file.controller.js";
import { CaseFileService, DB_POOL } from "./case-file.service.js";

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
    controllers: [CaseFilesController],
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
      CaseFileRepository,
      CaseFileService,
      ExistingCaseFileLoader,
      NewCaseFileLoader,
    ],
  };
}
