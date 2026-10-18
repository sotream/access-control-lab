import { type DynamicModule, Module, type Provider, type Type } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { AuthFailureLimiter } from "./auth/auth-failure-limiter.js";
import { AuthGuard } from "./auth/auth.guard.js";
import { TokenVerifier } from "./auth/token-verifier.js";
import { AUDIT_WRITER, MemoryAuditWriter } from "./audit/audit.js";
import { dataLayer } from "./casefiles/casefiles.module.js";
import { CONFIG, type AppConfig } from "./config.js";
import { JsonLogger } from "./http/logger.js";
import { CLOCK, type Clock, LOGGER, PolicyEnforcer } from "./policy/policy.enforcer.js";
import { HealthController } from "./health.controller.js";
import { MeController } from "./me.controller.js";

@Module({})
export class AppModule {
  static register(cfg: AppConfig, opts: { logger: JsonLogger; clock?: Clock; controllers?: Type[]; providers?: Provider[] }): DynamicModule {
    const data = dataLayer(cfg);
    return {
      module: AppModule,
      controllers: [HealthController, MeController, ...data.controllers, ...(opts.controllers ?? [])],
      providers: [
        { provide: CONFIG, useValue: cfg },
        TokenVerifier,
        AuthFailureLimiter,
        PolicyEnforcer,
        { provide: LOGGER, useValue: opts.logger },
        { provide: CLOCK, useValue: opts.clock ?? Date.now },
        ...data.providers,
        // without a database there is no chain: an in-memory sink keeps the HTTP-layer tests honest about WHAT is recorded
        ...(cfg.databaseUrl ? [] : [{ provide: AUDIT_WRITER, useClass: MemoryAuditWriter }]),
        ...(opts.providers ?? []),
        // rate limits live in the AuthGuard (per subject after verification, per address before)
        { provide: APP_GUARD, useClass: AuthGuard },
      ],
    };
  }
}
