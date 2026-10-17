import { type DynamicModule, Module, type Type } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { ThrottlerGuard, ThrottlerModule } from "@nestjs/throttler";
import { AuthFailureLimiter } from "./auth/auth-failure-limiter.js";
import { AuthGuard } from "./auth/auth.guard.js";
import { TokenVerifier } from "./auth/token-verifier.js";
import { CONFIG, type AppConfig } from "./config.js";
import { HealthController } from "./health.controller.js";
import { MeController } from "./me.controller.js";

@Module({})
export class AppModule {
  static register(cfg: AppConfig, extraControllers: Type[] = []): DynamicModule {
    return {
      module: AppModule,
      imports: [ThrottlerModule.forRoot({ throttlers: [{ ttl: cfg.throttleWindowMs, limit: cfg.throttleLimit }] })],
      controllers: [HealthController, MeController, ...extraControllers],
      providers: [
        { provide: CONFIG, useValue: cfg },
        TokenVerifier,
        AuthFailureLimiter,
        // order matters: coarse rate limit first, then authentication and default deny
        { provide: APP_GUARD, useClass: ThrottlerGuard },
        { provide: APP_GUARD, useClass: AuthGuard },
      ],
    };
  }
}
