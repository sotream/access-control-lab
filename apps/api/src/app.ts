import { type Provider, type Type, ValidationPipe } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";
import helmet from "helmet";
import { AppModule } from "./app.module.js";
import type { AppConfig } from "./config.js";
import { ErrorFilter } from "./http/error-filter.js";
import { JsonLogger } from "./http/logger.js";
import type { Clock } from "./policy/policy.enforcer.js";
import { requestContext } from "./http/request-context.js";

/** The one place the HTTP hardening is applied, so tests exercise exactly what production runs. */
export async function createApp(cfg: AppConfig, opts: { logger?: JsonLogger; extraControllers?: Type[]; extraProviders?: Provider[]; clock?: Clock } = {}) {
  const logger = opts.logger ?? new JsonLogger();
  const app = await NestFactory.create<NestExpressApplication>(AppModule.register(cfg, { logger, clock: opts.clock, controllers: opts.extraControllers, providers: opts.extraProviders }), {
    bodyParser: false,
    logger,
    abortOnError: false, // a failing provider (e.g. an unsafe database role) rejects here instead of aborting the process; main() exits non-zero
  });

  app.use(requestContext(logger));
  // JSON API: nothing renders, so the CSP is "nothing may load or frame"
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false, // helmet defaults would re-allow self scripts, styles and images
        directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'none'"], formAction: ["'none'"] },
      },
      referrerPolicy: { policy: "no-referrer" },
      crossOriginResourcePolicy: { policy: "same-origin" },
    }),
  );
  app.enableCors({
    origin: cfg.corsOrigins.length ? [...cfg.corsOrigins] : false, // empty allow-list: no CORS headers at all
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["authorization", "content-type"],
    credentials: false,
    maxAge: 600,
  });
  app.useBodyParser("json", { limit: cfg.bodyLimit });
  app.useGlobalPipes(
    new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, forbidUnknownValues: true, transform: false }),
  );
  app.useGlobalFilters(new ErrorFilter(logger));
  app.set("trust proxy", false); // never believe X-Forwarded-For from a client
  return app;
}
