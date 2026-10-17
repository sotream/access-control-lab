import { randomUUID } from "node:crypto";
import type { NextFunction, Response } from "express";
import type { JsonLogger } from "./logger.js";
import type { AppRequest } from "./request.js";

/** Always generates the id: a client supplied one could be used to forge or poison log lines. */
export function requestContext(logger: JsonLogger) {
  return (req: AppRequest, res: Response, next: NextFunction) => {
    req.id = randomUUID();
    res.setHeader("X-Request-Id", req.id);
    const start = process.hrtime.bigint();
    res.on("finish", () => {
      logger.event("info", "request", {
        reqId: req.id,
        method: req.method,
        path: req.path, // no query string: it can carry tokens
        status: res.statusCode,
        ms: Number((process.hrtime.bigint() - start) / 1_000_000n),
        sub: req.principal?.sub,
        authFailure: req.authFailure,
        ip: req.ip,
      });
    });
    next();
  };
}
