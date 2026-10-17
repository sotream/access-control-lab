import { type ArgumentsHost, Catch, type ExceptionFilter, HttpException } from "@nestjs/common";
import type { Response } from "express";
import { AuthChallenge, RateLimited, StepUpRequired } from "./errors.js";
import type { JsonLogger } from "./logger.js";
import type { AppRequest } from "./request.js";

const TEXT: Record<number, string> = {
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  413: "Payload Too Large",
  415: "Unsupported Media Type",
  429: "Too Many Requests",
  500: "Internal Server Error",
};

export const REALM = "casefile-api";

/** Every error leaves through here: fixed bodies, no stack, no claim or token content. */
@Catch()
export class ErrorFilter implements ExceptionFilter {
  constructor(private readonly logger: JsonLogger) {}

  catch(err: unknown, host: ArgumentsHost): void {
    const http = host.switchToHttp();
    const res = http.getResponse<Response>();
    const req = http.getRequest<AppRequest>();

    let status = 500;
    let message: string | string[] | undefined;
    let code: string | undefined;

    if (err instanceof AuthChallenge) {
      status = 401;
      res.setHeader("WWW-Authenticate", `Bearer realm="${REALM}"${err.presented ? ', error="invalid_token"' : ""}`);
    } else if (err instanceof StepUpRequired) {
      status = 403;
      code = "STEP_UP_REQUIRED";
      res.setHeader(
        "WWW-Authenticate",
        `Bearer realm="${REALM}", error="insufficient_user_authentication", error_description="A stronger authentication is required", acr_values="${err.acrValues}"`,
      );
    } else if (err instanceof RateLimited) {
      status = 429;
      res.setHeader("Retry-After", String(err.retryAfterSeconds));
    } else if (err instanceof HttpException) {
      status = err.getStatus();
      // only validation errors (400) carry detail: class-validator messages name fields, never values
      if (status === 400) {
        const r = err.getResponse();
        const m = typeof r === "object" && r !== null ? (r as { message?: unknown }).message : undefined;
        if (Array.isArray(m) && m.every((x) => typeof x === "string")) message = m as string[];
      }
      if (status === 429 && !res.getHeader("Retry-After")) res.setHeader("Retry-After", "60");
    } else if (typeof (err as { status?: unknown })?.status === "number") {
      // body-parser errors (too large, bad JSON) are plain errors with a status
      const s = (err as { status: number }).status;
      status = s >= 400 && s < 500 ? s : 500;
    }

    if (status >= 500) {
      this.logger.event("error", "unhandled", { reqId: req?.id, errorClass: err instanceof Error ? err.name : typeof err });
    }

    res.status(status).json({ statusCode: status, error: TEXT[status] ?? "Error", ...(message ? { message } : {}), ...(code ? { code } : {}) });
  }
}
