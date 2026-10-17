import { HttpException, HttpStatus } from "@nestjs/common";

/** 401. Body and headers are fixed; the reason only goes to the log. */
export class AuthChallenge extends HttpException {
  /** `invalid_token` when credentials were presented and refused; none when absent (RFC 6750 section 3.1) */
  constructor(readonly presented: boolean) {
    super("Unauthorized", HttpStatus.UNAUTHORIZED);
  }
}

export class RateLimited extends HttpException {
  constructor(readonly retryAfterSeconds: number) {
    super("Too Many Requests", HttpStatus.TOO_MANY_REQUESTS);
  }
}

/** 403 that tells the client how to recover: authenticate more strongly (RFC 9470). The only 403 with a code. */
export class StepUpRequired extends HttpException {
  constructor(readonly acrValues: string) {
    super("Forbidden", HttpStatus.FORBIDDEN);
  }
}
