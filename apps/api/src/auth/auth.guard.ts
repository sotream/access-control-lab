import { type CanActivate, type ExecutionContext, ForbiddenException, Inject, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { AuthChallenge, RateLimited } from "../http/errors.js";
import type { AppRequest } from "../http/request.js";
import { ACCESS_KEY, type Access } from "./access.js";
import { PolicyEnforcer } from "../policy/policy.enforcer.js";
import { AuthFailureLimiter } from "./auth-failure-limiter.js";
import { AuthError, TokenVerifier } from "./token-verifier.js";

const MAX_TOKEN_LENGTH = 8192;
// RFC 6750 token68
const BEARER = /^Bearer ([A-Za-z0-9\-._~+/]+=*)$/i;

/** Exactly one Authorization header, Bearer scheme, sane token. The token is never read from query or body. */
export function extractBearer(req: AppRequest): string {
  const count = req.rawHeaders.filter((h, i) => i % 2 === 0 && h.toLowerCase() === "authorization").length;
  if (count === 0) throw new AuthError("malformed"); // caller distinguishes "absent" itself
  if (count > 1) throw new AuthError("malformed");
  const m = BEARER.exec(req.headers.authorization ?? "");
  if (!m?.[1] || m[1].length > MAX_TOKEN_LENGTH) throw new AuthError("malformed");
  return m[1];
}

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(TokenVerifier) private readonly verifier: TokenVerifier,
    @Inject(AuthFailureLimiter) private readonly limiter: AuthFailureLimiter,
    @Inject(PolicyEnforcer) private readonly enforcer: PolicyEnforcer,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<AppRequest>();
    const access = this.reflector.getAllAndOverride<Access | undefined>(ACCESS_KEY, [ctx.getHandler(), ctx.getClass()]);
    if (access?.kind === "public") return true;

    const key = req.ip ?? "unknown";
    if (this.limiter.blocked(key)) {
      req.authFailure = "rate_limited";
      throw new RateLimited(this.limiter.retryAfter(key));
    }

    const presented = req.rawHeaders.some((h, i) => i % 2 === 0 && h.toLowerCase() === "authorization");
    try {
      req.principal = await this.verifier.verify(extractBearer(req));
    } catch (e) {
      this.limiter.fail(key);
      req.authFailure = !presented ? "missing_token" : e instanceof AuthError ? e.reason : "internal";
      throw new AuthChallenge(presented);
    }

    // authenticated, but nothing declared what this route allows: deny (default deny)
    if (!access) {
      req.authFailure = "no_access_declared";
      throw new ForbiddenException();
    }
    if (access.kind === "policy") await this.enforcer.enforce(req, access, req.principal);
    return true;
  }
}
