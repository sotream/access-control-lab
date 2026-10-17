import { createParamDecorator, type ExecutionContext } from "@nestjs/common";
import type { Request } from "express";
import type { Principal } from "../auth/principal.js";

export type AppRequest = Request & {
  id: string;
  principal?: Principal;
  /** machine reason for a refused authentication, logged, never returned */
  authFailure?: string;
};

export const CurrentPrincipal = createParamDecorator((_data: unknown, ctx: ExecutionContext): Principal => {
  const p = ctx.switchToHttp().getRequest<AppRequest>().principal;
  if (!p) throw new Error("CurrentPrincipal used on a route without authentication"); // programming error, surfaces as 500
  return p;
});
