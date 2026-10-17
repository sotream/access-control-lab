import { createParamDecorator, type ExecutionContext } from "@nestjs/common";
import type { Environment, Subject } from "@acl/policy";
import type { Request } from "express";
import type { Principal } from "../auth/principal.js";

export type AppRequest = Request & {
  id: string;
  principal?: Principal;
  /** machine reason for a refused authentication, logged, never returned */
  authFailure?: string;
  /** set by the guard on @Policy routes: what the decision was made with, for handlers that filter rows */
  policyContext?: { subject: Subject; env: Environment };
};

export const CurrentPrincipal = createParamDecorator((_data: unknown, ctx: ExecutionContext): Principal => {
  const p = ctx.switchToHttp().getRequest<AppRequest>().principal;
  if (!p) throw new Error("CurrentPrincipal used on a route without authentication"); // programming error, surfaces as 500
  return p;
});

export const PolicyContext = createParamDecorator((_data: unknown, ctx: ExecutionContext) => {
  const c = ctx.switchToHttp().getRequest<AppRequest>().policyContext;
  if (!c) throw new Error("PolicyContext used on a route without @Policy"); // programming error
  return c;
});
