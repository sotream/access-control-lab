import { Controller, Get, Header, Inject, Query, Req, Res } from "@nestjs/common";
import { IsIn, IsISO8601, IsOptional, IsString, Matches, MaxLength } from "class-validator";
import type { Response } from "express";
import { Policy } from "../auth/access.js";
import { callerOf } from "../casefiles/case-file.loaders.js";
import type { AppRequest } from "../http/request.js";
import { AuditLogService, type Filters } from "./audit-log.service.js";

const TAG = /^[A-Za-z0-9_.:-]{1,128}$/;

/** Query parameters of the auditor endpoints. Whitelisted and strict: an unknown parameter is a 400. */
export class AuditQuery {
  @IsOptional() @IsISO8601({ strict: true }) from?: string;
  @IsOptional() @IsISO8601({ strict: true }) to?: string;
  @IsOptional() @IsString() @Matches(TAG) actor?: string;
  @IsOptional() @IsString() @Matches(TAG) resource?: string;
  @IsOptional() @IsString() @Matches(/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/) action?: string;
  @IsOptional() @IsIn(["allow", "deny"]) effect?: string;
  @IsOptional() @IsString() @MaxLength(100) cursor?: string;
  /** digits only; parsed below (validation runs without transformation) */
  @IsOptional() @Matches(/^[1-9]\d{0,2}$/) limit?: string;
  @IsOptional() @IsIn(["ndjson", "csv"]) format?: "ndjson" | "csv";
}

const filters = (q: AuditQuery): Filters => ({ ...(q.from ? { from: q.from } : {}), ...(q.to ? { to: q.to } : {}), ...(q.actor ? { actor: q.actor } : {}), ...(q.resource ? { resource: q.resource } : {}), ...(q.action ? { action: q.action } : {}), ...(q.effect ? { effect: q.effect } : {}) });

@Controller("audit-log")
export class AuditLogController {
  constructor(@Inject(AuditLogService) private readonly logs: AuditLogService) {}

  @Policy({ action: "readAudit", resource: null })
  @Get()
  list(@Query() q: AuditQuery, @Req() req: AppRequest) {
    return this.logs.page(callerOf(req), filters(q), q.cursor, Math.min(Number(q.limit ?? 100), 500));
  }

  @Policy({ action: "readAudit", resource: null })
  @Get("export")
  async export(@Query() q: AuditQuery, @Req() req: AppRequest, @Res() res: Response) {
    const format = q.format ?? "ndjson";
    const out = await this.logs.export(callerOf(req), filters(q), format, q.cursor);
    res
      .status(200)
      .setHeader("content-type", out.contentType)
      .setHeader("content-disposition", `attachment; filename="audit-log.${format === "csv" ? "csv" : "ndjson"}"`)
      .setHeader("x-audit-proof", Buffer.from(JSON.stringify({ ...out.proof, nextCursor: out.nextCursor })).toString("base64"))
      .setHeader("x-content-type-options", "nosniff")
      .send(out.body);
  }

  @Policy({ action: "readAudit", resource: null })
  @Get("checkpoints")
  checkpoints(@Req() req: AppRequest) {
    return this.logs.checkpointList(callerOf(req));
  }

  @Policy({ action: "readAudit", resource: null })
  @Header("cache-control", "no-store")
  @Get("verify")
  verify(@Req() req: AppRequest) {
    return this.logs.verify(callerOf(req));
  }
}
