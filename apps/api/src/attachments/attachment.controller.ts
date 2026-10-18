import { Controller, Get, Inject, Param, Post, Req, Res, UnsupportedMediaTypeException } from "@nestjs/common";
import type { Response } from "express";
import { Policy } from "../auth/access.js";
import { ExistingCaseFileLoader, callerOf } from "../casefiles/case-file.loaders.js";
import type { AppRequest } from "../http/request.js";
import { AttachmentService, type AttachmentView } from "./attachment.service.js";
import { decodeNameHeader, disposition } from "./content.js";

const header = (req: AppRequest, name: string): string | undefined => {
  const v = req.headers[name];
  return typeof v === "string" ? v : undefined; // a repeated header arrives as an array or a joined string: either way it will not match the allow-list
};

/**
 * Same policy as the parent case file: upload needs `update` on it (a draft, own unit, own file for analysts), list and download need `read`
 * (clearance, compartments, step-up for SECRET). The route guard decides first; the service decides again inside its transaction and
 * row-level security a third time.
 */
@Controller("case-files/:id/attachments")
export class AttachmentsController {
  constructor(@Inject(AttachmentService) private readonly attachments: AttachmentService) {}

  @Policy({ action: "update", resource: ExistingCaseFileLoader })
  @Post()
  upload(@Param("id") id: string, @Req() req: AppRequest): Promise<AttachmentView> {
    if (!Buffer.isBuffer(req.body) || (req.headers["content-type"] ?? "").split(";")[0]?.trim().toLowerCase() !== "application/octet-stream") throw new UnsupportedMediaTypeException();
    return this.attachments.upload(callerOf(req), id, req.body, header(req, "x-attachment-type"), decodeNameHeader(header(req, "x-attachment-name")));
  }

  @Policy({ action: "read", resource: ExistingCaseFileLoader })
  @Get()
  list(@Param("id") id: string, @Req() req: AppRequest): Promise<AttachmentView[]> {
    return this.attachments.list(callerOf(req), id);
  }

  @Policy({ action: "read", resource: ExistingCaseFileLoader })
  @Get(":attachmentId")
  async download(@Param("id") id: string, @Param("attachmentId") attachmentId: string, @Req() req: AppRequest, @Res() res: Response): Promise<void> {
    const f = await this.attachments.download(callerOf(req), id, attachmentId);
    res
      .status(200)
      .setHeader("content-type", f.mediaType)
      .setHeader("content-disposition", disposition(f.name))
      .setHeader("x-content-type-options", "nosniff")
      .setHeader("content-security-policy", "sandbox; default-src 'none'")
      .setHeader("cache-control", "no-store")
      .setHeader("content-length", String(f.bytes.length))
      .end(f.bytes);
  }
}
