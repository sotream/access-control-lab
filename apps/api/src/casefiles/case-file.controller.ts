import { Body, Controller, Delete, Get, Inject, Param, Patch, Post, Req } from "@nestjs/common";
import { CLEARANCES } from "@acl/policy";
import { ArrayMaxSize, IsArray, IsIn, IsInt, IsOptional, IsString, Matches, Max, MaxLength, Min, MinLength } from "class-validator";
import { Policy } from "../auth/access.js";
import type { AppRequest } from "../http/request.js";
import { ExistingCaseFileLoader, NewCaseFileLoader, callerOf } from "./case-file.loaders.js";
import { CaseFileService, type CaseFileView } from "./case-file.service.js";

const TAG = /^[A-Za-z0-9_-]{1,32}$/;
// Postgres text cannot hold NUL; refuse it as a validation error instead of letting the driver fail
const NO_NUL = /^[^\u0000]*$/;

export class CreateCaseFileDto {
  @IsString() @MinLength(1) @MaxLength(100) @Matches(NO_NUL) title!: string;
  @IsOptional() @IsString() @MaxLength(50_000) @Matches(NO_NUL) body?: string;
  @IsIn(CLEARANCES as unknown as string[]) classification!: string;
  @IsArray() @ArrayMaxSize(16) @Matches(TAG, { each: true }) compartments!: string[];
}

export class UpdateCaseFileDto {
  @IsOptional() @IsString() @MinLength(1) @MaxLength(100) @Matches(NO_NUL) title?: string;
  @IsOptional() @IsString() @MaxLength(50_000) @Matches(NO_NUL) body?: string;
  /** optimistic concurrency: the version the client last read */
  @IsInt() @Min(1) @Max(2_147_483_647) version!: number;
}

@Controller("case-files")
export class CaseFilesController {
  constructor(@Inject(CaseFileService) private readonly files: CaseFileService) {}

  @Policy({ action: "read", resource: null })
  @Get()
  list(@Req() req: AppRequest): Promise<CaseFileView[]> {
    return this.files.list(callerOf(req));
  }

  @Policy({ action: "create", resource: NewCaseFileLoader })
  @Post()
  create(@Body() dto: CreateCaseFileDto, @Req() req: AppRequest): Promise<CaseFileView> {
    return this.files.create(callerOf(req), { title: dto.title, body: dto.body ?? "", classification: dto.classification, compartments: dto.compartments });
  }

  @Policy({ action: "read", resource: ExistingCaseFileLoader })
  @Get(":id")
  read(@Param("id") id: string, @Req() req: AppRequest): Promise<CaseFileView> {
    return this.files.read(callerOf(req), id);
  }

  @Policy({ action: "update", resource: ExistingCaseFileLoader })
  @Patch(":id")
  update(@Param("id") id: string, @Body() dto: UpdateCaseFileDto, @Req() req: AppRequest): Promise<CaseFileView> {
    return this.files.update(callerOf(req), id, dto);
  }

  @Policy({ action: "submit", resource: ExistingCaseFileLoader })
  @Post(":id/submit")
  submit(@Param("id") id: string, @Req() req: AppRequest): Promise<CaseFileView> {
    return this.files.submit(callerOf(req), id);
  }

  @Policy({ action: "approve", resource: ExistingCaseFileLoader })
  @Post(":id/approve")
  approve(@Param("id") id: string, @Req() req: AppRequest): Promise<CaseFileView> {
    return this.files.approve(callerOf(req), id);
  }

  @Policy({ action: "delete", resource: ExistingCaseFileLoader })
  @Delete(":id")
  async remove(@Param("id") id: string, @Req() req: AppRequest): Promise<{ id: string }> {
    await this.files.remove(callerOf(req), id);
    return { id };
  }

  @Policy({ action: "export", resource: ExistingCaseFileLoader })
  @Get(":id/export")
  export(@Param("id") id: string, @Req() req: AppRequest): Promise<CaseFileView> {
    return this.files.export(callerOf(req), id);
  }
}
