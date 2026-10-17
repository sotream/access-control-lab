// TEST FIXTURE ONLY. A minimal in-memory case-file API so the guard and the policy engine can be exercised
// end to end. It is deliberately outside `src/` (never built, never shipped); stage 5 adds the real data layer.
import { Body, Controller, Delete, Get, Inject, Injectable, Param, Patch, Post, type Provider, type Type } from "@nestjs/common";
import { CLEARANCES, matchesReadFilter, readFilter, type Resource } from "@acl/policy";
import { ArrayMaxSize, IsArray, IsIn, IsString, MaxLength } from "class-validator";
import { Policy, type ResourceLoader } from "../src/auth/access.js";
import type { Principal } from "../src/auth/principal.js";
import type { AppRequest } from "../src/http/request.js";
import { CurrentPrincipal, PolicyContext } from "../src/http/request.js";

export type StoredFile = { -readonly [K in keyof Resource]: Resource[K] } & { id: string; title: string };

const file = (id: string, o: Partial<StoredFile>): StoredFile => ({
  id,
  title: `title of ${id}`,
  classification: "OFFICIAL",
  ownerUnit: "alpha",
  compartments: [],
  status: "approved",
  authorId: "seed-author",
  submittedById: "seed-submitter",
  ...o,
});

export const SEED_FILES = (): StoredFile[] => [
  file("official-alpha", {}),
  file("official-beta", { ownerUnit: "beta" }),
  file("official-alpha-draft", { status: "draft", authorId: "seed-author" }),
  file("conf-alpha-a", { classification: "CONFIDENTIAL", compartments: ["A"] }),
  file("conf-alpha-a-draft", { classification: "CONFIDENTIAL", compartments: ["A"], status: "draft" }),
  file("conf-alpha-a-submitted", { classification: "CONFIDENTIAL", compartments: ["A"], status: "submitted" }),
  file("secret-alpha-a", { classification: "SECRET", compartments: ["A"] }),
  file("secret-alpha-b", { classification: "SECRET", compartments: ["B"] }),
];

@Injectable()
export class CaseFileStore {
  readonly files = new Map<string, StoredFile>(SEED_FILES().map((f) => [f.id, f]));
  private n = 0;
  nextId() {
    return `new-${++this.n}`;
  }
}

const ID = /^[A-Za-z0-9-]{1,64}$/;

@Injectable()
export class ExistingFileLoader implements ResourceLoader {
  readonly existing = true;
  constructor(@Inject(CaseFileStore) private readonly store: CaseFileStore) {}
  async load(req: AppRequest): Promise<Resource | undefined> {
    const id = req.params.id;
    return typeof id === "string" && ID.test(id) ? this.store.files.get(id) : undefined;
  }
}

/** The file about to be created. Unit, author and status are set from the verified principal, never from the body. */
@Injectable()
export class NewFileLoader implements ResourceLoader {
  readonly existing = false;
  async load(req: AppRequest): Promise<Resource> {
    const b = (typeof req.body === "object" && req.body !== null ? req.body : {}) as Record<string, unknown>;
    return {
      classification: b.classification as string,
      compartments: b.compartments as string[],
      ownerUnit: req.principal!.unit,
      authorId: req.principal!.sub,
      status: "draft",
    };
  }
}

class CreateDto {
  @IsString() @MaxLength(100) title!: string;
  @IsIn(CLEARANCES as unknown as string[]) classification!: string;
  @IsArray() @ArrayMaxSize(16) @IsString({ each: true }) @MaxLength(32, { each: true }) compartments!: string[];
}
class UpdateDto {
  @IsString() @MaxLength(100) title!: string;
}

@Controller()
export class CaseFileController {
  constructor(@Inject(CaseFileStore) private readonly store: CaseFileStore) {}

  @Policy({ action: "read", resource: null })
  @Get("files")
  list(@PolicyContext() ctx: NonNullable<AppRequest["policyContext"]>) {
    // role check passed in the guard; every row is filtered by the same rule as evaluate(read)
    const f = readFilter(ctx.subject, ctx.env);
    return [...this.store.files.values()].filter((x) => matchesReadFilter(f, x)).map((x) => ({ id: x.id, classification: x.classification }));
  }

  @Policy({ action: "create", resource: NewFileLoader })
  @Post("files")
  create(@Body() dto: CreateDto, @CurrentPrincipal() p: Principal) {
    const id = this.store.nextId();
    this.store.files.set(id, { id, title: dto.title, classification: dto.classification, compartments: dto.compartments, ownerUnit: p.unit, status: "draft", authorId: p.sub, submittedById: null });
    return { id };
  }

  @Policy({ action: "read", resource: ExistingFileLoader })
  @Get("files/:id")
  read(@Param("id") id: string) {
    const f = this.store.files.get(id)!;
    return { id: f.id, title: f.title, classification: f.classification, status: f.status };
  }

  @Policy({ action: "update", resource: ExistingFileLoader })
  @Patch("files/:id")
  update(@Param("id") id: string, @Body() dto: UpdateDto) {
    this.store.files.get(id)!.title = dto.title;
    return { id };
  }

  @Policy({ action: "submit", resource: ExistingFileLoader })
  @Post("files/:id/submit")
  submit(@Param("id") id: string, @CurrentPrincipal() p: Principal) {
    Object.assign(this.store.files.get(id)!, { status: "submitted", submittedById: p.sub });
    return { id, status: "submitted" };
  }

  @Policy({ action: "approve", resource: ExistingFileLoader })
  @Post("files/:id/approve")
  approve(@Param("id") id: string) {
    this.store.files.get(id)!.status = "approved";
    return { id, status: "approved" };
  }

  @Policy({ action: "delete", resource: ExistingFileLoader })
  @Delete("files/:id")
  remove(@Param("id") id: string) {
    this.store.files.delete(id);
    return { id };
  }

  @Policy({ action: "export", resource: ExistingFileLoader })
  @Get("files/:id/export")
  export(@Param("id") id: string) {
    return { id, exported: true };
  }

  @Policy({ action: "readAudit", resource: null })
  @Get("audit")
  audit() {
    return [];
  }

  @Policy({ action: "manageUsers", resource: null })
  @Get("admin/users")
  users() {
    return [];
  }
}

export const FIXTURE: { controllers: Type[]; providers: Provider[] } = {
  controllers: [CaseFileController],
  providers: [CaseFileStore, ExistingFileLoader, NewFileLoader],
};
