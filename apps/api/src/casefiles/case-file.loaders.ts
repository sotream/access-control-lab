import { Inject, Injectable } from "@nestjs/common";
import type { Resource } from "@acl/policy";
import type { ResourceLoader } from "../auth/access.js";
import { toResource } from "../db/case-file.repository.js";
import type { AppRequest } from "../http/request.js";
import { CaseFileService, type Caller } from "./case-file.service.js";

type Peek = Awaited<ReturnType<CaseFileService["peek"]>>;

export const callerOf = (req: AppRequest): Caller => {
  if (!req.policyContext) throw new Error("no policy context on the request"); // programming error: loader used outside @Policy
  return { ...req.policyContext, reqId: req.id };
};

/** Advisory load for the route guard (fast refusal, 404/403 choice). The service repeats the decision inside its transaction. */
@Injectable()
export class ExistingCaseFileLoader implements ResourceLoader {
  readonly existing = true;
  /** one lookup per request: load, the step-up question and the audit reason all read the same result */
  private readonly peeked = new WeakMap<AppRequest, Peek>();

  constructor(@Inject(CaseFileService) private readonly files: CaseFileService) {}

  private async peek(req: AppRequest): Promise<Peek | undefined> {
    const id = req.params.id;
    if (typeof id !== "string") return undefined;
    let p = this.peeked.get(req);
    if (!p) {
      p = await this.files.peek(callerOf(req), id);
      this.peeked.set(req, p);
    }
    return p;
  }

  async load(req: AppRequest): Promise<Resource | undefined> {
    const p = await this.peek(req);
    return p?.row ? toResource(p.row) : undefined;
  }

  async revealedByStepUp(req: AppRequest): Promise<boolean> {
    return (await this.peek(req))?.revealedByStepUp ?? false;
  }

  /** the policy's own reason for hiding the file, for the audit log only */
  async hiddenReason(req: AppRequest): Promise<string | undefined> {
    return (await this.peek(req))?.denialReason;
  }
}

/** The file about to be created: unit, author and status come from the verified principal, never from the body. */
@Injectable()
export class NewCaseFileLoader implements ResourceLoader {
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
