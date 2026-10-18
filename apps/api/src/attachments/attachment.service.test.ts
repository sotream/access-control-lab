// The service on its own, with fakes: what the live tests cannot reach because the route guard answers first (audit failures) (T-24, T-47).
import { ServiceUnavailableException } from "@nestjs/common";
import { describe, expect, it } from "vitest";
import type { AuditEntry } from "@acl/audit";
import { loadConfig } from "../config.js";
import { AttachmentService } from "./attachment.service.js";
import { makePng } from "./fixtures.js";
import type { ScanVerdict } from "./scanner.js";

const caller = { subject: { id: "u1", roles: ["analyst"], clearance: "OFFICIAL", unit: "alpha", compartments: [] }, env: { acr: "pwd", amr: ["pwd"], now: 0, networkZone: "unmanaged" }, reqId: "req-00000001" } as never;
const CASE = "0f1e2d3c-4b5a-4968-8776-655443322110";

function rig(o: { failAudit?: string; scan?: () => Promise<ScanVerdict> } = {}) {
  const audits: AuditEntry[] = [];
  const stored = new Map<string, "quarantine" | "files">();
  const rows: { id: string; status: string; storageKey: string }[] = [];
  const row = (v: Record<string, unknown>) => ({ id: "11111111-1111-4111-8111-111111111111", caseFileId: CASE, displayName: v.displayName, mediaType: v.mediaType, sizeBytes: v.sizeBytes, sha256: (v.sha256 as Buffer).toString("hex"), storageKey: v.storageKey, status: "pending", scanDetail: null, uploadedById: "u1", createdAt: new Date(0), scannedAt: null });
  const svc = new AttachmentService(
    { guarded: async (_c: unknown, _a: string, _id: string, fn: (tx: unknown, p: unknown) => unknown) => fn({}, { id: CASE }) } as never,
    {
      insert: async (_tx: unknown, v: Record<string, unknown>) => {
        const r = row(v);
        rows.push({ id: r.id, status: "pending", storageKey: r.storageKey as string });
        return r;
      },
      setVerdict: async (_tx: unknown, _id: string, status: string) => ({ ...row({ displayName: "x.png", mediaType: "image/png", sizeBytes: 1, sha256: Buffer.alloc(32), storageKey: rows[0]?.storageKey }), status }),
    } as never,
    {
      newKey: () => "a".repeat(32),
      putQuarantined: async (k: string) => void stored.set(k, "quarantine"),
      promote: async (k: string) => void stored.set(k, "files"),
      discardQuarantined: async (k: string) => void stored.delete(k),
    } as never,
    { scan: o.scan ?? (async () => ({ verdict: "clean" })) },
    {
      append: async (e: AuditEntry) => {
        if (e.action === o.failAudit) throw new Error("audit down");
        audits.push(e);
      },
    },
    { event: () => undefined } as never,
    loadConfig({}),
  );
  return { svc, audits, stored, rows };
}

describe("fail closed when the audit row cannot be written", () => {
  it("upload: no audit row for the upload, no bytes stored, no metadata", async () => {
    const r = rig({ failAudit: "attachment.upload" });
    await expect(r.svc.upload(caller, CASE, makePng(), "image/png", "a.png")).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(r.stored.size).toBe(0);
    expect(r.rows).toHaveLength(0);
  });
  it("clean verdict: no audit row, the file is never promoted out of quarantine", async () => {
    const r = rig({ failAudit: "attachment.scan" });
    await expect(r.svc.upload(caller, CASE, makePng(), "image/png", "a.png")).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect([...r.stored.values()]).toEqual(["quarantine"]);
  });
  it("a refusal stays a refusal when its own audit row fails (the safe outcome is not changed by the failure)", async () => {
    const r = rig({ failAudit: "attachment.rejected" });
    await expect(r.svc.upload(caller, CASE, Buffer.from("MZ" + "a".repeat(300)), "application/octet-stream", "a.exe")).rejects.toMatchObject({ status: 415 });
    expect(r.stored.size).toBe(0);
  });
  it("the happy path writes upload then scan, and promotes", async () => {
    const r = rig();
    await r.svc.upload(caller, CASE, makePng(), "image/png", "a.png");
    expect(r.audits.map((a) => a.action)).toEqual(["attachment.upload", "attachment.scan"]);
    expect([...r.stored.values()]).toEqual(["files"]);
  });
});
