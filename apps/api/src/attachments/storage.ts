import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { mkdir, open, readFile, rename, rm } from "node:fs/promises";
import { join } from "node:path";
import { Inject, Injectable } from "@nestjs/common";
import { CONFIG, type AppConfig } from "../config.js";

const KEY = /^[0-9a-f]{32}$/;

/**
 * Bytes on a dedicated directory outside any web root: `quarantine/<key>` until a scanner says clean, then `files/<key>`.
 * The key is 128 random bits chosen here; no user input ever becomes a path component. Files are created exclusively (never overwritten),
 * mode 0600, in directories 0700.
 */
@Injectable()
export class AttachmentStore {
  private readonly root: string;

  constructor(@Inject(CONFIG) cfg: AppConfig) {
    this.root = cfg.attachmentDir;
  }

  newKey = (): string => randomBytes(16).toString("hex");

  private path(area: "quarantine" | "files", key: string): string {
    if (!KEY.test(key)) throw new Error("bad storage key"); // defence in depth: keys come from newKey() or from a CHECKed column
    return join(this.root, area, key);
  }

  async init(): Promise<void> {
    for (const area of ["quarantine", "files"]) await mkdir(join(this.root, area), { recursive: true, mode: 0o700 });
  }

  async putQuarantined(key: string, bytes: Buffer): Promise<void> {
    await this.init();
    const f = await open(this.path("quarantine", key), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try {
      await f.writeFile(bytes);
      await f.sync();
    } finally {
      await f.close();
    }
  }

  async promote(key: string): Promise<void> {
    await rename(this.path("quarantine", key), this.path("files", key));
  }

  async discardQuarantined(key: string): Promise<void> {
    await rm(this.path("quarantine", key), { force: true });
  }

  /** only from `files/`: a quarantined or pending file can never be read through this path */
  async read(key: string): Promise<Buffer> {
    return await readFile(this.path("files", key));
  }
}
