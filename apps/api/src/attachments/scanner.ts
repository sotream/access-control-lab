import net from "node:net";
import { Inject, Injectable } from "@nestjs/common";
import { CONFIG, type AppConfig } from "../config.js";

export type ScanVerdict = { verdict: "clean" } | { verdict: "infected"; signature: string };

/**
 * Malware scan hook. `scan` either gives a verdict or THROWS: an error, a timeout or an unreadable answer is never "clean".
 * The caller leaves the attachment pending (not downloadable) when this throws.
 */
export interface Scanner {
  scan(bytes: Buffer): Promise<ScanVerdict>;
}
export const SCANNER = Symbol("SCANNER");

/**
 * ATTACHMENT_SCANNER=none. Development stub: everything is clean, which is exactly why it refuses to answer in production
 * (nothing becomes downloadable until a real scanner is configured).
 */
@Injectable()
export class StubScanner implements Scanner {
  constructor(@Inject(CONFIG) private readonly cfg: AppConfig) {}
  async scan(): Promise<ScanVerdict> {
    if (this.cfg.profile === "production") throw new Error("no malware scanner configured");
    return { verdict: "clean" };
  }
}

/** clamd over TCP, INSTREAM command. Answers: `stream: OK`, `stream: <name> FOUND`, anything else (ERROR, size limit) throws. */
@Injectable()
export class ClamdScanner implements Scanner {
  constructor(@Inject(CONFIG) private readonly cfg: AppConfig) {}

  scan(bytes: Buffer): Promise<ScanVerdict> {
    const { clamdHost: host, clamdPort: port } = this.cfg;
    return new Promise((resolve, reject) => {
      const socket = net.connect({ host, port });
      let answer = "";
      const done = (f: () => void) => {
        socket.destroy();
        f();
      };
      socket.setTimeout(15_000, () => done(() => reject(new Error("scanner timeout"))));
      socket.on("error", () => done(() => reject(new Error("scanner unreachable"))));
      socket.on("data", (d) => {
        answer += d.toString("latin1");
        if (answer.length > 512) done(() => reject(new Error("scanner answer too long")));
      });
      socket.on("end", () => {
        const a = answer.replace(/\0$/, "").trim();
        if (a === "stream: OK") return resolve({ verdict: "clean" });
        const m = /^stream: ([A-Za-z0-9_.-]{1,60}) FOUND$/.exec(a);
        if (m) return resolve({ verdict: "infected", signature: m[1] as string });
        reject(new Error("scanner error"));
      });
      socket.on("connect", () => {
        socket.write("zINSTREAM\0");
        for (let off = 0; off < bytes.length; off += 65_536) {
          const chunk = bytes.subarray(off, off + 65_536);
          const len = Buffer.alloc(4);
          len.writeUInt32BE(chunk.length);
          socket.write(len);
          socket.write(chunk);
        }
        socket.write(Buffer.alloc(4)); // zero-length chunk ends the stream
      });
    });
  }
}
