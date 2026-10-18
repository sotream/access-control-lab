import net from "node:net";
import { mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../config.js";
import { ClamdScanner, StubScanner } from "./scanner.js";
import { AttachmentStore } from "./storage.js";

const servers: net.Server[] = [];
afterEach(() => {
  for (const s of servers.splice(0)) s.close();
});

/** a fake clamd: records what it was sent and answers with `reply` (or nothing, or garbage) */
async function fakeClamd(reply: (received: Buffer) => string | undefined, opts: { hang?: boolean } = {}) {
  const received: Buffer[] = [];
  const server = net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    sock.on("data", (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      received.push(d);
      if (opts.hang) return;
      // INSTREAM ends with a zero-length chunk
      if (buf.subarray(-4).equals(Buffer.alloc(4)) && buf.length > 10) {
        const r = reply(buf);
        if (r !== undefined) sock.end(r + "\0");
        else sock.end();
      }
    });
    sock.on("error", () => undefined);
  });
  servers.push(server);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { port: (server.address() as net.AddressInfo).port, received };
}

const cfg = (port: number, env: Record<string, string> = {}) => loadConfig({ CLAMD_PORT: String(port), ATTACHMENT_SCANNER: "clamd", ...env });

describe("clamd client: only an explicit OK is clean", () => {
  it("sends zINSTREAM and length-prefixed chunks ending in a zero chunk; OK is clean", async () => {
    const f = await fakeClamd(() => "stream: OK");
    const bytes = Buffer.alloc(70_000, 0x61);
    expect(await new ClamdScanner(cfg(f.port)).scan(bytes)).toEqual({ verdict: "clean" });
    const all = Buffer.concat(f.received);
    expect(all.subarray(0, 10).toString()).toBe("zINSTREAM\0");
    expect(all.readUInt32BE(10)).toBe(65_536);
    expect(all.readUInt32BE(10 + 4 + 65_536)).toBe(70_000 - 65_536);
    expect(all.subarray(-4).equals(Buffer.alloc(4))).toBe(true);
  });
  it("FOUND gives the signature name", async () => {
    const f = await fakeClamd(() => "stream: Eicar-Test-Signature FOUND");
    expect(await new ClamdScanner(cfg(f.port)).scan(Buffer.from("x"))).toEqual({ verdict: "infected", signature: "Eicar-Test-Signature" });
  });
  it.each([
    ["an error answer", "INSTREAM size limit exceeded. ERROR"],
    ["an unknown answer", "stream: MAYBE"],
    ["an OK for another stream", "other: OK"],
    ["OK with trailing text", "stream: OK and something else"],
    ["a signature with odd characters", "stream: Bad Name; rm -rf FOUND"],
    ["an empty answer", ""],
  ])("%s is an error, never clean", async (_n, reply) => {
    const f = await fakeClamd(() => reply);
    await expect(new ClamdScanner(cfg(f.port)).scan(Buffer.from("x"))).rejects.toThrow();
  });
  it("a closed connection and a too long answer are errors", async () => {
    const closed = await fakeClamd(() => undefined);
    await expect(new ClamdScanner(cfg(closed.port)).scan(Buffer.from("x"))).rejects.toThrow();
    const long = await fakeClamd(() => "stream: " + "A".repeat(600) + " FOUND");
    await expect(new ClamdScanner(cfg(long.port)).scan(Buffer.from("x"))).rejects.toThrow();
  });
  it("an unreachable scanner is an error", async () => {
    const f = await fakeClamd(() => "stream: OK");
    const port = f.port;
    servers.pop()!.close();
    await new Promise((r) => setTimeout(r, 50));
    await expect(new ClamdScanner(cfg(port)).scan(Buffer.from("x"))).rejects.toThrow(/unreachable/);
  });
});

describe("stub scanner: a development convenience that refuses to run in production", () => {
  it("development: clean", async () => {
    expect(await new StubScanner(loadConfig({})).scan()).toEqual({ verdict: "clean" });
  });
  it("production: throws, so nothing is ever marked clean without a real scanner", async () => {
    const prod = loadConfig({
      ACL_ENV: "production",
      KEYCLOAK_ISSUER: "https://id.example/realms/casefile",
      DATABASE_URL: "postgres://casefile_app:q9Xv2LmT8sWk4RzP7nYd@db.internal:5432/acl",
      AUDIT_HMAC_KEYS: `audit-2026:${Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 37 + 11) % 251)).toString("base64")}`,
      ZONE_SIGNING_KEYS: `zone-2026:${Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 41 + 11) % 251)).toString("base64")}`,
    });
    await expect(new StubScanner(prod).scan()).rejects.toThrow(/scanner/);
  });
  it("only none and clamd are valid scanner settings", () => {
    expect(() => loadConfig({ ATTACHMENT_SCANNER: "virustotal" })).toThrow(/ATTACHMENT_SCANNER/);
    expect(() => loadConfig({ ATTACHMENT_MAX_BYTES: "999999999" })).toThrow();
  });
});

describe("attachment store", () => {
  const store = () => {
    const dir = mkdtempSync(join(tmpdir(), "acl-store-"));
    return { dir, s: new AttachmentStore({ attachmentDir: dir } as never) };
  };
  it("creates 0700 directories, writes 0600 files exclusively, promotes and reads only from files/", async () => {
    const { dir, s } = store();
    const key = s.newKey();
    expect(key).toMatch(/^[0-9a-f]{32}$/);
    await s.putQuarantined(key, Buffer.from("hello"));
    expect(statSync(join(dir, "quarantine", key)).mode & 0o777).toBe(0o600);
    await expect(s.read(key)).rejects.toThrow(); // not readable while in quarantine
    await expect(s.putQuarantined(key, Buffer.from("again"))).rejects.toThrow(); // never overwritten
    await s.promote(key);
    expect((await s.read(key)).toString()).toBe("hello");
  });
  it("a planted symlink is not followed, and keys that are not 32 hex digits are refused everywhere", async () => {
    const { dir, s } = store();
    await s.init();
    const target = join(dir, "victim.txt");
    writeFileSync(target, "victim");
    const key = "a".repeat(32);
    symlinkSync(target, join(dir, "quarantine", key));
    await expect(s.putQuarantined(key, Buffer.from("x"))).rejects.toThrow();
    expect(readFileSync(target, "utf8")).toBe("victim");
    for (const bad of ["../x", "a".repeat(31), "A".repeat(32), "a".repeat(33), "", "a/b" + "c".repeat(29)]) {
      await expect(s.putQuarantined(bad, Buffer.from("x")), bad).rejects.toThrow(/bad storage key/);
      await expect(s.read(bad), bad).rejects.toThrow(/bad storage key/);
      await expect(s.promote(bad), bad).rejects.toThrow(/bad storage key/);
      await expect(s.discardQuarantined(bad), bad).rejects.toThrow(/bad storage key/);
    }
  });
  it("discarding a missing file is not an error", async () => {
    const { s } = store();
    await s.init();
    await expect(s.discardQuarantined("b".repeat(32))).resolves.toBeUndefined();
  });
});
