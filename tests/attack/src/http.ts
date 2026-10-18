// HTTPS to the prod-like proxy on 127.0.0.1:443; the host name only selects the virtual host. The stack's CA is trusted through NODE_EXTRA_CA_CERTS
// (set by `pnpm test:attack`), never handed to a request. Redirects are never followed: an attacker's script decides what to do with a Location.
import https from "node:https";

export interface Resp {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
  text: string;
  json: unknown;
  location: string | null;
  ms: number;
}

export class Jar {
  readonly cookies = new Map<string, string>();
  absorb(setCookie: string[] | string | undefined): void {
    for (const line of [setCookie ?? []].flat()) {
      const [pair] = line.split(";");
      const i = pair!.indexOf("=");
      const name = pair!.slice(0, i);
      const value = pair!.slice(i + 1);
      if (value === "" || /max-age=0/i.test(line) || /expires=thu, 01 jan 1970/i.test(line)) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }
  header(): string {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  get(name: string): string | undefined {
    return this.cookies.get(name);
  }
  clone(): Jar {
    const j = new Jar();
    for (const [k, v] of this.cookies) j.cookies.set(k, v);
    return j;
  }
}

export interface ReqOpts {
  method?: string;
  headers?: Record<string, string | string[]>;
  body?: string | Buffer;
  jar?: Jar;
  timeoutMs?: number;
}

export function request(host: string, path: string, o: ReqOpts = {}): Promise<Resp> {
  const t0 = Date.now();
  return new Promise((resolve, reject) => {
    const headers: Record<string, string | string[]> = { host, ...(o.headers ?? {}) };
    if (o.jar?.cookies.size) headers.cookie = o.jar.header();
    if (o.body !== undefined && headers["content-length"] === undefined && !Object.keys(headers).some((k) => k.toLowerCase() === "transfer-encoding")) headers["content-length"] = String(Buffer.byteLength(o.body));
    const req = https.request({ host: "127.0.0.1", servername: host, port: 443, path, method: o.method ?? "GET", headers, lookup: (_n, _o, cb) => cb(null, "127.0.0.1", 4), timeout: o.timeoutMs ?? 60_000 }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        o.jar?.absorb(res.headers["set-cookie"]);
        const body = Buffer.concat(chunks);
        const text = body.toString("utf8");
        let json: unknown;
        try {
          json = JSON.parse(text);
        } catch {
          json = undefined;
        }
        resolve({ status: res.statusCode ?? 0, headers: res.headers, body, text, json, location: (res.headers.location as string | undefined) ?? null, ms: Date.now() - t0 });
      });
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end(o.body);
  });
}

export const vault = (path: string, o?: ReqOpts) => request("vault.localhost", path, o);
export const idp = (path: string, o?: ReqOpts) => request("id.localhost", path, o);
/** the API as an attacker with an internal foothold would reach it (test-only route, see infra/caddy/test/api.caddy): same code, rate limits lifted */
export const api = (path: string, o?: ReqOpts) => request("vault.localhost", `/__api${path}`, o);
/** the same, on the instance with the production rate limits */
export const apiStrict = (path: string, o?: ReqOpts) => request("vault.localhost", `/__api-strict${path}`, o);

export const form = (fields: Record<string, string>): string => new URLSearchParams(fields).toString();
export const FORM = { "content-type": "application/x-www-form-urlencoded" };

/** a multipart/form-data body as a browser builds it */
export function multipart(fields: Record<string, string>, file?: { name: string; type: string; bytes: Buffer | string; field?: string }, boundary = `----atk${Date.now()}${Math.floor(Math.random() * 1e6)}`): { body: Buffer; headers: Record<string, string> } {
  const parts: Buffer[] = [];
  for (const [k, v] of Object.entries(fields)) parts.push(Buffer.from(`--${boundary}\r\ncontent-disposition: form-data; name="${k}"\r\n\r\n${v}\r\n`));
  if (file) parts.push(Buffer.from(`--${boundary}\r\ncontent-disposition: form-data; name="${file.field ?? "file"}"; filename="${file.name}"\r\ncontent-type: ${file.type}\r\n\r\n`), Buffer.from(file.bytes), Buffer.from("\r\n"));
  parts.push(Buffer.from(`--${boundary}--\r\n`));
  const body = Buffer.concat(parts);
  return { body, headers: { "content-type": `multipart/form-data; boundary=${boundary}`, "content-length": String(body.length) } };
}
