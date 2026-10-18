// Raw TLS to the proxy for requests no HTTP client library would send (conflicting lengths, folded headers, absurd sizes).
import tls from "node:tls";

export interface RawResult {
  data: string;
  statuses: number[];
  closed: boolean;
  ms: number;
}

export function rawRequest(bytes: string | Buffer, o: { readMs?: number; host?: string } = {}): Promise<RawResult> {
  const t0 = Date.now();
  return new Promise((resolve) => {
    const host = o.host ?? "vault.localhost";
    const sock = tls.connect({ host: "127.0.0.1", port: 443, servername: host, ALPNProtocols: ["http/1.1"] });
    let data = "";
    let closed = false;
    const done = () => {
      sock.destroy();
      resolve({ data, statuses: [...data.matchAll(/HTTP\/1\.[01] (\d{3})/g)].map((m) => Number(m[1])), closed, ms: Date.now() - t0 });
    };
    const timer = setTimeout(done, o.readMs ?? 3000);
    sock.on("secureConnect", () => sock.write(bytes));
    sock.on("data", (d) => (data += d.toString("latin1")));
    sock.on("close", () => {
      closed = true;
      clearTimeout(timer);
      done();
    });
    sock.on("error", () => {
      closed = true;
      clearTimeout(timer);
      done();
    });
  });
}

export const HOSTLINE = "Host: vault.localhost\r\n";
