import { BlockList, isIP } from "node:net";

/** Normalises what a socket or a header says into a plain IP string, or undefined when it is not an IP address. */
export function normalizeIp(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  let s = raw.trim();
  if (s.toLowerCase().startsWith("::ffff:") && isIP(s.slice(7)) === 4) s = s.slice(7); // IPv4-mapped IPv6
  return isIP(s) ? s.toLowerCase() : undefined;
}

export interface Networks {
  readonly size: number;
  has(ip: string | undefined): boolean;
}

/** `10.0.0.0/8`, `fd00::/8` or a single address. Anything else throws: a typo must not silently shrink or widen a trust list. */
export function parseNetworks(entries: readonly string[]): Networks {
  const list = new BlockList();
  for (const e of entries) {
    const [addr, bits, extra] = e.split("/");
    const ip = normalizeIp(addr);
    if (!ip || extra !== undefined || (bits !== undefined && !/^\d{1,3}$/.test(bits))) throw new Error(`not an address or CIDR: ${e}`);
    const family = isIP(ip) === 4 ? "ipv4" : "ipv6";
    if (bits === undefined) list.addAddress(ip, family);
    else {
      const n = Number(bits);
      if (n > (family === "ipv4" ? 32 : 128)) throw new Error(`prefix too long: ${e}`);
      list.addSubnet(ip, n, family);
    }
  }
  return { size: entries.length, has: (ip) => !!ip && list.check(ip, isIP(ip) === 4 ? "ipv4" : "ipv6") };
}

/**
 * The client address, from the socket and the forwarded chain. The chain is believed ONLY when the socket peer is a configured trusted proxy,
 * and then only from the right: hops that are themselves trusted proxies are skipped, the first other address is the client.
 * Any malformed entry in the chain, or a chain made only of trusted hops, gives the peer address (never a value the client chose).
 */
export function clientIp(peer: string | undefined, forwardedFor: string | undefined, trusted: Networks): string | undefined {
  const p = normalizeIp(peer);
  if (!p || trusted.size === 0 || !trusted.has(p) || forwardedFor === undefined) return p;
  const hops = forwardedFor.split(",").map((h) => normalizeIp(h));
  if (hops.length > 20 || hops.some((h) => h === undefined)) return p;
  for (let i = hops.length - 1; i >= 0; i--) if (!trusted.has(hops[i])) return hops[i];
  return p;
}
