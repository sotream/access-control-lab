import { timingSafeEqual } from "node:crypto";
import { headers as requestHeaders } from "next/headers";
import { normalizeIp, parseNetworks, type Networks, type Zone } from "@acl/netguard";
import { config } from "./config";

/** Header names of the contract with the reverse proxy: the proxy overwrites both on every request and strips whatever the client sent. */
export const PROXY_SECRET_HEADER = "x-acl-proxy-secret";
export const CLIENT_IP_HEADER = "x-acl-client-ip";

let managed: { source: string; nets: Networks } | undefined;
const managedNets = (): Networks => {
  const source = config().managedCidrs.join(",");
  if (managed?.source !== source) managed = { source, nets: parseNetworks(config().managedCidrs) };
  return managed.nets;
};

const same = (a: string, b: string): boolean => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

/**
 * The client address, or "direct" when it cannot be known. Next.js route handlers cannot see the socket, so a forwarded address is believed
 * only when the request carries the proxy's secret (constant-time compare) and the address is a plain IP. Otherwise every forwarded header is ignored
 * and all such clients share one bucket ("direct"): a missing proxy contract fails towards stricter limits and the unmanaged zone, never towards trust.
 */
export function clientAddress(h: Pick<Headers, "get">): string {
  const secret = config().trustedProxySecret;
  const presented = h.get(PROXY_SECRET_HEADER);
  if (!secret || presented === null || !same(presented, secret)) return "direct";
  return normalizeIp(h.get(CLIENT_IP_HEADER) ?? undefined) ?? "direct";
}

export const zoneOf = (h: Pick<Headers, "get">): Zone => {
  const ip = clientAddress(h);
  return ip !== "direct" && managedNets().has(ip) ? "managed" : "unmanaged";
};

/** the headers of the request being served; undefined outside a request (unit tests, build) */
export async function currentHeaders(): Promise<Headers | undefined> {
  try {
    return await requestHeaders();
  } catch {
    return undefined;
  }
}
