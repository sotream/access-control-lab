import { cache } from "react";
import { redirect } from "next/navigation";
import { apiFetch, type ApiResult } from "./api";
import { currentSession } from "./session";
import type { Session } from "./session-store";

/** Protected pages: no session means sign in, then come back to this exact page. */
export async function requireSession(returnTo: string): Promise<Session> {
  const s = await currentSession();
  if (!s) redirect(`/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
  return s;
}

export interface CaseFileSummary {
  id: string;
  title: string;
  classification: string;
  unit: string;
  compartments: string[];
  status: string;
  version: number;
  body?: string;
  authorId?: string;
  createdAt?: string;
  updatedAt?: string;
}

export function parse<T>(r: ApiResult): T | undefined {
  try {
    return JSON.parse(r.body) as T;
  } catch {
    return undefined;
  }
}

export { apiFetch };

export interface Me {
  sub: string;
  roles: string[];
  clearance: string;
  unit: string;
  compartments: string[];
  acr: string;
  amr: string[];
  authTime: number;
}

const TAG = /^[A-Za-z0-9_.:-]{1,64}$/;
const tags = (v: unknown, max: number): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && TAG.test(x)).slice(0, max) : []);

/**
 * What the top bar shows, read from the access token this server received from the identity provider over TLS. DISPLAY ONLY: no decision
 * is taken from it (the API verifies the token and decides), and reading it costs no upstream call per page. Undefined if it is not a JWT.
 */
export function meFromToken(accessToken: string): Me | undefined {
  try {
    const part = accessToken.split(".")[1];
    if (!part) return undefined;
    const c = JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as Record<string, unknown>;
    const str = (v: unknown) => (typeof v === "string" && TAG.test(v) ? v : undefined);
    const realm = c.realm_access as { roles?: unknown } | undefined;
    const sub = typeof c.sub === "string" && /^[0-9a-f-]{8,64}$/i.test(c.sub) ? c.sub : undefined;
    const clearance = str(c.clearance);
    if (!sub || !clearance) return undefined;
    return { sub, roles: tags(realm?.roles, 16), clearance, unit: str(c.unit) ?? "?", compartments: tags(c.compartments, 16), acr: str(c.acr) ?? "", amr: tags(c.amr, 8), authTime: typeof c.auth_time === "number" ? c.auth_time : 0 };
  } catch {
    return undefined;
  }
}

export const getMe = cache(async (session: Session): Promise<Me | undefined> => meFromToken(session.tokens.accessToken));
