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
}

export function parse<T>(r: ApiResult): T | undefined {
  try {
    return JSON.parse(r.body) as T;
  } catch {
    return undefined;
  }
}

export { apiFetch };
