import { t } from "./i18n";

const TONES = { done: "ok", uploaded: "ok" } as const;
/** Only fixed codes are looked up; whatever else is in the URL is ignored (nothing is reflected). */
export function noticeFor(code: string | undefined): { tone: "ok" | "danger" | "warn"; text: string } | undefined {
  if (!code || !Object.hasOwn(t.msg, code) || ["ok", "problem", "notice", "reauth", "createForbidden", "createStepup"].includes(code)) return undefined;
  const text = t.msg[code as keyof typeof t.msg];
  return { tone: Object.hasOwn(TONES, code) ? "ok" : code === "stepup" || code === "conflict" ? "warn" : "danger", text };
}
