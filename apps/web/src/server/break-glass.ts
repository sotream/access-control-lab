// The justification travels from the form POST to the result page in a short-lived, HttpOnly, host-only cookie (never in a URL).
// It is user text, not a secret; the cookie is only ever set by a POST that passed the CSRF checks, and the page re-checks the case-file id.
const MAX_JUSTIFICATION = 500;
export const BG_COOKIE_SECONDS = 120;

export const packJustification = (id: string, justification: string): string => `${id}.${Buffer.from(justification, "utf8").toString("base64url")}`;

/** The justification stored for this case file, or undefined (absent, for another case file, malformed, too short or too long). */
export function unpackJustification(value: string | undefined, id: string): string | undefined {
  if (!value?.startsWith(`${id}.`)) return undefined;
  const b64 = value.slice(id.length + 1);
  if (b64.length === 0 || b64.length > 3000 || !/^[A-Za-z0-9_-]+$/.test(b64)) return undefined;
  const text = Buffer.from(b64, "base64url").toString("utf8").trim();
  return text.length >= 5 && text.length <= MAX_JUSTIFICATION ? text : undefined;
}
