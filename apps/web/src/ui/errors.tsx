import { Icon, type IconName } from "./icons";
import { t } from "./i18n";

export type ErrorStatus = 400 | 401 | 403 | 404 | 429 | 500 | 503;
const KNOWN: readonly number[] = [400, 401, 403, 404, 429, 500, 503];
export const errorStatus = (n: number): ErrorStatus => (KNOWN.includes(n) ? (n as ErrorStatus) : n === 502 || n === 504 ? 503 : 500);

/**
 * One generic text per status. 403 and 404 for a case file are the same text on purpose (ADR-9): the page never says
 * whether something exists. Nothing from the request, the API or the exception is shown.
 */
const ICON: Record<ErrorStatus, IconName> = { 400: "alert", 401: "lock", 403: "lock", 404: "search", 429: "clock", 500: "alert", 503: "alert" };

export function ErrorView({ status }: { status: number }) {
  const s = errorStatus(status);
  return (
    <section className="errorview" aria-labelledby="err-title">
      <p className="code" aria-label={`${t.err.status} ${s}`}><Icon name={ICON[s]} /> {s}</p>
      <h1 id="err-title">{t.err.title[s]}</h1>
      <p>{t.err.text[s]}</p>
      <p>{s === 401 ? <a className="btn" data-kind="primary" href="/api/auth/login">{t.err.signIn}</a> : <a className="btn" href="/">{t.err.home}</a>}</p>
    </section>
  );
}
