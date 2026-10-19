import type { ReactNode } from "react";
import { Icon, type IconName } from "./icons";
import { t } from "./i18n";

export const LEVELS = ["OFFICIAL", "CONFIDENTIAL", "SECRET"] as const;
export type Level = (typeof LEVELS)[number];
export const isLevel = (v: unknown): v is Level => typeof v === "string" && (LEVELS as readonly string[]).includes(v);
export const rank = (v: string): number => LEVELS.indexOf(v as Level);

/** highest classification of the given values; unknown values count as the highest (fail loud, not quiet) */
export function highest(values: readonly string[]): Level | undefined {
  if (values.length === 0) return undefined;
  let best: Level = "OFFICIAL";
  for (const v of values) {
    if (!isLevel(v)) return "SECRET";
    if (rank(v) > rank(best)) best = v;
  }
  return best;
}

/** Text label always; the colour and the border style are extra cues, never the only ones. */
export function Badge({ level }: { level: string }) {
  return isLevel(level) ? <span className="badge" data-level={level}>{t.cls[level]}</span> : <span className="chip" data-tone="danger">{level.slice(0, 20)}</span>;
}

export function Banner({ level, note }: { level: Level; note?: string }) {
  return (
    <div className="banner" data-level={level} role="note" aria-label={`${t.cls.highest}: ${t.cls[level]}`}>
      <span>{t.cls[level]}</span>
      <small>{note ?? `${t.cls.highest}. ${t.cls.handling}.`}</small>
    </div>
  );
}

export function Chip({ tone, status, children }: { tone?: "ok" | "warn" | "danger" | "info"; status?: string; children: ReactNode }) {
  return <span className="chip" data-tone={tone} data-status={status}>{children}</span>;
}

/** one glyph next to the word: a second cue for people who cannot tell the colours apart */
const GLYPH = { ok: "✓ ", warn: "! ", danger: "✗ ", info: "i " } as const;
export function Status({ tone, children }: { tone: "ok" | "warn" | "danger" | "info"; children: ReactNode }) {
  return <span className="chip" data-tone={tone}><span aria-hidden="true">{GLYPH[tone]}</span>{children}</span>;
}

export const statusLabel = (s: string): string => (Object.hasOwn(t.status, s) ? t.status[s as keyof typeof t.status] : s);
export function StatusChip({ status }: { status: string }) {
  return <Chip status={status} tone={status === "approved" ? "ok" : status === "submitted" ? "info" : undefined}>{statusLabel(status)}</Chip>;
}

export function ScanChip({ status }: { status: string }) {
  if (status === "clean") return <Status tone="ok">{t.scan.clean}</Status>;
  if (status === "pending") return <Status tone="warn">{t.scan.pending}</Status>;
  if (status === "quarantined") return <Status tone="danger">{t.scan.quarantined}</Status>;
  return <Status tone="warn">{t.scan.unknown}</Status>;
}

/** role="alert" is announced at once; role="status" politely. Both carry a word, not only a colour. */
export function Alert({ tone, children, live = "status" }: { tone: "info" | "ok" | "warn" | "danger"; children: ReactNode; live?: "alert" | "status" }) {
  const word = tone === "danger" ? t.msg.problem : tone === "ok" ? t.msg.ok : t.msg.notice;
  const icon: IconName = tone === "ok" ? "check" : tone === "info" ? "info" : "alert";
  return <div className="alert" data-tone={tone} role={live}><Icon name={icon} /><div><strong>{word}:</strong>{children}</div></div>;
}

export function Panel({ title, id, children }: { title: string; id: string; children: ReactNode }) {
  return (
    <section className="panel" aria-labelledby={id}>
      <h2 id={id}>{title}</h2>
      <div className="body">{children}</div>
    </section>
  );
}

export function KV({ rows }: { rows: [string, ReactNode][] }) {
  return <dl className="kv">{rows.map(([k, v]) => <div key={k} className="contents"><dt>{k}</dt><dd>{v}</dd></div>)}</dl>;
}

export function Field({ id, label, hint, error, children }: { id: string; label: string; hint?: string; error?: string; children: ReactNode }) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children}
      {hint ? <span className="hint" id={`${id}-hint`}>{hint}</span> : null}
      {error ? <span className="hint" id={`${id}-err`} role="alert">{error}</span> : null}
    </div>
  );
}

export const Mono = ({ children, title }: { children: ReactNode; title?: string }) => <span className="mono" title={title}>{children}</span>;

export function Page({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <>
      <div className="page-head"><h1>{title}</h1>{actions ? <div className="actions">{actions}</div> : null}</div>
      {children}
    </>
  );
}

export const shortId = (s: string): string => s.slice(0, 8);
export const utc = (iso: string | Date): string => new Date(iso).toISOString().slice(0, 19).replace("T", " ") + " UTC";

/** A table inside a scroll container: the container takes focus so the keyboard can scroll it, and it has a name. */
export function TableWrap({ label, children }: { label: string; children: ReactNode }) {
  return <div className="table-wrap" role="region" aria-label={label} tabIndex={0}>{children}</div>;
}

/** Empty state: an icon and the sentence that says what is missing (and, where one exists, the way forward). */
export function Empty({ icon, children, live }: { icon: IconName; children: ReactNode; live?: boolean }) {
  return <div className="empty" {...(live ? { role: "status" } : {})}><Icon name={icon} /><p>{children}</p></div>;
}
