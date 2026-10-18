import { apiFetch, parse, requireSession } from "../../src/server/pages";
import { Alert, Field, Mono, Page, Panel, Status, utc } from "../../src/ui/components";
import { t } from "../../src/ui/i18n";

interface Row {
  id: number;
  ts: string;
  actor_sub: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  effect: string;
  reason_code: string;
  source: string;
  request_id: string;
}
interface Checkpoint { id: number; ts: string; last_id: number; key_id: string }

export const metadata = { title: t.audit.title };

const KEYS = ["from", "to", "actor", "resource", "action", "effect"] as const;
const LABELS: Record<(typeof KEYS)[number], string> = { from: t.audit.from, to: t.audit.to, actor: t.audit.actor, resource: t.audit.resource, action: t.audit.action, effect: t.audit.effect };

export default async function AuditPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const session = await requireSession("/audit");
  const q = await searchParams;
  const filters = Object.fromEntries(KEYS.map((k) => [k, typeof q[k] === "string" ? (q[k] as string).slice(0, 64) : undefined]));
  let r;
  try {
    r = await apiFetch(session, "GET", "/audit-log", { query: { ...filters, ...(typeof q.cursor === "string" ? { cursor: q.cursor } : {}), limit: "50" } });
  } catch {
    return <Page title={t.audit.title}><Alert tone="danger" live="alert">{t.audit.invalidFilters}</Alert><a className="btn" href="/audit">{t.audit.reset}</a></Page>;
  }
  if (r.status === 403) return <Page title={t.audit.title}><Alert tone="warn">{t.audit.only}</Alert></Page>;
  if (r.status !== 200) return <Page title={t.audit.title}><Alert tone="danger" live="alert">{t.audit.unavailable}</Alert></Page>;
  const page = parse<{ rows: Row[]; nextCursor: string | null }>(r) ?? { rows: [], nextCursor: null };
  const cps = await apiFetch(session, "GET", "/audit-log/checkpoints");
  const checkpoints = cps.status === 200 ? (parse<Checkpoint[]>(cps) ?? []) : [];
  const latest = checkpoints.reduce<Checkpoint | undefined>((a, c) => (!a || c.id > a.id ? c : a), undefined);
  const next = new URLSearchParams(Object.entries(filters).filter(([, v]) => v) as [string, string][]);
  if (page.nextCursor) next.set("cursor", page.nextCursor);
  return (
    <Page title={t.audit.title}>
      <form method="get" action="/audit" className="filters" role="search" aria-label={t.audit.filters}>
        {KEYS.filter((k) => k !== "effect").map((k) => (
          <div className="field" key={k}><label htmlFor={`a-${k}`}>{LABELS[k]}</label><input id={`a-${k}`} name={k} defaultValue={filters[k] ?? ""} maxLength={64} className="mono" autoComplete="off" spellCheck={false} /></div>
        ))}
        <div className="field"><label htmlFor="a-effect">{t.audit.effect}</label>
          <select id="a-effect" name="effect" defaultValue={filters.effect ?? ""}><option value="">{t.audit.any}</option><option value="allow">{t.audit.allow}</option><option value="deny">{t.audit.deny}</option></select></div>
        <button type="submit" className="btn" data-kind="primary">{t.audit.apply}</button>
        <a className="btn" href="/audit">{t.audit.reset}</a>
      </form>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_20rem]">
        <div>
          {page.rows.length === 0 ? <p className="empty" role="status">{t.audit.empty}</p> : (
            <div className="table-wrap">
              <table className="tbl">
                <caption>{t.audit.caption}</caption>
                <thead><tr>{(["id", "time", "actor", "action", "resource", "effect", "reason", "source", "request"] as const).map((c) => <th scope="col" key={c}>{t.audit.columns[c]}</th>)}</tr></thead>
                <tbody>
                  {page.rows.map((x) => (
                    <tr key={x.id}>
                      <td className="mono">{x.id}</td>
                      <td className="mono whitespace-nowrap">{x.ts.slice(0, 19).replace("T", " ")}</td>
                      <td className="mono" title={x.actor_sub}>{x.actor_sub.slice(0, 8)}</td>
                      <td className="mono">{x.action}</td>
                      <td className="mono" title={x.resource_id ?? x.resource_type}>{x.resource_id ? x.resource_id.slice(0, 8) : x.resource_type}</td>
                      <td>{x.effect === "allow" ? <Status tone="ok">{t.audit.allow}</Status> : <Status tone="danger">{x.effect === "deny" ? t.audit.deny : x.effect}</Status>}</td>
                      <td className="mono">{x.reason_code}</td>
                      <td className="mono">{x.source}</td>
                      <td className="mono" title={x.request_id}>{x.request_id.slice(0, 8)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {page.nextCursor ? <nav className="pager" aria-label={t.audit.next}><a href={`/audit?${next}`} rel="next">{t.audit.next}</a></nav> : null}
        </div>
        <aside aria-label={t.audit.proof}>
          <Panel title={t.audit.proof} id="p-proof">
            <p className="mb-2 text-sm text-muted">{t.audit.proofLead}</p>
            <p className="mb-2">{latest ? <>{t.audit.lastCheckpoint}: <Mono>#{latest.id}</Mono>, {t.audit.last} <Mono>{latest.last_id}</Mono>, <Mono>{utc(latest.ts)}</Mono></> : t.audit.noCheckpoints}</p>
            <p className="mb-2 text-sm">{t.audit.checkpoints}: <Mono>{checkpoints.length}</Mono></p>
            <a className="btn" href="/audit/verify">{t.audit.verifyLink}</a>
          </Panel>
          <Panel title={t.audit.export} id="p-export">
            <p className="mb-2 text-sm text-muted">{t.audit.exportLead}</p>
            <form method="post" action="/actions/audit/export">
              <input type="hidden" name="csrf" value={session.csrfToken} />
              {KEYS.map((k) => (filters[k] ? <input key={k} type="hidden" name={k} value={filters[k]} /> : null))}
              <Field id="x-format" label={t.audit.format}><select id="x-format" name="format"><option value="ndjson">NDJSON</option><option value="csv">CSV</option></select></Field>
              <button type="submit" className="btn" data-kind="primary">{t.audit.exportButton}</button>
            </form>
          </Panel>
        </aside>
      </div>
    </Page>
  );
}
