import { apiFetch, parse, requireSession } from "../../../src/server/pages";
import { Alert, KV, Mono, Page, Panel } from "../../../src/ui/components";
import { ErrorView } from "../../../src/ui/errors";
import { t } from "../../../src/ui/i18n";

export const metadata = { title: t.audit.verifyTitle };

interface Verdict { ok: boolean; checked: number; lastId: number; issues: { id: number | null; code: string; message: string }[] }

export default async function Verify() {
  const session = await requireSession("/audit/verify");
  const r = await apiFetch(session, "GET", "/audit-log/verify");
  if (r.status === 403) return <Page title={t.audit.verifyTitle}><Alert tone="warn">{t.audit.only}</Alert></Page>;
  const v = r.status === 200 ? parse<Verdict>(r) : undefined;
  if (!v) return <ErrorView status={r.status === 200 ? 503 : r.status} />;
  return (
    <Page title={t.audit.verifyTitle} actions={<a className="btn" href="/audit">{t.audit.back}</a>}>
      {v.ok ? <Alert tone="ok">{t.audit.verified}</Alert> : <Alert tone="danger" live="alert">{t.audit.broken}</Alert>}
      <Panel title={t.audit.proof} id="p-v">
        <KV rows={[[t.audit.rows, <Mono key="r">{v.checked}</Mono>], [t.audit.last, <Mono key="l">{v.lastId}</Mono>]]} />
      </Panel>
      <Panel title={t.audit.issues} id="p-i">
        {v.issues.length === 0 ? <p>{t.audit.noIssues}</p> : (
          <ul className="list-disc pl-5">{v.issues.map((i, n) => <li key={n}><Mono>{i.code}</Mono> ({i.id ?? "chain"}): {i.message}</li>)}</ul>
        )}
      </Panel>
    </Page>
  );
}
