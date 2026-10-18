import { notFound } from "next/navigation";
import { apiFetch, parse, requireSession, type CaseFileSummary } from "../../../src/server/pages";
import { UUID_RE } from "../../../src/server/actions";
import { Alert, Badge, Banner, KV, Mono, Page, Panel, ScanChip, StatusChip, isLevel, utc } from "../../../src/ui/components";
import { ErrorView } from "../../../src/ui/errors";
import { t } from "../../../src/ui/i18n";
import { noticeFor } from "../../../src/ui/messages";
import { StepUpView } from "../../../src/ui/stepup";

interface Attachment { id: string; name: string; mediaType: string; size: number; sha256: string; status: string }
const STEPS = ["draft", "submitted", "approved"] as const;

export const metadata = { title: "Case file" };

export default async function CaseDetail({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ m?: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const session = await requireSession(`/cases/${id}`);
  const { m } = await searchParams;
  const r = await apiFetch(session, "GET", `/case-files/${id}`);
  if (r.stepUp) return <StepUpView returnTo={`/cases/${id}`} back="/cases" />;
  if (r.status === 404) notFound(); // hidden and missing look the same (ADR-9)
  const f = r.status === 200 ? parse<CaseFileSummary>(r) : undefined;
  if (!f) return <ErrorView status={r.status === 403 ? 404 : r.status} />; // 403 on a case file is shown as 404: never tell hidden from forbidden
  const list = await apiFetch(session, "GET", `/case-files/${id}/attachments`);
  const attachments = list.status === 200 ? (parse<Attachment[]>(list) ?? []) : [];
  const csrf = <input type="hidden" name="csrf" value={session.csrfToken} />;
  const n = noticeFor(m);
  const draft = f.status === "draft";
  const submitted = f.status === "submitted";
  const stepIdx = STEPS.indexOf(f.status as (typeof STEPS)[number]);
  return (
    <>
      {isLevel(f.classification) ? <Banner level={f.classification} /> : <Banner level="SECRET" note={t.cls.handling} />}
      <Page title={f.title} actions={draft ? <a className="btn" href={`/cases/${id}/edit`}>{t.detail.edit}</a> : undefined}>
        {n ? <Alert tone={n.tone} live={n.tone === "ok" ? "status" : "alert"}>{n.text}</Alert> : null}
        <div className="grid gap-4 lg:grid-cols-[minmax(0,20rem)_minmax(0,1fr)]">
          <div>
            <Panel title={t.detail.meta} id="p-meta">
              <KV rows={[
                [t.detail.classification, <Badge key="c" level={f.classification} />],
                [t.detail.status, <StatusChip key="s" status={f.status} />],
                [t.detail.unit, f.unit],
                [t.detail.compartments, f.compartments.join(", ") || t.detail.compartmentsNone],
                [t.detail.version, <Mono key="v">{f.version}</Mono>],
                [t.detail.id, <Mono key="i">{id}</Mono>],
                ...(f.authorId ? [[t.detail.author, <Mono key="a" title={f.authorId}>{f.authorId.slice(0, 8)}</Mono>] as [string, React.ReactNode]] : []),
                ...(f.createdAt ? [[t.detail.created, <Mono key="cr">{utc(f.createdAt)}</Mono>] as [string, React.ReactNode]] : []),
                ...(f.updatedAt ? [[t.detail.updated, <Mono key="up">{utc(f.updatedAt)}</Mono>] as [string, React.ReactNode]] : []),
              ]} />
            </Panel>
            <Panel title={t.detail.workflow} id="p-flow">
              <ol className="stepper mb-3" aria-label={t.detail.stepLabel}>
                {STEPS.map((s, i) => <li key={s} {...(i === stepIdx ? { "aria-current": "step" as const } : {})} data-done={i < stepIdx}>{t.detail.step[s]}</li>)}
              </ol>
              <form method="post" action={`/actions/case-files/${id}/submit`} className="inline-form">{csrf}<button type="submit" className="btn" data-kind="primary" disabled={!draft}>{t.detail.submit}</button></form>
              <form method="post" action={`/actions/case-files/${id}/approve`} className="inline-form">{csrf}<button type="submit" className="btn" data-kind="primary" disabled={!submitted}>{t.detail.approve}</button></form>
              <form method="post" action={`/actions/case-files/${id}/delete`} className="inline-form">{csrf}<button type="submit" className="btn" data-kind="danger" disabled={!draft}>{t.detail.delete}</button></form>
              {!draft || !submitted ? <p className="mt-2 text-sm text-muted">{draft ? t.detail.notSubmitted : submitted ? t.detail.notDraft : `${t.detail.notDraft} ${t.detail.notSubmitted}`}</p> : null}
            </Panel>
            <Panel title={t.detail.history} id="p-hist"><p className="text-sm text-muted">{t.detail.historyHint}</p></Panel>
          </div>
          <div>
            <Panel title={t.detail.body} id="p-body"><pre className="doc">{f.body}</pre></Panel>
            <Panel title={t.detail.attachments} id="p-att">
              {attachments.length === 0 ? <p className="empty">{t.detail.noAttachments}</p> : (
                <div className="table-wrap">
                  <table className="tbl">
                    <thead><tr><th scope="col">{t.detail.file}</th><th scope="col">{t.detail.type}</th><th scope="col" className="num">{t.detail.size}</th><th scope="col">{t.detail.sha}</th><th scope="col">{t.detail.scan}</th></tr></thead>
                    <tbody>
                      {attachments.map((a) => (
                        <tr key={a.id}>
                          <th scope="row" className="font-normal">{a.status === "clean" ? <a href={`/attachments/${id}/${a.id}`}>{a.name}</a> : <span title={t.detail.notDownloadable}>{a.name}</span>}</th>
                          <td className="mono">{a.mediaType}</td>
                          <td className="num mono">{a.size} B</td>
                          <td className="mono" title={a.sha256}>{a.sha256.slice(0, 12)}</td>
                          <td><ScanChip status={a.status} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {draft ? (
                <form method="post" action={`/actions/case-files/${id}/attachments`} encType="multipart/form-data" className="mt-4">
                  {csrf}
                  <div className="field">
                    <label htmlFor="att-file">{t.detail.upload}</label>
                    <input id="att-file" type="file" name="file" required aria-describedby="att-file-hint" accept=".pdf,.png,.jpg,.jpeg,.txt,application/pdf,image/png,image/jpeg,text/plain" />
                    <span className="hint" id="att-file-hint">{t.detail.uploadHint}</span>
                  </div>
                  <button type="submit" className="btn">{t.detail.uploadButton}</button>
                </form>
              ) : null}
            </Panel>
            <p><a href={`/cases/${id}/break-glass`}>{t.detail.bg}</a></p>
          </div>
        </div>
      </Page>
    </>
  );
}
