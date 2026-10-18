import { notFound } from "next/navigation";
import { apiFetch, parse, requireSession, type CaseFileSummary } from "../../../../src/server/pages";
import { UUID_RE } from "../../../../src/server/actions";
import { Alert, Banner, Field, Page, isLevel } from "../../../../src/ui/components";
import { ErrorView } from "../../../../src/ui/errors";
import { t } from "../../../../src/ui/i18n";
import { StepUpView } from "../../../../src/ui/stepup";

export const metadata = { title: t.form.editTitle };

export default async function EditCase({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const session = await requireSession(`/cases/${id}`);
  const r = await apiFetch(session, "GET", `/case-files/${id}`);
  if (r.stepUp) return <StepUpView returnTo={`/cases/${id}`} back="/cases" />;
  if (r.status === 404 || r.status === 403) notFound();
  const f = r.status === 200 ? parse<CaseFileSummary>(r) : undefined;
  if (!f) return <ErrorView status={r.status} />;
  return (
    <>
      {isLevel(f.classification) ? <Banner level={f.classification} /> : null}
      <Page title={t.form.editTitle}>
        {f.status !== "draft" ? <Alert tone="warn">{t.detail.editHint}</Alert> : null}
        <form method="post" action={`/actions/case-files/${id}/update`} className="max-w-3xl">
          <input type="hidden" name="csrf" value={session.csrfToken} />
          <input type="hidden" name="version" value={f.version} />
          <Field id="e-title" label={t.form.title} hint={t.form.titleHint}><input id="e-title" name="title" defaultValue={f.title} required maxLength={100} aria-describedby="e-title-hint" /></Field>
          <Field id="e-body" label={t.form.body} hint={t.form.bodyHint}><textarea id="e-body" name="body" rows={14} defaultValue={f.body} maxLength={50000} aria-describedby="e-body-hint" /></Field>
          <p className="flex gap-2"><button type="submit" className="btn" data-kind="primary" disabled={f.status !== "draft"}>{t.form.save}</button><a className="btn" href={`/cases/${id}`}>{t.form.cancel}</a></p>
        </form>
      </Page>
    </>
  );
}
