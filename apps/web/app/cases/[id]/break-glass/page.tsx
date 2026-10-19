import { notFound } from "next/navigation";
import { requireSession } from "../../../../src/server/pages";
import { UUID_RE } from "../../../../src/server/actions";
import { Alert, Field, Page } from "../../../../src/ui/components";
import { Icon } from "../../../../src/ui/icons";
import { t } from "../../../../src/ui/i18n";

export const metadata = { title: t.bg.title };

export default async function BreakGlass({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ e?: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const session = await requireSession(`/cases/${id}/break-glass`);
  const { e } = await searchParams;
  const problem = e === "short" ? t.bg.needReasonText : e === "expired" ? t.bg.expired : undefined; // fixed codes only
  return (
    <Page title={t.bg.title}>
      {problem ? <Alert tone="danger" live="alert">{problem}</Alert> : null}
      <form method="post" action={`/actions/case-files/${id}/break-glass`} className="glass max-w-3xl" aria-labelledby="bg-frame">
        <h2 id="bg-frame"><Icon name="alert" />{t.bg.frame}</h2>
        <p className="mb-3">{t.bg.warn}</p>
        <input type="hidden" name="csrf" value={session.csrfToken} />
        <Field id="bg-just" label={t.bg.justification} hint={t.bg.justHint}>
          <textarea id="bg-just" name="justification" rows={5} required minLength={5} maxLength={500} aria-describedby="bg-just-hint" />
        </Field>
        <p className="flex gap-2"><button type="submit" className="btn" data-kind="danger">{t.bg.submit}</button><a className="btn" href={`/cases/${id}`}>{t.form.cancel}</a></p>
      </form>
    </Page>
  );
}
