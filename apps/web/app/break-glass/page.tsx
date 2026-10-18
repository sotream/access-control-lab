import { redirect } from "next/navigation";
import { requireSession } from "../../src/server/pages";
import { UUID_RE } from "../../src/server/actions";
import { Alert, Field, Page } from "../../src/ui/components";
import { t } from "../../src/ui/i18n";

export const metadata = { title: t.bg.enterTitle };

/** Entry point for emergency access: ask for the case file identifier, then continue to the justification page. GET only; nothing is recorded here. */
export default async function BreakGlassEntry({ searchParams }: { searchParams: Promise<{ id?: string | string[] }> }) {
  await requireSession("/break-glass");
  const { id } = await searchParams;
  const given = typeof id === "string" ? id.trim().toLowerCase() : undefined;
  if (given && UUID_RE.test(given)) redirect(`/cases/${given}/break-glass`);
  return (
    <Page title={t.bg.enterTitle}>
      <p className="mb-3 max-w-2xl">{t.bg.enterLead}</p>
      {given !== undefined ? <Alert tone="danger" live="alert">{t.bg.badId}</Alert> : null}
      <form method="get" action="/break-glass" className="max-w-xl">
        <Field id="bg-id" label={t.bg.caseId} hint={t.bg.caseIdHint}>
          <input id="bg-id" name="id" className="mono" required maxLength={36} autoComplete="off" spellCheck={false} aria-describedby="bg-id-hint" {...(given !== undefined ? { "aria-invalid": true } : {})} />
        </Field>
        <button type="submit" className="btn" data-kind="primary">{t.bg.continue}</button>
      </form>
    </Page>
  );
}
