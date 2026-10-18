import { requireSession } from "../../../src/server/pages";
import { Alert, Field, LEVELS, Page } from "../../../src/ui/components";
import { t } from "../../../src/ui/i18n";

export const metadata = { title: t.form.newTitle };

const MESSAGES: Record<string, string> = { forbidden: t.msg.createForbidden, invalid: t.msg.invalid, stepup: t.msg.createStepup };

export default async function NewCase({ searchParams }: { searchParams: Promise<{ e?: string }> }) {
  const session = await requireSession("/cases/new");
  const { e } = await searchParams;
  const message = e && Object.hasOwn(MESSAGES, e) ? MESSAGES[e] : undefined; // only known codes are shown; nothing from the URL is reflected
  return (
    <Page title={t.form.newTitle}>
      {message ? <Alert tone="danger" live="alert">{message}{e === "stepup" ? <> <a href="/api/auth/login?acr=mfa&returnTo=%2Fcases%2Fnew">{t.msg.reauth}</a></> : null}</Alert> : null}
      <form method="post" action="/actions/case-files/create" className="max-w-3xl">
        <input type="hidden" name="csrf" value={session.csrfToken} />
        <Field id="n-title" label={t.form.title} hint={t.form.titleHint}><input id="n-title" name="title" required maxLength={100} aria-describedby="n-title-hint" /></Field>
        <Field id="n-body" label={t.form.body} hint={t.form.bodyHint}><textarea id="n-body" name="body" rows={10} maxLength={50000} aria-describedby="n-body-hint" /></Field>
        <Field id="n-cls" label={t.form.classification}><select id="n-cls" name="classification">{LEVELS.map((l) => <option key={l} value={l}>{t.cls[l]}</option>)}</select></Field>
        <Field id="n-comp" label={t.form.compartments} hint={t.form.compartmentsHint}><input id="n-comp" name="compartments" aria-describedby="n-comp-hint" autoComplete="off" /></Field>
        <p className="flex gap-2"><button type="submit" className="btn" data-kind="primary">{t.form.create}</button><a className="btn" href="/cases">{t.form.cancel}</a></p>
      </form>
    </Page>
  );
}
