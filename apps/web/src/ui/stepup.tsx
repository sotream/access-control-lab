import { Page } from "./components";
import { t } from "./i18n";

/** The explanatory screen before a step-up: says why, what happens next, and changes nothing until the user continues. Shows no case data. */
export function StepUpView({ returnTo, back }: { returnTo: string; back: string }) {
  return (
    <Page title={t.step.title}>
      <div className="alert max-w-2xl" data-tone="warn" role="status"><strong>{t.msg.notice}:</strong>{t.step.lead}</div>
      <section className="panel max-w-2xl" aria-labelledby="su-why"><h2 id="su-why">{t.step.why}</h2><div className="body">{t.step.whyText}</div></section>
      <section className="panel max-w-2xl" aria-labelledby="su-next"><h2 id="su-next">{t.step.what}</h2><div className="body">{t.step.whatText}</div></section>
      <p className="flex gap-2">
        <a className="btn" data-kind="primary" href={`/api/auth/login?acr=mfa&returnTo=${encodeURIComponent(returnTo)}`}>{t.step.go}</a>
        <a className="btn" href={back}>{t.step.back}</a>
      </p>
    </Page>
  );
}
