import { cookies } from "next/headers";
import { notFound, redirect } from "next/navigation";
import { apiFetch, parse, requireSession, type CaseFileSummary } from "../../../../../src/server/pages";
import { UUID_RE } from "../../../../../src/server/actions";
import { unpackJustification } from "../../../../../src/server/break-glass";
import { breakGlassCookieName } from "../../../../../src/server/cookies";
import { Badge, Banner, KV, Mono, Page, Panel, StatusChip, isLevel } from "../../../../../src/ui/components";
import { ErrorView } from "../../../../../src/ui/errors";
import { t } from "../../../../../src/ui/i18n";
import { StepUpView } from "../../../../../src/ui/stepup";

export const metadata = { title: t.bg.resultTitle };

/** The audited read. Every render is a read and is recorded; the case file is shown in a frame nothing else on the site uses. */
export default async function BreakGlassResult({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const session = await requireSession(`/cases/${id}/break-glass`);
  const justification = unpackJustification((await cookies()).get(breakGlassCookieName())?.value, id);
  if (!justification) redirect(`/cases/${id}/break-glass?e=expired`);
  const r = await apiFetch(session, "GET", `/case-files/${id}`, { breakGlass: justification });
  if (r.stepUp) return <StepUpView returnTo={`/cases/${id}`} back={`/cases/${id}`} />;
  if (r.status === 404 || r.status === 403) notFound(); // same page for hidden, missing and refused (ADR-9)
  const f = r.status === 200 ? parse<CaseFileSummary>(r) : undefined;
  if (!f) return <ErrorView status={r.status} />;
  return (
    <>
      <Banner level={isLevel(f.classification) ? f.classification : "SECRET"} />
      <Page title={t.bg.resultTitle}>
        <div className="glass" role="status"><h2>{t.bg.frame}</h2><p>{t.bg.audited}</p></div>
        <Panel title={f.title} id="bgr">
          <KV rows={[
            [t.detail.classification, <Badge key="c" level={f.classification} />],
            [t.detail.unit, f.unit],
            [t.detail.compartments, f.compartments.join(", ") || t.detail.compartmentsNone],
            [t.detail.status, <StatusChip key="s" status={f.status} />],
            [t.detail.id, <Mono key="i">{id}</Mono>],
          ]} />
        </Panel>
        <Panel title={t.detail.body} id="bgb"><pre className="doc">{f.body ?? ""}</pre></Panel>
        <a className="btn" href="/cases">{t.bg.back}</a>
      </Page>
    </>
  );
}
