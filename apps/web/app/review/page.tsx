import { apiFetch, parse, requireSession, type CaseFileSummary } from "../../src/server/pages";
import { CaseList } from "../../src/ui/case-list";
import { parseQuery } from "../../src/ui/cases-query";
import { ErrorView } from "../../src/ui/errors";
import { t } from "../../src/ui/i18n";

export const metadata = { title: t.cases.titleReview };

/** The same list, fixed to submitted case files. What the reviewer may actually see is still decided by the API. */
export default async function Review({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const session = await requireSession("/review");
  const q = { ...parseQuery(await searchParams), status: "submitted" };
  const r = await apiFetch(session, "GET", "/case-files");
  if (r.status !== 200) return <ErrorView status={r.status} />;
  return <CaseList rows={parse<CaseFileSummary[]>(r) ?? []} q={q} base="/review" title={t.cases.titleReview} lead={t.cases.reviewLead} fixedStatus canCreate={false} />;
}
