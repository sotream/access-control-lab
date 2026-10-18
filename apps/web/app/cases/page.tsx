import { apiFetch, parse, requireSession, type CaseFileSummary } from "../../src/server/pages";
import { CaseList } from "../../src/ui/case-list";
import { parseQuery } from "../../src/ui/cases-query";
import { ErrorView } from "../../src/ui/errors";
import { getMe } from "../../src/server/pages";
import { t } from "../../src/ui/i18n";

export const metadata = { title: t.cases.title };

export default async function Cases({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const session = await requireSession("/cases");
  const q = parseQuery(await searchParams);
  const [r, me] = await Promise.all([apiFetch(session, "GET", "/case-files"), getMe(session)]);
  if (r.status !== 200) return <ErrorView status={r.status === 403 ? 403 : r.status} />;
  const title = me?.roles.includes("unit-admin") && !me.roles.includes("analyst") ? t.cases.titleUnit : me?.roles.includes("analyst") ? t.nav.myCases : t.cases.title;
  return <CaseList rows={parse<CaseFileSummary[]>(r) ?? []} q={q} base="/cases" title={title} />;
}
