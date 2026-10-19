import { Badge, Banner, Empty, Page, StatusChip, TableWrap, highest, statusLabel } from "./components";
import { applyQuery, hrefFor, PAGE_SIZE, SORTS, STATUS_VALUES, type Query, type Row, type SortKey } from "./cases-query";
import { LEVELS } from "./components";
import { Icon } from "./icons";
import { t } from "./i18n";

/** The list used by "my cases", "unit cases" and the review queue: filters, sortable headers, pagination, all via GET (works without script). */
export function CaseList({ rows, q, base, title, lead, fixedStatus, canCreate }: { rows: Row[]; q: Query; base: string; title: string; lead?: string; fixedStatus?: boolean; canCreate: boolean }) {
  const { rows: shown, total, pages } = applyQuery(rows, q);
  const page = Math.min(q.page, pages);
  const level = highest(shown.map((r) => r.classification));
  const units = [...new Set(rows.map((r) => r.unit))].sort();
  const col = (k: SortKey, label: string) => {
    const on = q.sort === k;
    const dir = on && q.dir === "asc" ? "desc" : "asc";
    return (
      <th scope="col" aria-sort={on ? (q.dir === "asc" ? "ascending" : "descending") : "none"}>
        <a href={hrefFor(base, q, { sort: k, dir, page: 1 })}>{label}{on ? (q.dir === "asc" ? " ▲" : " ▼") : ""}</a>
      </th>
    );
  };
  return (
    <>
      {level ? <Banner level={level} /> : null}
      <Page title={title} actions={canCreate ? <a className="btn" data-kind="primary" href="/cases/new"><Icon name="plus" />{t.cases.newCase}</a> : undefined}>
        {lead ? <p className="mb-3 text-muted">{lead}</p> : null}
        <form method="get" action={base} className="filters" role="search" aria-label={t.cases.filters.label}>
          <div className="field"><label htmlFor="f-q">{t.cases.filters.text}</label><input id="f-q" name="q" defaultValue={q.q} maxLength={100} /></div>
          {fixedStatus ? null : (
            <div className="field"><label htmlFor="f-status">{t.cases.filters.status}</label>
              <select id="f-status" name="status" defaultValue={q.status}><option value="">{t.cases.filters.any}</option>{STATUS_VALUES.map((s) => <option key={s} value={s}>{statusLabel(s)}</option>)}</select></div>
          )}
          <div className="field"><label htmlFor="f-cls">{t.cases.filters.level}</label>
            <select id="f-cls" name="cls" defaultValue={q.level}><option value="">{t.cases.filters.any}</option>{LEVELS.map((l) => <option key={l} value={l}>{t.cls[l]}</option>)}</select></div>
          <div className="field"><label htmlFor="f-unit">{t.cases.filters.unit}</label>
            <select id="f-unit" name="unit" defaultValue={q.unit}><option value="">{t.cases.filters.any}</option>{units.map((u) => <option key={u} value={u}>{u}</option>)}</select></div>
          <input type="hidden" name="sort" value={q.sort} />
          <input type="hidden" name="dir" value={q.dir} />
          <button type="submit" className="btn" data-kind="primary"><Icon name="search" />{t.cases.filters.apply}</button>
          <a className="btn" href={base}>{t.cases.filters.reset}</a>
        </form>
        {rows.length === 0 ? (
          <Empty icon="folder">{t.cases.emptyAll}</Empty>
        ) : shown.length === 0 ? (
          <Empty icon="search" live>{t.cases.empty}</Empty>
        ) : (
          <TableWrap label={t.cases.captionList}>
            <table className="tbl">
              <caption>{t.cases.captionList}: {shown.length} {t.cases.of} {total}</caption>
              <thead><tr>{col("title", t.cases.columns.title)}{col("classification", t.cases.columns.classification)}{col("unit", t.cases.columns.unit)}{col("status", t.cases.columns.status)}<th scope="col">{t.cases.columns.id}</th></tr></thead>
              <tbody>
                {shown.map((r) => (
                  <tr key={r.id}>
                    <th scope="row" className="font-normal"><a href={`/cases/${r.id}`}>{r.title}</a></th>
                    <td><Badge level={r.classification} /></td>
                    <td>{r.unit}</td>
                    <td><StatusChip status={r.status} /></td>
                    <td className="mono">{r.id.slice(0, 8)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
        {pages > 1 ? (
          <nav className="pager" aria-label={t.cases.page}>
            {page > 1 ? <a href={hrefFor(base, q, { page: page - 1 })} rel="prev">{t.cases.prev}</a> : null}
            <span>{t.cases.page} {page} {t.cases.of} {pages} ({PAGE_SIZE})</span>
            {page < pages ? <a href={hrefFor(base, q, { page: page + 1 })} rel="next">{t.cases.next}</a> : null}
          </nav>
        ) : null}
      </Page>
    </>
  );
}

export { SORTS };
