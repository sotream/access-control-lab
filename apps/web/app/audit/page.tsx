import { apiFetch, parse, requireSession } from "../../src/server/pages";

interface Row {
  id: number;
  ts: string;
  actor_sub: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  effect: string;
  reason_code: string;
  source: string;
  request_id: string;
}

const KEYS = ["from", "to", "actor", "resource", "action", "effect"] as const;

export default async function AuditPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const session = await requireSession("/audit");
  const q = await searchParams;
  const filters = Object.fromEntries(KEYS.map((k) => [k, typeof q[k] === "string" ? q[k] : undefined]));
  let r;
  try {
    r = await apiFetch(session, "GET", "/audit-log", { query: { ...filters, ...(typeof q.cursor === "string" ? { cursor: q.cursor } : {}), limit: "50" } });
  } catch {
    return <p>The filters are not valid.</p>;
  }
  if (r.status === 403) return <><h1>Audit log</h1><p>Only auditors may read the audit log.</p></>;
  if (r.status !== 200) return <><h1>Audit log</h1><p>The audit log is not available ({r.status}).</p></>;
  const page = parse<{ rows: Row[]; nextCursor: string | null }>(r) ?? { rows: [], nextCursor: null };
  const next = new URLSearchParams(Object.entries(filters).filter(([, v]) => v) as [string, string][]);
  if (page.nextCursor) next.set("cursor", page.nextCursor);
  return (
    <>
      <h1>Audit log</h1>
      <form method="get" action="/audit">
        {KEYS.map((k) => (
          <label key={k}>{k} <input name={k} defaultValue={filters[k] ?? ""} maxLength={64} /> </label>
        ))}
        <button type="submit">Filter</button>
      </form>
      <p><a href="/audit/verify">Verify the chain</a></p>
      <table>
        <thead><tr><th>Id</th><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th><th>Effect</th><th>Reason</th><th>Source</th><th>Request</th></tr></thead>
        <tbody>
          {page.rows.map((x) => (
            <tr key={x.id}>
              <td>{x.id}</td><td>{x.ts}</td><td>{x.actor_sub}</td><td>{x.action}</td><td>{x.resource_id ?? x.resource_type}</td><td>{x.effect}</td><td>{x.reason_code}</td><td>{x.source}</td><td>{x.request_id}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {page.nextCursor ? <p><a href={`/audit?${next}`}>Next page</a></p> : null}
      <h2>Export</h2>
      <form method="post" action="/actions/audit/export">
        <input type="hidden" name="csrf" value={session.csrfToken} />
        {KEYS.map((k) => (filters[k] ? <input key={k} type="hidden" name={k} value={filters[k]} /> : null))}
        <label>Format <select name="format"><option value="ndjson">NDJSON</option><option value="csv">CSV</option></select></label>{" "}
        <button type="submit">Export (this is recorded)</button>
      </form>
    </>
  );
}
