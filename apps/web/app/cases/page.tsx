import { apiFetch, parse, requireSession, type CaseFileSummary } from "../../src/server/pages";

export default async function Cases() {
  const session = await requireSession("/cases");
  const r = await apiFetch(session, "GET", "/case-files");
  const files = r.status === 200 ? (parse<CaseFileSummary[]>(r) ?? []) : undefined;
  return (
    <>
      <h1>Case files</h1>
      <p><a href="/cases/new">New case file</a></p>
      {files === undefined ? (
        <p>You may not list case files with this account ({r.status}).</p>
      ) : files.length === 0 ? (
        <p>Nothing you may see.</p>
      ) : (
        <table>
          <thead><tr><th>Title</th><th>Classification</th><th>Unit</th><th>Status</th></tr></thead>
          <tbody>
            {files.map((f) => (
              <tr key={f.id}>
                <td><a href={`/cases/${f.id}`}>{f.title}</a></td>
                <td>{f.classification}</td>
                <td>{f.unit}</td>
                <td>{f.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
