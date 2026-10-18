import { apiFetch, parse, requireSession } from "../../../src/server/pages";

export default async function Verify() {
  const session = await requireSession("/audit/verify");
  const r = await apiFetch(session, "GET", "/audit-log/verify");
  const v = r.status === 200 ? parse<{ ok: boolean; checked: number; lastId: number; issues: { id: number | null; code: string; message: string }[] }>(r) : undefined;
  return (
    <>
      <h1>Audit chain verification</h1>
      {v ? (
        <>
          <p>{v.ok ? "The chain verifies." : "THE CHAIN DOES NOT VERIFY."} Rows checked: {v.checked}, last id {v.lastId}.</p>
          <ul>{v.issues.map((i, n) => <li key={n}>{i.code} at {i.id ?? "chain"}: {i.message}</li>)}</ul>
        </>
      ) : (
        <p>Verification is not available ({r.status}).</p>
      )}
      <p><a href="/audit">Back to the audit log</a></p>
    </>
  );
}
