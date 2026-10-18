import { notFound } from "next/navigation";
import { apiFetch, parse, requireSession, type CaseFileSummary } from "../../../src/server/pages";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MESSAGES: Record<string, string> = {
  done: "Done.",
  forbidden: "That action is not allowed.",
  conflict: "The case file changed meanwhile. Reload and try again.",
  invalid: "Please check the fields.",
  stepup: "A second factor is required for this action.",
};

export default async function CaseDetail({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ m?: string }> }) {
  const { id } = await params;
  if (!UUID.test(id)) notFound();
  const session = await requireSession(`/cases/${id}`);
  const { m } = await searchParams;
  const r = await apiFetch(session, "GET", `/case-files/${id}`);
  if (r.stepUp) {
    return (
      <>
        <h1>Second factor required</h1>
        <p>This case file needs a stronger sign-in. <a href={`/api/auth/login?acr=mfa&returnTo=${encodeURIComponent(`/cases/${id}`)}`}>Authenticate with a second factor</a>.</p>
      </>
    );
  }
  if (r.status === 404) notFound();
  const f = r.status === 200 ? parse<CaseFileSummary>(r) : undefined;
  if (!f) {
    return (
      <>
        <h1>Case file</h1>
        <p>This case file cannot be shown ({r.status}).</p>
      </>
    );
  }
  const csrf = <input type="hidden" name="csrf" value={session.csrfToken} />;
  return (
    <>
      <h1>{f.title}</h1>
      {m && MESSAGES[m] ? <p role="alert">{MESSAGES[m]}</p> : null}
      <dl>
        <dt>Classification</dt><dd>{f.classification}</dd>
        <dt>Unit</dt><dd>{f.unit}</dd>
        <dt>Compartments</dt><dd>{f.compartments.join(", ") || "none"}</dd>
        <dt>Status</dt><dd>{f.status}</dd>
        <dt>Version</dt><dd>{f.version}</dd>
      </dl>
      <pre>{f.body}</pre>

      <h2>Edit (drafts only)</h2>
      <form method="post" action={`/actions/case-files/${id}/update`}>
        {csrf}
        <input type="hidden" name="version" value={f.version} />
        <p><label>Title <input name="title" defaultValue={f.title} required maxLength={100} /></label></p>
        <p><label>Body <textarea name="body" rows={6} defaultValue={f.body} maxLength={50000} /></label></p>
        <p><button type="submit">Save</button></p>
      </form>

      <h2>Workflow</h2>
      <form method="post" action={`/actions/case-files/${id}/submit`} style={{ display: "inline" }}>{csrf}<button type="submit">Submit for review</button></form>{" "}
      <form method="post" action={`/actions/case-files/${id}/approve`} style={{ display: "inline" }}>{csrf}<button type="submit">Approve</button></form>{" "}
      <form method="post" action={`/actions/case-files/${id}/delete`} style={{ display: "inline" }}>{csrf}<button type="submit">Delete draft</button></form>

      <p><a href={`/cases/${id}/break-glass`}>Emergency access (break-glass)</a></p>
    </>
  );
}
