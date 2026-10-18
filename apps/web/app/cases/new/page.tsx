import { requireSession } from "../../../src/server/pages";

const MESSAGES: Record<string, string> = { forbidden: "You may not create this case file.", invalid: "Please check the fields.", stepup: "A second factor is required for this classification." };

export default async function NewCase({ searchParams }: { searchParams: Promise<{ e?: string }> }) {
  const session = await requireSession("/cases/new");
  const { e } = await searchParams;
  const message = e ? MESSAGES[e] : undefined; // only known codes are shown; nothing from the URL is reflected
  return (
    <>
      <h1>New case file</h1>
      {message ? <p role="alert">{message}{e === "stepup" ? <> <a href="/api/auth/login?acr=mfa&amp;returnTo=%2Fcases%2Fnew">Authenticate again</a></> : null}</p> : null}
      <form method="post" action="/actions/case-files/create">
        <input type="hidden" name="csrf" value={session.csrfToken} />
        <p><label>Title <input name="title" required maxLength={100} /></label></p>
        <p><label>Body <textarea name="body" rows={6} maxLength={50000} /></label></p>
        <p><label>Classification <select name="classification"><option>OFFICIAL</option><option>CONFIDENTIAL</option><option>SECRET</option></select></label></p>
        <p><label>Compartments (comma separated) <input name="compartments" /></label></p>
        <p><button type="submit">Create draft</button></p>
      </form>
    </>
  );
}
