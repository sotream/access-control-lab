import { notFound } from "next/navigation";
import { requireSession } from "../../../../src/server/pages";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export default async function BreakGlass({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID.test(id)) notFound();
  const session = await requireSession(`/cases/${id}/break-glass`);
  return (
    <>
      <h1>Emergency access</h1>
      <p>Reading outside your need-to-know is recorded and raises an alert. Give a reason.</p>
      <form method="post" action={`/actions/case-files/${id}/break-glass`}>
        <input type="hidden" name="csrf" value={session.csrfToken} />
        <p><label>Justification <textarea name="justification" rows={4} required minLength={5} maxLength={500} /></label></p>
        <p><button type="submit">Read with break-glass</button></p>
      </form>
    </>
  );
}
