import { currentSession } from "../src/server/session";
import { Page } from "../src/ui/components";
import { t } from "../src/ui/i18n";

export default async function Home() {
  const session = await currentSession();
  return (
    <Page title={t.landing.title}>
      <p className="mb-4 max-w-2xl">{t.landing.lead}</p>
      {session ? (
        <>
          <p className="mb-3">{t.landing.signedIn}</p>
          <a className="btn" data-kind="primary" href="/cases">{t.landing.open}</a>
        </>
      ) : (
        <>
          <a className="btn" data-kind="primary" href="/api/auth/login">{t.landing.signIn}</a>
          <p className="mt-4 max-w-2xl text-muted">{t.landing.note}</p>
        </>
      )}
    </Page>
  );
}
