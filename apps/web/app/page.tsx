import { currentSession } from "../src/server/session";
import { Icon } from "../src/ui/icons";
import { t } from "../src/ui/i18n";

export default async function Home() {
  const session = await currentSession();
  return (
    <section className="hero" aria-labelledby="hero-title">
      <h1 id="hero-title"><span className="brand-mark"><Icon name="shield" /></span>{t.landing.title}</h1>
      <p className="lead">{t.landing.lead}</p>
      {session ? (
        <>
          <p className="mb-4">{t.landing.signedIn}</p>
          <a className="btn" data-kind="primary" href="/cases"><Icon name="folder" />{t.landing.open}</a>
        </>
      ) : (
        <a className="btn" data-kind="primary" href="/api/auth/login"><Icon name="lock" />{t.landing.signIn}</a>
      )}
      <ul className="points">
        <li><Icon name="eye" />{t.landing.pointRecorded}</li>
        <li><Icon name="lock" />{t.landing.pointMfa}</li>
        <li><Icon name="shield" />{t.landing.pointNeed}</li>
      </ul>
      {session ? null : <p className="mt-4 text-sm text-muted">{t.landing.note}</p>}
    </section>
  );
}
