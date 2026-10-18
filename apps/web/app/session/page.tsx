import { apiFetch, parse, requireSession, type Me } from "../../src/server/pages";
import { Alert, Badge, KV, Mono, Page, Panel, Status, utc } from "../../src/ui/components";
import { ErrorView } from "../../src/ui/errors";
import { t } from "../../src/ui/i18n";

export const metadata = { title: t.session.title };

export default async function SessionPage() {
  const session = await requireSession("/session");
  const r = await apiFetch(session, "GET", "/me"); // the API's own view of this session, not the token's
  const me = r.status === 200 ? parse<Me>(r) : undefined;
  if (!me) return <ErrorView status={r.status === 200 ? 503 : r.status} />;
  const mfa = me.acr === "mfa";
  return (
    <Page title={t.session.title}>
      {mfa ? <Alert tone="ok">{t.session.stepUpOk}</Alert> : <Alert tone="warn">{t.session.stepUpNo}</Alert>}
      <Panel title={t.session.title} id="p-session">
        <KV rows={[
          [t.session.subject, <Mono key="s">{me.sub}</Mono>],
          [t.session.roles, me.roles.join(", ") || t.bar.none],
          [t.session.clearance, <Badge key="c" level={me.clearance} />],
          [t.session.unit, me.unit],
          [t.session.compartments, me.compartments.join(", ") || t.bar.none],
          [t.session.level, <span key="a">{mfa ? <Status tone="ok">{t.bar.mfa}</Status> : <Status tone="warn">{t.bar.pwd}</Status>} <Mono>{me.acr}</Mono></span>],
          [t.session.methods, <Mono key="m">{me.amr.join(", ")}</Mono>],
          [t.session.expires, <Mono key="e">{utc(session.expiresAt)}</Mono>],
        ]} />
      </Panel>
      {mfa ? null : <p><a className="btn" data-kind="primary" href="/api/auth/login?acr=mfa&returnTo=%2Fsession">{t.session.stepUp}</a></p>}
    </Page>
  );
}
