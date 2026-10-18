import { apiFetch, parse, requireSession } from "../../src/server/pages";

interface Me {
  sub: string;
  roles: string[];
  clearance: string;
  unit: string;
  compartments: string[];
  acr: string;
  amr: string[];
  authTime: number;
}

export default async function SessionPage() {
  const session = await requireSession("/session");
  const r = await apiFetch(session, "GET", "/me");
  const me = r.status === 200 ? parse<Me>(r) : undefined;
  return (
    <>
      <h1>Session</h1>
      {me ? (
        <dl>
          <dt>Subject</dt><dd>{me.sub}</dd>
          <dt>Roles</dt><dd>{me.roles.join(", ")}</dd>
          <dt>Clearance</dt><dd>{me.clearance}</dd>
          <dt>Unit</dt><dd>{me.unit}</dd>
          <dt>Compartments</dt><dd>{me.compartments.join(", ") || "none"}</dd>
          <dt>Authentication level</dt><dd>{me.acr} ({me.amr.join(", ")})</dd>
          <dt>Session expires</dt><dd>{session.expiresAt.toISOString()}</dd>
        </dl>
      ) : (
        <p>The API did not accept this session ({r.status}).</p>
      )}
      <p><a href="/api/auth/login?acr=mfa&amp;returnTo=%2Fsession">Re-authenticate with a second factor</a></p>
    </>
  );
}
