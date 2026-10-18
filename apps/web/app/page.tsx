import { currentSession } from "../src/server/session";

export default async function Home() {
  const session = await currentSession();
  return (
    <>
      <h1>Casefile Vault</h1>
      {session ? <p>You are signed in. Open the <a href="/cases">case files</a>.</p> : <p>Please <a href="/api/auth/login">sign in</a>.</p>}
    </>
  );
}
