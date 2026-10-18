import "./globals.css";
import type { ReactNode } from "react";
import { currentSession } from "../src/server/session";

export const metadata = { title: "Casefile Vault" };
export const dynamic = "force-dynamic"; // every response is per request: nonce, session, no caching

export default async function RootLayout({ children }: { children: ReactNode }) {
  const session = await currentSession();
  return (
    <html lang="en">
      <body>
        <header>
          <nav>
            <a href="/">Home</a> | <a href="/cases">Case files</a> | <a href="/session">Session</a>
            {session ? (
              <form method="post" action="/api/auth/logout" style={{ display: "inline" }}>
                {" | "}
                <input type="hidden" name="csrf" value={session.csrfToken} />
                <button type="submit">Sign out</button>
              </form>
            ) : (
              <>
                {" | "}
                <a href="/api/auth/login">Sign in</a>
              </>
            )}
          </nav>
        </header>
        <main>{children}</main>
      </body>
    </html>
  );
}
