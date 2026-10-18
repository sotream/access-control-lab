import type { ReactNode } from "react";
import { headers } from "next/headers";
import { currentSession } from "../src/server/session";
import { getMe } from "../src/server/pages";
import { currentTheme } from "../src/server/theme";
import { Chrome } from "../src/ui/chrome";
import { t } from "../src/ui/i18n";

export const metadata = { title: { default: t.product, template: `%s | ${t.product}` }, robots: { index: false, follow: false } };
export const dynamic = "force-dynamic"; // every response is per request: nonce, session, no caching

export default async function RootLayout({ children }: { children: ReactNode }) {
  const [session, theme, h] = await Promise.all([currentSession(), currentTheme(), headers()]);
  const me = session ? await getMe(session) : undefined;
  const nonce = h.get("x-nonce") ?? undefined;
  const path = h.get("x-pathname") ?? "/";
  return (
    <html lang="en" {...(theme === "system" ? {} : { "data-theme": theme })}>
      <head>
        <link rel="stylesheet" href="/ui.css" nonce={nonce} />
      </head>
      <body>
        <Chrome me={me} csrf={session?.csrfToken} expiresAt={session?.expiresAt} theme={theme} path={path} nonce={nonce}>{children}</Chrome>
      </body>
    </html>
  );
}
