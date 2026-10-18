import type { ReactNode } from "react";
import { Badge, Chip, Status, utc } from "./components";
import { t } from "./i18n";
import { navFor } from "./nav";
import type { Me } from "../server/pages";
import type { Theme } from "../server/theme";

interface ChromeProps {
  me?: Me | undefined;
  /** present when signed in */
  csrf?: string | undefined;
  expiresAt?: Date | undefined;
  theme: Theme;
  path: string;
  nonce?: string | undefined;
  children: ReactNode;
}

const THEMES: Theme[] = ["system", "light", "dark"];
const themeLabel = (x: Theme) => (x === "light" ? t.bar.themeLight : x === "dark" ? t.bar.themeDark : t.bar.themeSystem);

/** Theme choice is a plain form (no script needed): the server sets the cookie and renders data-theme on <html>. */
function ThemeForm({ theme, csrf, path }: { theme: Theme; csrf?: string | undefined; path: string }) {
  return (
    <form method="post" action="/actions/theme" className="inline-form">
      {csrf ? <input type="hidden" name="csrf" value={csrf} /> : null}
      <input type="hidden" name="next" value={path} />
      <label htmlFor="theme-select" className="sr-only">{t.bar.theme}</label>
      <select id="theme-select" name="theme" defaultValue={theme} className="compact">
        {THEMES.map((x) => <option key={x} value={x}>{themeLabel(x)}</option>)}
      </select>
      <button type="submit" className="btn compact">{t.bar.themeSet}</button>
    </form>
  );
}

export function TopBar({ me, csrf, expiresAt, theme, path }: Omit<ChromeProps, "children" | "nonce">) {
  const signedIn = csrf !== undefined;
  const mfa = me ? me.acr === "mfa" : false;
  return (
    <header className="topbar">
      <a className="brand" href="/">{t.product}</a>
      <div className="topbar-meta">
        {signedIn && me ? (
          <dl className="contents">
            <div className="meta-item"><dt>{t.bar.user}</dt><dd className="mono" title={me.sub}>{me.sub.slice(0, 8)}</dd></div>
            <div className="meta-item"><dt>{t.bar.roles}</dt><dd>{me.roles.join(", ") || t.bar.none}</dd></div>
            <div className="meta-item"><dt>{t.bar.clearance}</dt><dd><Badge level={me.clearance} /></dd></div>
            <div className="meta-item"><dt>{t.bar.unit}</dt><dd>{me.unit}</dd></div>
            <div className="meta-item"><dt>{t.bar.compartments}</dt><dd>{me.compartments.join(", ") || t.bar.none}</dd></div>
            <div className="meta-item"><dt>{t.bar.auth}</dt><dd>{mfa ? <Status tone="ok">{t.bar.mfa}</Status> : <Status tone="warn">{t.bar.pwd}</Status>}</dd></div>
          </dl>
        ) : signedIn ? (
          <Chip tone="warn">{t.bar.infoUnavailable}</Chip>
        ) : null}
        {signedIn && expiresAt ? (
          <span className="meta-item">
            <span className="text-muted">{t.bar.expires}</span>
            <time className="mono" dateTime={expiresAt.toISOString()} data-countdown={expiresAt.toISOString()}>{utc(expiresAt)}</time>
          </span>
        ) : null}
        <ThemeForm theme={theme} csrf={csrf} path={path} />
        {signedIn ? (
          <form method="post" action="/api/auth/logout" className="inline-form">
            <input type="hidden" name="csrf" value={csrf} />
            <button type="submit" className="btn compact">{t.bar.signOut}</button>
          </form>
        ) : (
          <a className="btn compact" href="/api/auth/login">{t.bar.signIn}</a>
        )}
      </div>
    </header>
  );
}

export function SideNav({ me, path }: { me?: Me | undefined; path: string }) {
  const items = navFor(me?.roles ?? []);
  const current = (href: string) => (href === "/" ? path === "/" : path === href || (href !== "/cases" && path.startsWith(`${href}/`)) || (href === "/cases" && /^\/cases\/(?!new)/.test(path)));
  return (
    <nav className="sidenav" aria-label={t.nav.label}>
      <h2>{t.nav.section}</h2>
      <ul>
        {items.map((i) => (
          <li key={i.href}><a href={i.href} {...(current(i.href) ? { "aria-current": "page" as const } : {})}>{i.label}</a></li>
        ))}
      </ul>
    </nav>
  );
}

/** The whole frame. Used by the root layout and by the few route handlers that answer with a page. */
export function Chrome(p: ChromeProps) {
  const signedIn = p.csrf !== undefined;
  return (
    <>
      <a className="skip-link" href="#main">{t.skip}</a>
      <TopBar {...p} />
      <div className="layout" data-nav={signedIn ? "yes" : "none"}>
        {signedIn ? <SideNav me={p.me} path={p.path} /> : null}
        <main id="main" className="content" tabIndex={-1}>{p.children}</main>
      </div>
      <footer className="footer">{t.product}</footer>
      {signedIn && p.expiresAt ? <script src="/ui.js" nonce={p.nonce} defer /> : null}
    </>
  );
}
