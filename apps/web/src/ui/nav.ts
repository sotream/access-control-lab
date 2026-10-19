import { t } from "./i18n";
import type { IconName } from "./icons";

export interface NavItem {
  href: string;
  label: string;
  icon: IconName;
}

/** What the side navigation offers, by role. Only a convenience: the API decides what each page may show. */
export function navFor(roles: readonly string[]): NavItem[] {
  const has = (r: string) => roles.includes(r);
  const items: NavItem[] = [{ href: "/", label: t.nav.home, icon: "home" }];
  if (has("analyst")) items.push({ href: "/cases", label: t.nav.myCases, icon: "folder" }, { href: "/cases/new", label: t.nav.newCase, icon: "plus" });
  if (has("reviewer")) items.push({ href: "/review", label: t.nav.review, icon: "inbox" });
  if (has("unit-admin")) items.push({ href: "/cases", label: t.nav.unitCases, icon: "folder" }, { href: "/cases/new", label: t.nav.newCase, icon: "plus" }, { href: "/break-glass", label: t.nav.breakGlass, icon: "alert" });
  if (has("auditor")) items.push({ href: "/audit", label: t.nav.audit, icon: "list" }, { href: "/audit/verify", label: t.nav.verify, icon: "verify" });
  items.push({ href: "/session", label: t.nav.session, icon: "user" });
  const seen = new Set<string>();
  return items.filter((i) => (seen.has(i.href) ? false : (seen.add(i.href), true)));
}
