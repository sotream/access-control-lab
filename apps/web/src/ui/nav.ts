import { t } from "./i18n";

export interface NavItem {
  href: string;
  label: string;
}

/** What the side navigation offers, by role. Only a convenience: the API decides what each page may show. */
export function navFor(roles: readonly string[]): NavItem[] {
  const has = (r: string) => roles.includes(r);
  const items: NavItem[] = [{ href: "/", label: t.nav.home }];
  if (has("analyst")) items.push({ href: "/cases", label: t.nav.myCases }, { href: "/cases/new", label: t.nav.newCase });
  if (has("reviewer")) items.push({ href: "/review", label: t.nav.review });
  if (has("unit-admin")) items.push({ href: "/cases", label: t.nav.unitCases }, { href: "/cases/new", label: t.nav.newCase }, { href: "/break-glass", label: t.nav.breakGlass });
  if (has("auditor")) items.push({ href: "/audit", label: t.nav.audit }, { href: "/audit/verify", label: t.nav.verify });
  items.push({ href: "/session", label: t.nav.session });
  const seen = new Set<string>();
  return items.filter((i) => (seen.has(i.href) ? false : (seen.add(i.href), true)));
}
