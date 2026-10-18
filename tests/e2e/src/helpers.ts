import AxeBuilder from "@axe-core/playwright";
import { expect, test as base, type Page } from "@playwright/test";
import { authFile, type User } from "./env";

/** What a real browser reported while a page was in use: CSP violations, console errors, uncaught exceptions, failed requests to other origins. */
export interface Watch {
  csp: string[];
  errors: string[];
  foreign: string[];
}

export function watch(page: Page): Watch {
  const w: Watch = { csp: [], errors: [], foreign: [] };
  page.on("console", (m) => {
    if (m.type() === "error") w.errors.push(m.text());
  });
  page.on("pageerror", (e) => w.errors.push(String(e)));
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (!["vault.localhost", "id.localhost"].includes(u.hostname) && !["data:", "blob:", "about:"].includes(u.protocol)) w.foreign.push(r.url());
  });
  void page.exposeFunction("__cspViolation", (s: string) => w.csp.push(s));
  void page.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (e) => (window as unknown as { __cspViolation(s: string): void }).__cspViolation(`${e.violatedDirective} ${e.blockedURI}`));
  });
  return w;
}

export function expectClean(w: Watch) {
  expect(w.csp, "CSP violations").toEqual([]);
  expect(w.errors, "console errors").toEqual([]);
  expect(w.foreign, "requests to other origins").toEqual([]);
}

/** axe-core on the current page: no serious or critical violation (WCAG 2.0/2.1/2.2 A and AA rules). */
export async function expectAccessible(page: Page, label: string) {
  const r = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]).analyze();
  const bad = r.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  expect(bad.map((v) => `${v.id} (${v.impact}): ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ")}`), `axe on ${label}`).toEqual([]);
}

export const test = base.extend<{ as: (user: User) => Promise<Page>; watcher: Watch }>({
  watcher: async ({ page }, use) => use(watch(page)),
  as: async ({ browser }, use) => {
    const contexts: { close(): Promise<void> }[] = [];
    await use(async (user) => {
      const ctx = await browser.newContext({ storageState: authFile(user), ignoreHTTPSErrors: true, baseURL: "https://vault.localhost", locale: "en-US", timezoneId: "UTC" });
      contexts.push(ctx);
      return ctx.newPage();
    });
    for (const c of contexts) await c.close();
  },
});
export { expect };

export const setTheme = async (page: Page, theme: "light" | "dark" | "system") => {
  await page.locator("#theme-select").selectOption(theme);
  await page.getByRole("button", { name: "Set theme" }).click();
  await page.waitForLoadState("domcontentloaded");
};
