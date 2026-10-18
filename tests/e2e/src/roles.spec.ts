// A smoke path per role with a real sign-in: the pages render, the navigation matches the role, the browser enforces the CSP without a single
// violation, axe finds nothing serious (system light and system dark), and nothing leaves for another origin.
import { expect, expectAccessible, expectClean, test, watch } from "./helpers";
import type { User } from "./env";

const PATHS: Record<User, { paths: [string, RegExp][]; nav: string[]; notNav: string[]; roles: RegExp }> = {
  "analyst-official": { paths: [["/cases", /my cases/i], ["/cases/new", /new case file/i], ["/session", /session/i]], nav: ["My cases", "New case", "Session"], notNav: ["Audit log", "Review queue", "Break-glass"], roles: /analyst/ },
  "analyst-secret-a": { paths: [["/cases", /my cases/i], ["/session", /session/i]], nav: ["My cases"], notNav: ["Audit log"], roles: /analyst/ },
  "analyst-secret-b": { paths: [["/cases", /my cases/i]], nav: ["My cases"], notNav: ["Audit log"], roles: /analyst/ },
  reviewer: { paths: [["/review", /review queue/i], ["/session", /session/i]], nav: ["Review queue", "Session"], notNav: ["New case", "Audit log", "Break-glass"], roles: /reviewer/ },
  "unit-admin-alpha": { paths: [["/cases", /case files|unit cases|my cases/i], ["/break-glass", /break-glass access/i], ["/session", /session/i]], nav: ["Unit cases", "Break-glass"], notNav: ["Audit log", "Review queue"], roles: /unit-admin/ },
  "unit-admin-beta": { paths: [["/cases", /case files|unit cases|my cases/i]], nav: ["Unit cases", "Break-glass"], notNav: ["Audit log"], roles: /unit-admin/ },
  auditor: { paths: [["/audit", /audit log/i], ["/audit/verify", /chain verification/i], ["/session", /session/i]], nav: ["Audit log", "Chain verification"], notNav: ["My cases", "New case", "Break-glass"], roles: /auditor/ },
  "platform-admin": { paths: [["/session", /session/i]], nav: ["Session"], notNav: ["My cases", "Audit log", "Review queue"], roles: /platform-admin/ },
};

for (const [user, spec] of Object.entries(PATHS) as [User, (typeof PATHS)[User]][]) {
  test.describe(user, () => {
    test("pages render, navigation fits the role, no CSP violation, no serious axe finding (light and dark)", async ({ as }) => {
      const page = await as(user);
      const w = watch(page);
      await page.goto("/");
      const bar = page.locator("header.topbar");
      await expect(bar).toContainText(spec.roles);
      await expect(bar.locator(".badge")).toHaveCount(1); // the clearance, as a labelled badge
      await expect(bar).toContainText(/MFA verified|pwd only/);
      await expect(bar.locator("time[data-countdown]")).toContainText(/\d+m \d+s|\d+h/); // the countdown script ran (CSP allowed it)
      const nav = page.getByRole("navigation", { name: "Main" });
      for (const n of spec.nav) await expect(nav.getByRole("link", { name: n, exact: true })).toBeVisible();
      for (const n of spec.notNav) await expect(nav.getByRole("link", { name: n, exact: true })).toHaveCount(0);
      for (const scheme of ["light", "dark"] as const) {
        await page.emulateMedia({ colorScheme: scheme });
        for (const [path, heading] of spec.paths) {
          await page.goto(path);
          await expect(page.getByRole("heading", { level: 1 }).first()).toHaveText(heading);
          await expect(page.getByRole("main")).toBeVisible();
          await expectAccessible(page, `${user} ${path} ${scheme}`);
        }
      }
      expectClean(w);
    });
  });
}
