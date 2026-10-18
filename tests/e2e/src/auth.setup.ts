// One real sign-in per seed user through the BFF and Keycloak (password, then the one-time code when asked), saved as a browser storage state.
import { mkdirSync } from "node:fs";
import { test as setup, expect } from "@playwright/test";
import { authFile, nextOtp, PASSWORD, USERS } from "./env";

mkdirSync(new URL("../.auth/", import.meta.url).pathname, { recursive: true });

for (const user of USERS) {
  setup(`sign in ${user}`, async ({ page }) => {
    await page.goto("/api/auth/login");
    await page.locator("#username").fill(user);
    await page.locator("#password").fill(PASSWORD);
    await page.locator("#kc-login").click();
    for (let attempt = 0; attempt < 3 && (await page.locator("#otp").count()) > 0; attempt++) {
      await page.locator("#otp").fill(await nextOtp(user));
      await page.locator("#kc-login").click();
      await page.waitForLoadState("domcontentloaded");
    }
    await page.waitForURL("https://vault.localhost/**");
    await expect(page.locator("header.topbar")).toContainText("Sign out");
    await page.context().storageState({ path: authFile(user) });
  });
}
