import { defineConfig, devices } from "@playwright/test";

// Chromium only, one worker (Keycloak refuses a one-time code twice, so sign-ins are done once per user in auth.setup.ts and reused).
// The prod-like stack serves https://vault.localhost with a private CA that Chromium does not know: ignoreHTTPSErrors is limited to this suite.
// Cookies, CSP, framing and headers are unaffected by it (the origin is still https and still a secure context).
export default defineConfig({
  testDir: "src",
  outputDir: "test-results",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 120_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [["list"], ["github"]] : [["list"]],
  use: {
    baseURL: "https://vault.localhost",
    ignoreHTTPSErrors: true,
    locale: "en-US",
    timezoneId: "UTC",
    trace: "retain-on-failure",
    launchOptions: { args: ["--host-resolver-rules=MAP *.localhost 127.0.0.1"] },
  },
  projects: [
    { name: "setup", testMatch: /auth\.setup\.ts/ },
    { name: "chromium", use: { ...devices["Desktop Chrome"] }, dependencies: ["setup"], testIgnore: /auth\.setup\.ts/ },
  ],
});
