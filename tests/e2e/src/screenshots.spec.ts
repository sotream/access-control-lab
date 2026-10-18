// Generates docs/screenshots/*.png (light and dark) from the running prod-like stack. Seed users and fixed demo text only; no real data.
// Run: pnpm --filter @acl/e2e-tests screenshots   (the files are generated, never edited by hand)
import { expect, test } from "./helpers";
import type { Page } from "@playwright/test";

test.skip(process.env.SHOTS !== "1", "set SHOTS=1 (pnpm screenshots)");
test.describe.configure({ mode: "serial" });

const OUT = new URL("../../../docs/screenshots/", import.meta.url).pathname;
const tag = Date.now().toString(36);
const ids: Record<string, string> = {};

async function create(page: Page, key: string, title: string, body: string, level: string, compartments = "") {
  await page.goto("/cases/new");
  await page.getByLabel("Title").fill(title);
  await page.getByLabel("Body").fill(body);
  await page.getByLabel("Classification").selectOption(level);
  await page.getByLabel("Compartments").fill(compartments);
  await page.getByRole("button", { name: "Create draft" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(title);
  ids[key] = page.url().split("?")[0]!.split("/").pop()!;
}

async function shoot(page: Page, name: string, path: string, opts: { full?: boolean } = {}) {
  for (const scheme of ["light", "dark"] as const) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    await page.goto(path);
    await page.waitForLoadState("networkidle");
    await page.evaluate(() => document.querySelectorAll("time[data-countdown]").forEach((t) => (t.textContent = "7h 59m 12s"))); // a fixed value, so the image does not change on every run
    await page.screenshot({ path: `${OUT}${name}-${scheme}.png`, fullPage: opts.full ?? false });
  }
}

test("fixtures", async ({ as }) => {
  const analyst = await as("analyst-official");
  await create(analyst, "official", `Standortwechsel Rechenzentrum ${tag}`, "Lagebericht\n\nDer Betrieb wird von Standort A nach Standort B verlegt.\nÜbergabe: 06:00 UTC, Rückfall: bis 12:00 UTC.\nVerantwortlich: Einheit alpha.", "OFFICIAL");
  await analyst.getByLabel("Add a file").setInputFiles({ name: "uebergabe-protokoll.txt", mimeType: "text/plain", buffer: Buffer.from("Übergabeprotokoll\n1. Zugänge geprüft\n2. Sicherung bestätigt\n") });
  await analyst.getByRole("button", { name: "Upload" }).click();
  await expect(analyst.getByRole("status").filter({ hasText: "Attachment stored." })).toBeVisible();
  await analyst.getByRole("button", { name: "Submit for review" }).click();
  await create(analyst, "draft", `Entwurf Lieferkette ${tag}`, "Offene Punkte zur Lieferkette.", "OFFICIAL");
  const secret = await as("analyst-secret-a");
  await create(secret, "secret", `Quellenlage Nord ${tag}`, "Auszug, nur für berechtigte Personen.", "SECRET", "A");
});

test("analyst pages", async ({ as }) => {
  const page = await as("analyst-official");
  await shoot(page, "cases-list", "/cases");
  await shoot(page, "case-detail", `/cases/${ids.official}`, { full: true });
  await shoot(page, "case-new", "/cases/new");
  await shoot(page, "session", "/session");
  await shoot(page, "error-404", "/cases/00000000-0000-4000-8000-000000000000");
});

test("secret case", async ({ as }) => {
  await shoot(await as("analyst-secret-a"), "case-secret", `/cases/${ids.secret}`);
});

test("reviewer queue", async ({ as }) => {
  await shoot(await as("reviewer"), "review-queue", "/review");
});

test("break-glass", async ({ as }) => {
  await shoot(await as("unit-admin-beta"), "break-glass", `/cases/${ids.secret}/break-glass`);
});

test("auditor pages", async ({ as }) => {
  const page = await as("auditor");
  await shoot(page, "audit-log", "/audit", { full: true });
  await shoot(page, "audit-verify", "/audit/verify");
});

test("signed-out landing", async ({ browser }) => {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, baseURL: "https://vault.localhost", locale: "en-US", timezoneId: "UTC", viewport: { width: 1280, height: 720 } });
  await shoot(await ctx.newPage(), "landing", "/");
  await ctx.close();
});
