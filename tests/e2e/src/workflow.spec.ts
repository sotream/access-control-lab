// The main flows end to end in a real browser: create, upload, edit, submit, review, break-glass, the audit trail, and the 404 rule (ADR-9).
import { expect, expectAccessible, expectClean, setTheme, test, watch } from "./helpers";

test.describe.configure({ mode: "serial" });

const title = `E2E case ${Date.now().toString(36)}`;

test("an analyst creates a draft, attaches a file, edits it and submits it", async ({ as }) => {
  const page = await as("analyst-official");
  const w = watch(page);
  await page.goto("/cases/new");
  await page.getByLabel("Title").fill(title);
  await page.getByLabel("Body").fill("Lagebericht\nStörung im Rechenzentrum, Ersatz über Standort B.");
  await page.getByLabel("Classification").selectOption("OFFICIAL");
  await page.getByRole("button", { name: "Create draft" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(title);
  await expect(page.locator(".banner")).toContainText("OFFICIAL");
  await expect(page.getByRole("status").filter({ hasText: "Done." })).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve" })).toBeDisabled();

  await page.getByLabel("Add a file").setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("plain text attachment\n") });
  await page.getByRole("button", { name: "Upload" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Attachment stored." })).toBeVisible();
  await expect(page.getByRole("row", { name: /notes\.txt/ })).toContainText(/Clean|Pending scan/);

  await page.getByRole("link", { name: "Edit", exact: true }).click();
  await page.getByLabel("Body").fill("Lagebericht, aktualisiert: Ersatz läuft.");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByText("Lagebericht, aktualisiert: Ersatz läuft.")).toBeVisible();

  await expectAccessible(page, "case detail");
  await page.getByRole("button", { name: "Submit for review" }).click();
  await expect(page.locator(".stepper [aria-current='step']")).toHaveText(/Submitted/);
  await expect(page.getByRole("button", { name: "Submit for review" })).toBeDisabled();
  expectClean(w);
});

test("a reviewer finds it in the queue and approves it", async ({ as }) => {
  const page = await as("reviewer");
  const w = watch(page);
  await page.goto("/review");
  await expect(page.getByRole("link", { name: "New case" })).toHaveCount(0); // a reviewer cannot create: no button that would only lead to a refusal
  await page.getByLabel("Title contains").fill(title);
  await page.getByRole("button", { name: "Apply" }).click();
  await page.getByRole("link", { name: title }).click();
  await expect(page.getByRole("button", { name: "Approve" })).toBeEnabled();
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.locator(".stepper [aria-current='step']")).toHaveText(/Approved/);
  await page.goto("/review");
  await expect(page.getByRole("link", { name: title })).toHaveCount(0); // no longer waiting
  expectClean(w);
});

test("the list filters and sorts, and the header says how", async ({ as }) => {
  const page = await as("analyst-official");
  await page.goto("/cases?status=approved");
  await expect(page.getByRole("link", { name: title })).toBeVisible();
  await page.getByRole("link", { name: /^Title/ }).click();
  await expect(page.getByRole("columnheader", { name: /Title/ })).toHaveAttribute("aria-sort", "descending");
  await page.goto(`/cases?q=${encodeURIComponent("no such case anywhere")}`);
  await expect(page.getByRole("status")).toContainText("No case files match");
});

test("break-glass: justification required, framed, recorded, and visible to the auditor", async ({ as }) => {
  // a CONFIDENTIAL file in compartment A: unit-admin-beta has no compartment A, so a plain read is a 404 and break-glass is the way in
  const author = await as("analyst-secret-a");
  await author.goto("/cases/new");
  await author.getByLabel("Title").fill(`E2E compartment ${Date.now().toString(36)}`);
  await author.getByLabel("Body").fill("Nur mit Notfallzugriff lesbar.");
  await author.getByLabel("Classification").selectOption("CONFIDENTIAL");
  await author.getByLabel("Compartments").fill("A");
  await author.getByRole("button", { name: "Create draft" }).click();
  const bgTitle = await author.getByRole("heading", { level: 1 }).innerText();
  const bgId = author.url().split("?")[0]!.split("/").pop()!;

  const admin = await as("unit-admin-beta");
  expect((await admin.goto(`/cases/${bgId}`))?.status()).toBe(404); // the browser logs a 404 as a console error: watch only from here on
  const w = watch(admin);
  await admin.goto("/break-glass");
  await admin.getByLabel("Case file identifier").fill(bgId);
  await admin.getByRole("button", { name: "Continue" }).click();
  await expect(admin.locator(".glass")).toContainText("Break-glass");
  await expect(admin.getByLabel("Justification")).toHaveAttribute("required", "");
  await admin.getByLabel("Justification").fill("Incident 4711, Lagebild für die Bereitschaft");
  await admin.getByRole("button", { name: "Read with break-glass" }).click();
  await expect(admin.locator(".glass")).toContainText("This access was recorded");
  await expect(admin.getByRole("heading", { name: bgTitle })).toBeVisible();
  await expectAccessible(admin, "break-glass result");
  expect(admin.url()).not.toContain("Incident"); // the justification is never in a URL
  expectClean(w);

  const auditor = await as("auditor");
  await auditor.goto(`/audit?resource=${bgId}`);
  await expect(auditor.getByRole("table")).toContainText(/BREAK_GLASS/);
  await expectAccessible(auditor, "audit log");
  await auditor.goto("/audit/verify");
  await expect(auditor.getByRole("alert").or(auditor.getByRole("status")).first()).toContainText("The chain verifies.");
});

test("hidden and missing look the same (ADR-9), and the page says nothing about why", async ({ as }) => {
  const secret = await as("analyst-secret-a");
  await secret.goto("/cases/new");
  await secret.getByLabel("Title").fill(`E2E secret ${Date.now().toString(36)}`);
  await secret.getByLabel("Body").fill("not for everyone");
  await secret.getByLabel("Classification").selectOption("SECRET");
  await secret.getByLabel("Compartments").fill("A");
  await secret.getByRole("button", { name: "Create draft" }).click();
  await expect(secret.locator(".banner")).toContainText("SECRET");
  const hiddenUrl = secret.url().split("?")[0]!;

  const other = await as("analyst-official");
  const seen = async (url: string) => {
    const r = await other.goto(url);
    return { status: r?.status(), text: (await other.getByRole("main").innerText()).replace(/\s+/g, " ") };
  };
  const hidden = await seen(hiddenUrl);
  const missing = await seen("/cases/00000000-0000-4000-8000-000000000000");
  expect(hidden.status).toBe(404);
  expect(missing).toEqual(hidden);
  expect(hidden.text).toMatch(/does not exist, or you may not see it/);
});

test("the theme toggle works under the strict CSP and sticks", async ({ as }) => {
  const page = await as("analyst-official");
  const w = watch(page);
  await page.goto("/cases");
  const bg = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  await setTheme(page, "dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  const dark = await bg();
  await setTheme(page, "light");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  expect(await bg()).not.toBe(dark);
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await setTheme(page, "system");
  await expect(page.locator("html")).not.toHaveAttribute("data-theme", /.+/);
  expectClean(w);
});
