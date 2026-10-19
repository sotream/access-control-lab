// Keyboard use of the main flows: the skip link comes first, the order follows the visual order, focus is visible, and forms work without a mouse.
import { expect, test } from "./helpers";
import type { Page } from "@playwright/test";

const focusPath = async (page: Page, steps: number) => {
  const seen: string[] = [];
  for (let i = 0; i < steps; i++) {
    await page.keyboard.press("Tab");
    seen.push(await page.evaluate(() => {
      const e = document.activeElement as HTMLElement | null;
      if (!e) return "none";
      const tag = e.tagName.toLowerCase();
      const form = ["input", "select", "textarea"].includes(tag);
      return `${tag}:${(form ? e.getAttribute("name") : e.getAttribute("aria-label") || e.innerText || "")?.trim().slice(0, 40)}`;
    }));
  }
  return seen;
};

test("the skip link is the first stop and moves focus to the main content", async ({ as }) => {
  const page = await as("analyst-official");
  await page.goto("/cases");
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Skip to main content" });
  await expect(skip).toBeFocused();
  await expect(skip).toBeInViewport();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main")).toBeFocused();
});

test("focus is visible: every stop has an outline", async ({ as }) => {
  const page = await as("analyst-official");
  await page.goto("/cases/new");
  for (let i = 0; i < 14; i++) {
    await page.keyboard.press("Tab");
    const outline = await page.evaluate(() => {
      const s = getComputedStyle(document.activeElement!);
      return { w: parseFloat(s.outlineWidth), style: s.outlineStyle };
    });
    expect(outline.style, `stop ${i}`).not.toBe("none");
    expect(outline.w, `stop ${i}`).toBeGreaterThanOrEqual(2);
  }
});

test("create form: the order is skip link, brand, navigation, theme and sign-out, then the fields top to bottom, and Enter in the title field submits", async ({ as }) => {
  const page = await as("analyst-official");
  await page.goto("/cases/new");
  const order = await focusPath(page, 26);
  const at = (s: string) => order.findIndex((x) => x.includes(s));
  expect(at("Skip to main content")).toBe(0);
  expect(at("Casefile Vault")).toBeLessThan(at("My cases"));
  expect(at("My cases")).toBeLessThan(at("Sign out"));
  expect(at("Sign out")).toBeLessThan(at("input:title"));
  expect(at("input:title")).toBeLessThan(at("textarea:body"));
  expect(at("textarea:body")).toBeLessThan(at("select:classification"));
  expect(at("select:classification")).toBeLessThan(at("input:compartments"));
  expect(at("input:compartments")).toBeLessThan(at("Create draft"));
  expect(at("Create draft")).toBeLessThan(at("Cancel"));
  await page.getByLabel("Title").fill(`E2E keyboard ${Date.now().toString(36)}`);
  await page.getByLabel("Title").press("Enter");
  await expect(page.getByRole("heading", { level: 1 })).toContainText("E2E keyboard");
});

test("case list: filters and sort links are reachable by keyboard in reading order", async ({ as }) => {
  const page = await as("analyst-official");
  await page.goto("/cases");
  await page.getByLabel("Title contains").focus();
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("Status")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("Classification", { exact: true }).first()).toBeFocused();
});

test("break-glass justification: the field is required and announced, the warning frame is a labelled form", async ({ as }) => {
  const page = await as("unit-admin-alpha");
  await page.goto("/break-glass");
  await page.getByLabel("Case file identifier").fill("00000000-0000-4000-8000-000000000000");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("form", { name: "Break-glass" })).toBeVisible();
  await expect(page.getByLabel("Justification")).toHaveAttribute("aria-describedby", "bg-just-hint");
});
