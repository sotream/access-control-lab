// Form controls: the select chevron is drawn by us (the native arrow sat flush against the edge). Pins the numbers so a regression is caught:
// the chevron is inset from the edge and the padding keeps the label clear of it; forced-colors mode gets the native arrow back.
import { expect, test } from "./helpers";
import type { Page } from "@playwright/test";

const CHEVRON_WIDTH = 14; // two 7px strokes, see styles/ui.css

async function selects(page: Page) {
  return page.locator("select").evaluateAll((els) =>
    els.map((el) => {
      const s = getComputedStyle(el);
      return {
        name: el.getAttribute("name") ?? el.id,
        appearance: s.appearance,
        paddingRight: parseFloat(s.paddingRight),
        positionX: s.backgroundPositionX,
        image: s.backgroundImage,
        inset: 0.75 * parseFloat(getComputedStyle(document.documentElement).fontSize), // 0.75rem
      };
    }),
  );
}

const PAGES: [string, "analyst-official" | "auditor"][] = [["/cases", "analyst-official"], ["/cases/new", "analyst-official"], ["/audit", "auditor"]];

for (const [path, user] of PAGES) {
  for (const scheme of ["light", "dark"] as const) {
    test(`${path} ${scheme}: every select has an inset chevron and room for its label`, async ({ as }) => {
      const page = await as(user);
      await page.emulateMedia({ colorScheme: scheme });
      await page.goto(path);
      const all = await selects(page);
      expect(all.length).toBeGreaterThan(0);
      for (const s of all) {
        expect(s.appearance, `${s.name}: native arrow off`).toBe("none");
        expect(s.image, `${s.name}: chevron drawn`).toContain("linear-gradient");
        expect(s.paddingRight, `${s.name}: room for the chevron plus its inset`).toBeGreaterThanOrEqual(s.inset + CHEVRON_WIDTH);
        expect(s.positionX, `${s.name}: chevron inset 0.75rem from the right edge`).toContain(`100% - ${s.inset}px`);
      }
    });
  }
}

test("forced-colors mode gets the native arrow back", async ({ as }) => {
  const page = await as("analyst-official");
  await page.emulateMedia({ forcedColors: "active" });
  await page.goto("/cases");
  for (const s of await selects(page)) {
    expect(s.appearance, s.name).toBe("auto");
    expect(s.image, s.name).toBe("none");
  }
});
