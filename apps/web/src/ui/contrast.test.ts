import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const css = readFileSync(new URL("../../styles/ui.css", import.meta.url), "utf8");

/** the variables of one theme block, found by its selector line */
function block(selector: string): Record<string, string> {
  const start = css.indexOf(selector);
  if (start < 0) throw new Error(`no block ${selector}`);
  const body = css.slice(css.indexOf("{", start) + 1, css.indexOf("}", start));
  return Object.fromEntries([...body.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6})/g)].map((m) => [m[1]!, m[2]!]));
}
const lum = (hex: string) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
};
export const ratio = (a: string, b: string) => {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x! + 0.05) / (y! + 0.05);
};

const themes = {
  light: block(':root[data-theme="light"]'),
  dark: block(':root[data-theme="dark"]'),
  "dark (system)": block(':root:not([data-theme="light"])'),
};

// [foreground, background, minimum]: 4.5 for text, 3 for focus rings and the borders of form controls (WCAG 1.4.3, 1.4.11)
const TEXT: [string, string][] = [
  ["text", "bg"], ["text", "surface"], ["text", "surface-2"], ["muted", "bg"], ["muted", "surface"], ["muted", "surface-2"],
  ["link", "bg"], ["link", "surface"], ["link", "surface-2"], ["accent-text", "accent"],
  ["danger", "danger-bg"], ["warn", "warn-bg"], ["ok", "ok-bg"], ["info", "info-bg"],
  ["cls-official", "cls-official-bg"], ["cls-confidential", "cls-confidential-bg"], ["cls-secret", "cls-secret-bg"],
  ["bar-text", "bar-official"], ["bar-text", "bar-confidential"], ["bar-text", "bar-secret"],
  ["danger", "surface"], ["text", "danger-bg"],
];
const NON_TEXT: [string, string][] = [["focus", "bg"], ["focus", "surface"], ["line-strong", "surface"], ["line-strong", "bg"], ["danger", "surface"]];

describe("design tokens meet WCAG 2.2 AA in every theme", () => {
  it("the two dark blocks (explicit and system) are identical", () => {
    const { ["dark (system)"]: sys, dark } = themes;
    expect(sys).toEqual(dark);
  });
  for (const [name, tok] of Object.entries(themes)) {
    it.each(TEXT)(`${name}: %s on %s is at least 4.5:1`, (fg, bg) => expect(ratio(tok[fg]!, tok[bg]!)).toBeGreaterThanOrEqual(4.5));
    it.each(NON_TEXT)(`${name}: %s against %s is at least 3:1`, (fg, bg) => expect(ratio(tok[fg]!, tok[bg]!)).toBeGreaterThanOrEqual(3));
  }
  it("classification states are told apart by label too: every level has a distinct text, border style or width", () => {
    expect(css).toMatch(/\.badge\[data-level="CONFIDENTIAL"\][^}]*border-style: dashed/);
    expect(css).toMatch(/\.badge\[data-level="SECRET"\][^}]*border-width: 2px/);
  });
});
