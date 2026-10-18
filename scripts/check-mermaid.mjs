#!/usr/bin/env node
// Every ```mermaid block in README.md and docs/ must parse with mermaid (pinned in the root package.json, parsed in jsdom).
// A diagram that does not parse renders as an error box on GitHub; this fails before it gets there.
import { readFileSync, readdirSync } from "node:fs";
import { JSDOM } from "jsdom";

const root = new URL("../", import.meta.url).pathname;
const files = ["README.md", ...readdirSync(`${root}docs`).filter((f) => f.endsWith(".md")).map((f) => `docs/${f}`)];

const dom = new JSDOM("<!doctype html><html><body></body></html>");
globalThis.window = dom.window;
globalThis.document = dom.window.document;
Object.defineProperty(globalThis, "navigator", { value: dom.window.navigator, configurable: true });
const { default: mermaid } = await import("mermaid");
mermaid.initialize({ startOnLoad: false });

let blocks = 0;
const problems = [];
for (const file of files) {
  const text = readFileSync(`${root}${file}`, "utf8");
  for (const m of text.matchAll(/^```mermaid\n([\s\S]*?)^```/gm)) {
    blocks++;
    const line = text.slice(0, m.index).split("\n").length;
    try {
      await mermaid.parse(m[1]);
    } catch (e) {
      problems.push(`${file}:${line}: ${String(e.message ?? e).split("\n").slice(0, 4).join(" | ")}`);
    }
  }
}
if (problems.length) {
  console.error(`mermaid: ${problems.length} block(s) do not parse\n  ${problems.join("\n  ")}`);
  process.exit(1);
}
console.log(`ok: ${blocks} mermaid block(s) parse`);
