// Compiles styles/ui.css (Tailwind + design tokens) into public/ui.css at build time: the one self-served stylesheet.
// Plain file, no runtime CSS-in-JS and no inline style, so the CSP (style-src 'self' + nonce) needs no 'unsafe-inline'.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import postcss from "postcss";
import tailwind from "@tailwindcss/postcss";

const from = new URL("../styles/ui.css", import.meta.url).pathname;
const out = new URL("../public/ui.css", import.meta.url).pathname;
const result = await postcss([tailwind()]).process(readFileSync(from, "utf8"), { from, to: out });
mkdirSync(new URL("../public/", import.meta.url), { recursive: true });
writeFileSync(out, result.css);
console.log(`public/ui.css: ${(result.css.length / 1024).toFixed(1)} KiB`);
