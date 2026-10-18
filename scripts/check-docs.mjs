#!/usr/bin/env node
// Documentation guards that stay cheap:
//  - every relative link and image in README.md and docs/*.md points at a file that exists;
//  - every `pnpm <script>` named in code spans or code blocks exists (root script, or script of the package named by --filter).
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const root = new URL("../", import.meta.url).pathname;
const files = ["README.md", "SECURITY.md", ...readdirSync(`${root}docs`).filter((f) => f.endsWith(".md")).map((f) => `docs/${f}`)].filter((f) => existsSync(root + f));
const problems = [];

// ---- workspace packages and their scripts
const packages = new Map(); // name -> scripts
const rootPkg = JSON.parse(readFileSync(`${root}package.json`, "utf8"));
packages.set(rootPkg.name, rootPkg.scripts ?? {});
for (const dir of ["apps", "packages", "tests"]) {
  for (const d of readdirSync(`${root}${dir}`, { withFileTypes: true })) {
    const p = join(root, dir, d.name, "package.json");
    if (d.isDirectory() && existsSync(p)) {
      const j = JSON.parse(readFileSync(p, "utf8"));
      packages.set(j.name, j.scripts ?? {});
    }
  }
}
// pnpm commands that are not package scripts
const BUILTIN = new Set(["install", "i", "add", "remove", "rm", "update", "up", "upgrade", "exec", "dlx", "run", "deploy", "audit", "why", "list", "ls", "outdated", "store", "config", "init", "create", "publish", "pack", "rebuild", "prune", "fetch", "dedupe", "link", "unlink", "approve-builds", "self-update", "setup", "env", "licenses", "patch", "patch-commit", "root", "bin", "import", "doctor", "cache", "sbom", "version"]);

function codeRegions(text) {
  const out = [];
  for (const m of text.matchAll(/^```[^\n]*\n([\s\S]*?)^```/gm)) out.push(m[1]);
  const prose = text.replace(/^```[^\n]*\n[\s\S]*?^```/gm, "");
  for (const m of prose.matchAll(/`([^`\n]+)`/g)) out.push(m[1]);
  return out;
}

for (const file of files) {
  const text = readFileSync(root + file, "utf8");
  const prose = text.replace(/^```[^\n]*\n[\s\S]*?^```/gm, "").replace(/`[^`\n]*`/g, "");
  // ---- links
  for (const m of prose.matchAll(/!?\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
    const target = m[1];
    if (/^(https?:|mailto:|#)/.test(target)) continue;
    const path = decodeURIComponent(target.split("#")[0].split("?")[0]);
    if (!path) continue;
    if (!existsSync(resolve(root, dirname(file), path))) problems.push(`${file}: link to a missing file: ${target}`);
  }
  // ---- pnpm scripts
  for (const region of codeRegions(text)) {
    for (const line of region.split("\n")) {
      for (const m of line.matchAll(/(?:^|[\s&;|(])pnpm((?:\s+[^\s&;|)`]+)*)/g)) {
        const tokens = m[1].trim().split(/\s+/).filter(Boolean).map((t) => t.replace(/^['"]|['"]$/g, ""));
        let filter;
        let i = 0;
        while (i < tokens.length && tokens[i].startsWith("-")) {
          if (tokens[i] === "--filter" || tokens[i] === "-F") filter = tokens[++i];
          else if (tokens[i].startsWith("--filter=")) filter = tokens[i].slice(9);
          i++;
        }
        let cmd = tokens[i];
        if (cmd === "run") cmd = tokens[++i];
        if (!cmd || cmd.startsWith("<") || cmd.startsWith("$") || cmd.startsWith("-")) continue;
        if (BUILTIN.has(cmd) && cmd !== "run") continue;
        let scripts;
        if (filter) {
          const name = filter.replace(/\.\.\.$/, "").replace(/^\.\.\./, "");
          if (!packages.has(name)) {
            if (/[*{}]/.test(name)) continue; // a pattern: not resolved here
            problems.push(`${file}: pnpm --filter ${filter}: no such workspace package`);
            continue;
          }
          scripts = packages.get(name);
        } else scripts = packages.get(rootPkg.name);
        if (!Object.hasOwn(scripts, cmd) && !["test", "start", "stop", "restart"].includes(cmd)) problems.push(`${file}: \`pnpm ${filter ? `--filter ${filter} ` : ""}${cmd}\` is not a script${filter ? ` of ${filter}` : " of the root package"}`);
        else if (!Object.hasOwn(scripts, cmd)) problems.push(`${file}: \`pnpm ${cmd}\` has no script to run`);
      }
    }
  }
}
if (problems.length) {
  console.error(`docs: ${problems.length} problem(s)\n  ${[...new Set(problems)].join("\n  ")}`);
  process.exit(1);
}
console.log(`ok: ${files.length} documents: relative links resolve, every pnpm script named exists`);
