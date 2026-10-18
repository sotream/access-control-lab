import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts", "src/index.ts", "src/testkit.ts"],
      // the audit chain is evidence: any untested line or branch is a gap
      thresholds: { lines: 95, branches: 95, functions: 95, statements: 95 },
    },
  },
});
