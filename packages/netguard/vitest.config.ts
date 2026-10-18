import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts", "src/index.ts"],
      // rate limits and trust decisions: any untested branch is a gap
      thresholds: { lines: 95, branches: 95, functions: 95, statements: 95 },
    },
  },
});
