import { defineConfig } from "vitest/config";

// Black-box attack suite against the prod-like stack (docs/attack-catalogue.md). One stack, started once; files run one after the other.
export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    globalSetup: ["src/global-setup.ts"],
    testTimeout: 180_000,
    hookTimeout: 900_000,
    fileParallelism: false,
    reporters: ["default"],
  },
});
