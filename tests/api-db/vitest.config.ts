import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: { alias: {
      "@acl/audit": fileURLToPath(new URL("../../packages/audit/src/index.ts", import.meta.url)), "@acl/policy": fileURLToPath(new URL("../../packages/policy/src/index.ts", import.meta.url)) } },
  test: {
    include: ["src/**/*.test.ts"],
    globalSetup: ["src/global-setup.ts"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
    fileParallelism: false, // one shared test database
  },
});
