import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: { alias: {
      "@acl/audit": fileURLToPath(new URL("../../packages/audit/src/index.ts", import.meta.url)), "@acl/netguard": fileURLToPath(new URL("../../packages/netguard/src/index.ts", import.meta.url)), "@acl/policy": fileURLToPath(new URL("../../packages/policy/src/index.ts", import.meta.url)) } },
  test: { include: ["src/**/*.test.ts"], testTimeout: 90_000, fileParallelism: false },
});
