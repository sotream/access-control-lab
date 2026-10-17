import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  // tests run against the policy source, so no build step is needed before `pnpm test`
  resolve: { alias: { "@acl/policy": fileURLToPath(new URL("../../packages/policy/src/index.ts", import.meta.url)) } },
  test: { include: ["src/**/*.test.ts"] },
});
