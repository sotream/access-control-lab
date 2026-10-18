// The production app WITH the data layer mounted: every route declares its access (T-11).
import { RequestMethod } from "@nestjs/common";
import { afterAll, describe, expect, it } from "vitest";
import { createApp } from "../../../apps/api/src/app.js";
import { loadConfig } from "../../../apps/api/src/config.js";
import { enumerate } from "../../../apps/api/test/inventory.js";
import { appUrl } from "./db.js";

describe("route inventory of the real application", () => {
  const cfg = loadConfig({ KEYCLOAK_ISSUER: "http://127.0.0.1:8080/realms/casefile", DATABASE_URL: appUrl(), AUDIT_HMAC_KEYS: process.env.AUDIT_HMAC_KEYS!, AUTH_FAIL_LIMIT: "10000" });
  const started = createApp(cfg).then(async (app) => (await app.listen(0, "127.0.0.1"), app));
  afterAll(async () => (await started).close());

  it("lists the case-file routes and none is undeclared", async () => {
    const app = await started;
    const routes = enumerate(app);
    const paths = routes.map((r) => `${RequestMethod[r.method]} ${r.path}`).sort();
    expect(paths).toEqual(
      [
        "DELETE /case-files/:id",
        "GET /audit-log",
        "GET /audit-log/checkpoints",
        "GET /audit-log/export",
        "GET /audit-log/verify",
        "GET /case-files",
        "GET /case-files/:id",
        "GET /case-files/:id/export",
        "GET /health",
        "GET /me",
        "PATCH /case-files/:id",
        "POST /case-files",
        "POST /case-files/:id/approve",
        "POST /case-files/:id/submit",
      ].sort(),
    );
    expect(routes.filter((r) => !r.access)).toEqual([]);
    expect(routes.filter((r) => r.access?.kind === "public").map((r) => r.path)).toEqual(["/health"]);
  });

  it("every non-public route answers 401 without a token", async () => {
    const app = await started;
    const url = `http://127.0.0.1:${(app.getHttpServer().address() as { port: number }).port}`;
    for (const r of enumerate(app).filter((x) => x.access?.kind !== "public")) {
      const res = await fetch(`${url}${r.path.replace(":id", "00000000-0000-4000-8000-000000000001")}`, { method: RequestMethod[r.method] });
      expect(res.status, `${RequestMethod[r.method]} ${r.path}`).toBe(401);
    }
  });

  it("the API refuses to start as a superuser, a BYPASSRLS role or the table owner", async () => {
    for (const url of [process.env.ADMIN_DATABASE_URL!, process.env.MIGRATOR_DATABASE_URL!]) {
      const u = new URL(url);
      u.pathname = new URL(appUrl()).pathname;
      await expect(createApp(loadConfig({ KEYCLOAK_ISSUER: "http://127.0.0.1:8080/realms/casefile", DATABASE_URL: u.toString(), AUDIT_HMAC_KEYS: process.env.AUDIT_HMAC_KEYS! }))).rejects.toThrow(/unsafe for the API/);
    }
  });
});
