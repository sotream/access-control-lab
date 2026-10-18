import { createApp } from "./app.js";
import { loadConfig } from "./config.js";

async function bootstrap() {
  const cfg = loadConfig();
  if (!cfg.databaseUrl) throw new Error("DATABASE_URL is required (casefile_app, see .env.example)");
  const app = await createApp(cfg);
  // loopback unless API_HOST says otherwise (a container on a private network); the API is reached through the BFF, never directly from a browser
  await app.listen(Number(process.env.API_PORT ?? 3001), cfg.host);
  console.log(JSON.stringify({ level: "info", msg: "api started", profile: cfg.profile, host: cfg.host }));
}
bootstrap().catch((e: unknown) => {
  console.error(JSON.stringify({ level: "error", msg: "startup failed", error: e instanceof Error ? e.message : String(e) }));
  process.exit(1);
});
