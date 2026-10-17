import { createApp } from "./app.js";
import { loadConfig } from "./config.js";

async function bootstrap() {
  const app = await createApp(loadConfig());
  // bind loopback only; the API is reached through the BFF, never directly from a browser
  await app.listen(Number(process.env.API_PORT ?? 3001), "127.0.0.1");
}
void bootstrap();
