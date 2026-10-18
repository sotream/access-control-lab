import { migrate } from "./migrate.js";

const url = process.env.MIGRATOR_DATABASE_URL;
if (!url) {
  console.error("MIGRATOR_DATABASE_URL is required (casefile_migrator, see .env.example)");
  process.exit(1);
}
const r = await migrate(url);
console.log(JSON.stringify(r));
