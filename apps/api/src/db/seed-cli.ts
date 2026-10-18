import { seed } from "./seed.js";

const url = process.env.ADMIN_DATABASE_URL;
if (!url) {
  console.error("ADMIN_DATABASE_URL is required (dev superuser, see .env.example)");
  process.exit(1);
}
console.log(JSON.stringify({ inserted: await seed(url) }));
