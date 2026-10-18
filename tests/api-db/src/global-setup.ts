import { migrate } from "../../../apps/api/src/db/migrate.js";
import { migratorUrl } from "./db.js";

// Idempotent: the first run creates the schema in the test database, later runs find everything applied.
export default async function setup() {
  if (process.env.TEST_DB_NO_MIGRATE === "1") return; // mutation runs apply a deliberately broken schema themselves
  await migrate(migratorUrl());
}
