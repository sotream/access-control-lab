import { migrate } from "../../../apps/api/src/db/migrate.js";
import { migratorUrl } from "./db.js";

// Idempotent: the first run creates the schema in the test database, later runs find everything applied.
export default async function setup() {
  await migrate(migratorUrl());
}
