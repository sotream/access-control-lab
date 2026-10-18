import { migrate } from "../../../apps/api/src/db/migrate.js";
import { migratorUrl } from "../../api-db/src/db.js";

export default async function setup() {
  await migrate(migratorUrl()); // idempotent
}
