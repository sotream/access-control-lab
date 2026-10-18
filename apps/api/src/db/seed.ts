import pg from "pg";

/** DEV ONLY. Fake case files with fixed ids so the dev users in docs/dev-users.md have something to read. Idempotent. */
export const SEED_FILES = [
  { id: "00000000-0000-4000-8000-000000000001", title: "Dev: public bulletin", classification: "OFFICIAL", unit: "alpha", compartments: [], status: "approved" },
  { id: "00000000-0000-4000-8000-000000000002", title: "Dev: beta unit notice", classification: "OFFICIAL", unit: "beta", compartments: [], status: "approved" },
  { id: "00000000-0000-4000-8000-000000000003", title: "Dev: alpha draft", classification: "OFFICIAL", unit: "alpha", compartments: [], status: "draft" },
  { id: "00000000-0000-4000-8000-000000000004", title: "Dev: confidential A", classification: "CONFIDENTIAL", unit: "alpha", compartments: ["A"], status: "approved" },
  { id: "00000000-0000-4000-8000-000000000005", title: "Dev: confidential A awaiting review", classification: "CONFIDENTIAL", unit: "alpha", compartments: ["A"], status: "submitted" },
  { id: "00000000-0000-4000-8000-000000000006", title: "Dev: secret A", classification: "SECRET", unit: "alpha", compartments: ["A"], status: "approved" },
  { id: "00000000-0000-4000-8000-000000000007", title: "Dev: secret B", classification: "SECRET", unit: "alpha", compartments: ["B"], status: "approved" },
] as const;

const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

/** Needs a connection that may bypass RLS (the dev superuser): the application role cannot insert arbitrary rows, by design. */
export async function seed(adminUrl: string): Promise<number> {
  const u = new URL(adminUrl);
  if (process.env.NODE_ENV === "production" || !LOOPBACK.has(u.hostname)) throw new Error("seed refuses to run against a non-local database or in production");
  const client = new pg.Client({ connectionString: adminUrl });
  await client.connect();
  try {
    let inserted = 0;
    for (const f of SEED_FILES) {
      const r = await client.query(
        `INSERT INTO case_files (id, title, body, classification, unit, compartments, status, author_id, submitted_by_id)
         VALUES ($1, $2, 'Fake dev content.', $3::classification, $4, $5::text[], $6::case_status, 'seed-author', $7)
         ON CONFLICT (id) DO NOTHING`,
        [f.id, f.title, f.classification, f.unit, [...f.compartments], f.status, f.status === "draft" ? null : "seed-submitter"],
      );
      inserted += r.rowCount ?? 0;
    }
    return inserted;
  } finally {
    await client.end();
  }
}
