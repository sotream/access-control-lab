// Case files the attacks go after, inserted by the operator (psql) so that every class of resource exists: each classification, compartment and unit.
import { insertCase, psql, q } from "./stack.js";

export interface Fixtures {
  offAlpha: string;
  offBeta: string;
  confAlphaA: string;
  secAlphaA: string;
  secAlphaB: string;
  submittedAlpha: string;
}

let cached: Fixtures | undefined;
export function fixtures(): Fixtures {
  if (cached) return cached;
  const find = (title: string): string | undefined => psql(`SELECT id FROM case_files WHERE title = ${q(title)} LIMIT 1`).split("\n")[0] || undefined;
  const make = (title: string, o: Parameters<typeof insertCase>[0]) => find(title) ?? insertCase({ ...o, title });
  cached = {
    offAlpha: make("attack: official alpha", { classification: "OFFICIAL", unit: "alpha", status: "approved" }),
    offBeta: make("attack: official beta", { classification: "OFFICIAL", unit: "beta", status: "approved" }),
    confAlphaA: make("attack: confidential alpha A", { classification: "CONFIDENTIAL", unit: "alpha", compartments: ["A"], status: "approved" }),
    secAlphaA: make("attack: secret alpha A", { classification: "SECRET", unit: "alpha", compartments: ["A"], status: "approved" }),
    secAlphaB: make("attack: secret alpha B", { classification: "SECRET", unit: "alpha", compartments: ["B"], status: "approved" }),
    submittedAlpha: make("attack: submitted alpha", { classification: "OFFICIAL", unit: "alpha", status: "submitted" }),
  };
  return cached;
}
