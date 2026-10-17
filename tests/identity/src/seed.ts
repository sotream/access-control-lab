// Expected claims of the dev users imported from infra/keycloak/realm-casefile.json (see docs/dev-users.md).
export const SEED = {
  "analyst-official": { role: "analyst", clearance: "OFFICIAL", unit: "alpha", compartments: undefined },
  "analyst-secret-a": { role: "analyst", clearance: "SECRET", unit: "alpha", compartments: ["A"] },
  "analyst-secret-b": { role: "analyst", clearance: "SECRET", unit: "alpha", compartments: ["B"] },
  reviewer: { role: "reviewer", clearance: "CONFIDENTIAL", unit: "alpha", compartments: ["A"] },
  "unit-admin-alpha": { role: "unit-admin", clearance: "CONFIDENTIAL", unit: "alpha", compartments: undefined },
  "unit-admin-beta": { role: "unit-admin", clearance: "CONFIDENTIAL", unit: "beta", compartments: undefined },
  auditor: { role: "auditor", clearance: "OFFICIAL", unit: "hq", compartments: undefined },
  "platform-admin": { role: "platform-admin", clearance: "OFFICIAL", unit: "hq", compartments: undefined },
} as const;
