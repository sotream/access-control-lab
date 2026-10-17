# Security policy

Casefile Vault is a learning and demonstration project; it holds no real data. Reports are still welcome.

## Reporting

Report privately to the repository owner: GitHub private vulnerability reporting if it is enabled for this
repository (Security tab), otherwise a direct message. Do not open a public issue with details.
Please do not post exploit details in public issues.

## Scope

In scope: authentication, authorization (RBAC and ABAC), token handling, the BFF session, audit log integrity,
upload handling, and the build and supply chain (workflows, dependencies, images).
Out of scope: the dev-only Keycloak setup (`start-dev`, plain HTTP on loopback, seeded users with documented
dev passwords) and denial of service against a laptop.

## Handling

Acknowledge within 7 days, fix or document within 30 days. Fixes land with a negative test that fails
without the fix, and the matching entry in `docs/threat-model.md` is updated.
