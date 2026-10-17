# Dev users

**Dev only. Fake identities, throwaway credentials, imported from `infra/keycloak/realm-casefile.json`. Never reuse
anywhere.** Values come from `.env.example` (copy to `.env`).

- Password for every user below: value of `DEV_USER_PASSWORD` (default `dev-only-Casefile-User-Pw-1`).
- SECRET users also have a seeded TOTP credential. Raw key = `DEV_TOTP_SECRET` (default `dev-only-totp-secret-0123`);
  Keycloak uses the UTF-8 bytes of that string as the HMAC key. For an authenticator app enter the base32 form
  `MRSXMLLPNZWHSLLUN52HALLTMVRXEZLUFUYDCMRT` (SHA-1, 6 digits, 30 s). The tests compute codes themselves.
- Keycloak master admin console: `http://127.0.0.1:8080`, `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD` from `.env`.

| Username | Role | Clearance | Unit | Compartments | TOTP | Why it exists |
|----------|------|-----------|------|--------------|------|---------------|
| `analyst-official` | analyst | OFFICIAL | alpha | none | no | baseline low clearance; IDOR and clearance negative tests |
| `analyst-secret-a` | analyst | SECRET | alpha | A | yes | SECRET read with compartment A; step-up |
| `analyst-secret-b` | analyst | SECRET | alpha | B | yes | same clearance, wrong compartment: must not read A files |
| `reviewer` | reviewer | CONFIDENTIAL | alpha | A | no | approves files; separation of duties (not own) |
| `unit-admin-alpha` | unit-admin | CONFIDENTIAL | alpha | none | no | admin of the unit that owns most test files |
| `unit-admin-beta` | unit-admin | CONFIDENTIAL | beta | none | no | admin of another unit: cross-unit negative tests |
| `auditor` | auditor | OFFICIAL | hq | none | no | audit log only, no case content |
| `platform-admin` | platform-admin | OFFICIAL | hq | none | no | operations role, no implicit case access |
| `lockout-victim` | analyst | OFFICIAL | alpha | none | no | used only by the brute-force test; do not log in with it |

Units and compartments are fixed lists in the realm user profile (`alpha`, `beta`, `hq`; `A`, `B`).
