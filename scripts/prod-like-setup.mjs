#!/usr/bin/env node
// Generates everything the prod-like stack needs under secrets-dev/prod-like/ (git-ignored, never committed):
// random strong secrets (one file each, mode 0600, so the services read them with NAME_FILE), a throw-away CA and server certificate for
// vault.localhost and id.localhost, and the realm file adapted to https (sslRequired=all, redirect URIs of the proxy).
// Usage: node scripts/prod-like-setup.mjs [--force]   (needs the openssl command line tool)
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";

const root = new URL("../", import.meta.url).pathname;
const out = join(root, "secrets-dev", "prod-like");
if (existsSync(join(out, "compose.env")) && !process.argv.includes("--force")) {
  console.log(`${out} exists; use --force to regenerate (this makes existing database volumes unusable)`);
  process.exit(0);
}
mkdirSync(out, { recursive: true, mode: 0o700 });

const b64 = (n = 32) => randomBytes(n).toString("base64");
const pw = () => randomBytes(24).toString("base64url"); // 32 characters, URL safe (goes into connection strings)
const ring = (id) => `${id}:${b64()}`;
const put = (name, value) => {
  writeFileSync(join(out, name), value, { mode: 0o600 });
  chmodSync(join(out, name), 0o644); // readable by the non-root service users inside the containers; the directory is 0700 on the host
};

const P = { postgres: pw(), keycloakDb: pw(), migrator: pw(), app: pw(), web: pw(), audit: pw(), kcAdmin: pw(), webSecret: pw(), userPw: `Pw-${pw()}`, totp: randomBytes(10).toString("hex") };
const db = (user, pass) => `postgres://${user}:${pass}@postgres:5432/acl`;

put("database_url_api", db("casefile_app", P.app));
put("database_url_web", db("casefile_web", P.web));
put("database_url_audit", db("casefile_audit", P.audit));
put("audit_hmac_keys", ring("prod-like-audit-1"));
put("zone_signing_keys", ring("prod-like-zone-1"));
put("session_encryption_keys", ring("prod-like-session-1"));
put("trusted_proxy_secret", pw() + pw());
put("casefile_web_secret", P.webSecret);

// values for the services that only take environment variables (postgres init script, keycloak): kept in one env file, read by compose
writeFileSync(
  join(out, "compose.env"),
  [
    "POSTGRES_USER=postgres", `POSTGRES_PASSWORD=${P.postgres}`, "POSTGRES_DB=acl",
    "KEYCLOAK_DB_NAME=keycloak", "KEYCLOAK_DB_USER=keycloak", `KEYCLOAK_DB_PASSWORD=${P.keycloakDb}`,
    `CASEFILE_MIGRATOR_PASSWORD=${P.migrator}`, `CASEFILE_APP_PASSWORD=${P.app}`, `CASEFILE_WEB_DB_PASSWORD=${P.web}`, `CASEFILE_AUDIT_PASSWORD=${P.audit}`,
    "KEYCLOAK_ADMIN=admin", `KEYCLOAK_ADMIN_PASSWORD=${P.kcAdmin}`,
    `KC_DB_PASSWORD=${P.keycloakDb}`, "KC_BOOTSTRAP_ADMIN_USERNAME=admin", `KC_BOOTSTRAP_ADMIN_PASSWORD=${P.kcAdmin}`,
    `CASEFILE_WEB_SECRET=${P.webSecret}`, `DEV_USER_PASSWORD=${P.userPw}`, `DEV_TOTP_SECRET=${P.totp}`,
    `MIGRATOR_DATABASE_URL=${db("casefile_migrator", P.migrator)}`,
    "",
  ].join("\n"),
  { mode: 0o600 },
);
chmodSync(join(out, "compose.env"), 0o600);

// throw-away CA and a server certificate for the two names (the BFF and the API trust this CA through NODE_EXTRA_CA_CERTS)
const sh = (args, opts = {}) => execFileSync("openssl", args, { stdio: ["ignore", "pipe", "pipe"], ...opts });
sh(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "30", "-subj", "/CN=casefile prod-like test CA", "-keyout", join(out, "ca.key"), "-out", join(out, "ca.crt")]);
sh(["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-subj", "/CN=vault.localhost", "-keyout", join(out, "tls.key"), "-out", join(out, "tls.csr")]);
writeFileSync(join(out, "san.cnf"), "subjectAltName=DNS:vault.localhost,DNS:id.localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n");
sh(["x509", "-req", "-in", join(out, "tls.csr"), "-CA", join(out, "ca.crt"), "-CAkey", join(out, "ca.key"), "-CAcreateserial", "-days", "30", "-extfile", join(out, "san.cnf"), "-out", join(out, "tls.crt")]);
for (const f of ["tls.key", "ca.key"]) chmodSync(join(out, f), 0o644); // the proxy user reads the key; the host directory is 0700

// realm for https behind the proxy
const realm = readFileSync(join(root, "infra/keycloak/realm-casefile.json"), "utf8")
  .replaceAll("http://127.0.0.1:3000", "https://vault.localhost")
  .replace('"sslRequired": "external"', '"sslRequired": "all"');
writeFileSync(join(out, "realm-casefile.json"), realm);
console.log(`generated ${out}\nbring the stack up with: docker compose -f docker-compose.prod-like.yml up -d --build   (see docs/deployment.md)`);
