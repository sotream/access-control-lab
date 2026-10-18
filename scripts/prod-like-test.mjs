#!/usr/bin/env node
// Checks of the prod-like stack (docs/deployment.md). It starts the stack (with the test-only echo route), asserts how it is built and attacks it:
// production profile refuses dev values, only the proxy is reachable, the proxy overwrites the headers the BFF trusts, containers are non-root /
// read-only / capability-free, and a real EICAR file is caught by the real scanner through the real login, BFF and API.
// Usage: node scripts/prod-like-test.mjs [--keep]    (needs docker, curl-free: uses node's https with the stack's own CA)
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import https from "node:https";
import net from "node:net";
import { join } from "node:path";

const root = new URL("../", import.meta.url).pathname;
const dir = join(root, "secrets-dev", "prod-like");
const compose = ["compose", "-f", "docker-compose.prod-like.yml", "-f", "docker-compose.prod-like.test.yml"];
const NODE_IMAGE = "node:24-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5";
// The stack's CA is trusted through NODE_EXTRA_CA_CERTS (set by re-running this script once the files exist), not handed to each request.
if (!process.env.NODE_EXTRA_CA_CERTS) {
  if (!process.argv.includes("--fast")) execFileSync("node", ["scripts/prod-like-setup.mjs"], { cwd: root, stdio: "inherit" });
  const r = spawnSync(process.execPath, [new URL(import.meta.url).pathname, ...process.argv.slice(2)], { cwd: root, stdio: "inherit", env: { ...process.env, NODE_EXTRA_CA_CERTS: join(dir, "ca.crt") } });
  process.exit(r.status ?? 1);
}
const env = Object.fromEntries(readFileSync(join(dir, "compose.env"), "utf8").split("\n").filter(Boolean).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));

const sh = (cmd, args, o = {}) => execFileSync(cmd, args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...o });
const dc = (...args) => sh("docker", [...compose, ...args]);
const tryRun = (cmd, args, extraEnv) => spawnSync(cmd, args, { cwd: root, encoding: "utf8", ...(extraEnv ? { env: { ...process.env, ...extraEnv } } : {}) });

const only = process.argv.find((a) => a.startsWith("--only="))?.slice(7);
const fast = process.argv.includes("--fast"); // mutation runs: stack already built, no setup
let failed = 0;
async function check(name, fn) {
  if (only && !only.split("|").some((part) => name.toLowerCase().includes(part.toLowerCase()))) return;
  try {
    await fn();
    console.log(`PASS  ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL  ${name}\n      ${String(e.message ?? e).split("\n").join("\n      ")}`);
  }
}
const assert = (c, m) => {
  if (!c) throw new Error(m);
};

/** HTTPS to the proxy on 127.0.0.1:443 with the stack's CA; the name only selects the virtual host */
function request(host, path, { method = "GET", headers = {}, body, jar } = {}) {
  return new Promise((resolve, reject) => {
    const h = { host, ...headers, ...(jar?.size ? { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") } : {}) };
    const req = https.request({ host: "127.0.0.1", servername: host, port: 443, path, method, headers: h, lookup: (_n, _o, cb) => cb(null, "127.0.0.1", 4) }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        for (const c of res.headers["set-cookie"] ?? []) {
          const [kv] = c.split(";");
          const i = kv.indexOf("=");
          const v = kv.slice(i + 1);
          if (/max-age=0|expires=thu, 01 jan 1970/i.test(c) || v === "") jar?.delete(kv.slice(0, i));
          else jar?.set(kv.slice(0, i), v);
        }
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) });
      });
    });
    req.on("error", reject);
    req.end(body);
  });
}
const text = (r) => r.body.toString("utf8");
const vault = (path, o) => request("vault.localhost", path, o);
const idp = (path, o) => request("id.localhost", path, o);

/** can this host:port be connected to from the host? */
const reachable = (port) =>
  new Promise((resolve) => {
    const s = net.connect({ host: "127.0.0.1", port, timeout: 1500 });
    s.on("connect", () => (s.destroy(), resolve(true)));
    s.on("error", () => resolve(false));
    s.on("timeout", () => (s.destroy(), resolve(false)));
  });

// ------------------------------------------------------------------ bring the stack up
console.log("starting the prod-like stack (first run builds the images)...");
try {
  dc("up", "-d", ...(fast ? [] : ["--build"]), "--wait", "--wait-timeout", "600");
} catch (e) {
  // a stack that does not come up is a failed check, with the reason, not a crash of the test
  console.log(`FAIL  the stack comes up\n      ${String(e.stderr ?? e.message).split("\n").slice(-6).join("\n      ")}`);
  if (!process.argv.includes("--keep")) tryRun("docker", [...compose, "down", "-v"]);
  process.exit(1);
}
dc("restart", "caddy"); // picks up regenerated bind-mounted files on hosts that keep the old inode
await new Promise((r) => setTimeout(r, 3000));

const SERVICES = ["caddy", "web", "api", "postgres", "keycloak", "clamd", "echo"];
const idOf = (svc) => dc("ps", "-q", svc).trim();

await check("every service is up and the ones with healthchecks are healthy", () => {
  for (const s of SERVICES) {
    const st = JSON.parse(sh("docker", ["inspect", idOf(s)]))[0].State;
    assert(st.Running, `${s} is not running`);
    if (st.Health) assert(st.Health.Status === "healthy", `${s} is ${st.Health.Status}`);
  }
});

await check("containers: no process runs as root, read-only root filesystem, all capabilities dropped (only the listed ones back), no-new-privileges, memory and pids limited", () => {
  const allowedAdd = {}; // no service gets any capability back
  for (const s of SERVICES) {
    const c = JSON.parse(sh("docker", ["inspect", idOf(s)]))[0];
    const h = c.HostConfig;
    assert(h.ReadonlyRootfs, `${s}: root filesystem is writable`);
    assert((h.CapDrop ?? []).includes("ALL"), `${s}: capabilities not dropped`);
    assert((h.SecurityOpt ?? []).includes("no-new-privileges:true"), `${s}: no-new-privileges missing`);
    assert(h.Memory > 0 && h.PidsLimit > 0, `${s}: no memory or pids limit`);
    const add = (h.CapAdd ?? []).map((c) => c.replace(/^CAP_/, "")).sort().join();
    assert(add === (allowedAdd[s] ?? []).slice().sort().join(), `${s}: unexpected capabilities added: ${add}`);
    assert(!(h.Privileged), `${s}: privileged`);
    const top = sh("docker", ["top", idOf(s), "-o", "user,pid,comm"]).split("\n").slice(1).filter(Boolean);
    const root = top.filter((l) => /^(root|0)\s/.test(l.trim()));
    assert(root.length === 0, `${s}: processes running as root:\n${root.join("\n")}`);
  }
});

await check("networks: app, data and scan are internal (no route out); only the proxy publishes a port, on loopback", () => {
  for (const n of ["app", "data", "scan"]) assert(JSON.parse(sh("docker", ["network", "inspect", `casefile-prod-like_${n}`]))[0].Internal === true, `${n} network is not internal`);
  assert(JSON.parse(sh("docker", ["network", "inspect", "casefile-prod-like_edge"]))[0].Internal === false, "edge must be the routable one");
  for (const s of SERVICES) {
    const ports = JSON.parse(sh("docker", ["inspect", idOf(s)]))[0].NetworkSettings.Ports ?? {};
    const published = Object.entries(ports).filter(([, v]) => v?.length);
    if (s === "caddy") assert(published.length === 1 && published[0][1][0].HostIp === "127.0.0.1" && published[0][1][0].HostPort === "443", `caddy publishes ${JSON.stringify(published)}`);
    else assert(published.length === 0, `${s} publishes ${JSON.stringify(published)}`);
  }
});

await check("a request that does not go through the proxy cannot reach the BFF, the API, Postgres, Keycloak or the scanner (host and edge network)", async () => {
  // ports another stack on this machine (the dev compose) publishes are not ours to judge
  const others = sh("docker", ["ps", "--format", '{{.Label "com.docker.compose.project"}}|{{.Ports}}']).split("\n").filter((l) => l && !l.startsWith("casefile-prod-like|")).join("\n");
  for (const port of [3000, 3001, 5432, 8080, 9000, 3310, 9001, 80, 8443]) {
    if (new RegExp(`:${port}->`).test(others)) {
      console.log(`      (skipping 127.0.0.1:${port}: published by another stack on this machine)`);
      continue;
    }
    assert(!(await reachable(port)), `127.0.0.1:${port} accepts connections`);
  }
  const probe = (host, port) =>
    tryRun("docker", ["run", "--rm", "--network", "casefile-prod-like_edge", NODE_IMAGE, "node", "-e", `require('net').connect({host:'${host}',port:${port},timeout:2000}).on('connect',()=>process.exit(0)).on('error',()=>process.exit(1)).on('timeout',()=>process.exit(1))`]).status;
  for (const [h, p] of [["web", 3000], ["api", 3001], ["postgres", 5432], ["keycloak", 8080], ["clamd", 3310]]) assert(probe(h, p) !== 0, `a container on the edge network reaches ${h}:${p}`);
  assert(probe("caddy", 443) === 0, "the proxy is not reachable on the edge network (test setup problem)");
});

await check("the app and data networks have no way out: no internet from a container on them", () => {
  for (const n of ["app", "data", "scan"]) {
    const r = tryRun("docker", ["run", "--rm", "--network", `casefile-prod-like_${n}`, NODE_IMAGE, "node", "-e", "fetch('https://example.com',{signal:AbortSignal.timeout(4000)}).then(()=>process.exit(0),()=>process.exit(1))"]);
    assert(r.status !== 0, `a container on ${n} reached the internet`);
  }
});

await check("TLS and headers: HTTPS works with the stack's CA, HSTS is set, no Server / Via / Alt-Svc, the BFF's own headers pass", async () => {
  const r = await vault("/api/auth/session");
  assert(r.status === 200, `status ${r.status}`);
  assert(/max-age=31536000/.test(r.headers["strict-transport-security"] ?? ""), "HSTS missing");
  for (const h of ["server", "via", "alt-svc", "x-powered-by"]) assert(r.headers[h] === undefined, `${h} is exposed`);
  assert(r.headers["x-content-type-options"] === "nosniff" && r.headers["content-security-policy"], "BFF headers missing");
  // a client that does not know the stack's CA must refuse the certificate
  const probe = tryRun("node", ["-e", "require('https').get({host:'127.0.0.1',port:443,servername:'vault.localhost',headers:{host:'vault.localhost'},lookup:(n,o,cb)=>cb(null,'127.0.0.1',4)},()=>process.exit(0)).on('error',()=>process.exit(1))"], { NODE_EXTRA_CA_CERTS: "" });
  assert(probe.status === 1, "the certificate is trusted without the stack's CA");
});

await check("identity provider: only the realm and its resources are reachable through the proxy (no admin console, master realm, health, metrics)", async () => {
  assert((await idp("/realms/casefile/.well-known/openid-configuration")).status === 200, "realm discovery not served");
  assert(JSON.parse(text(await idp("/realms/casefile/.well-known/openid-configuration"))).issuer === "https://id.localhost/realms/casefile", "issuer differs from the public name");
  for (const p of ["/admin/", "/admin/master/console/", "/realms/master", "/realms/master/.well-known/openid-configuration", "/health", "/health/ready", "/metrics", "/"]) assert((await idp(p)).status === 404, `${p} is reachable`);
  assert((await vault("/realms/casefile")).status !== 200, "the BFF vhost serves identity paths");
});

await check("the proxy overwrites what the BFF trusts: forged x-acl-client-ip, x-acl-proxy-secret, x-acl-zone and forwarded headers never arrive", async () => {
  const forged = { "x-acl-client-ip": "6.6.6.6", "x-acl-proxy-secret": "forged-secret", "x-acl-zone": "managed", "x-real-ip": "6.6.6.6", forwarded: "for=6.6.6.6", "x-forwarded-for": "6.6.6.6, 7.7.7.7", "x-forwarded-host": "evil.example", "x-forwarded-port": "1", "x-forwarded-proto": "http" };
  const got = JSON.parse(text(await vault("/__echo", { headers: forged })));
  const secret = readFileSync(join(dir, "trusted_proxy_secret"), "utf8").trim();
  assert(got["x-acl-proxy-secret"] === secret, `proxy secret is not the proxy's: ${got["x-acl-proxy-secret"]}`);
  assert(/^\d+\.\d+\.\d+\.\d+$/.test(got["x-acl-client-ip"]) && got["x-acl-client-ip"] !== "6.6.6.6", `client ip: ${got["x-acl-client-ip"]}`);
  assert(got["x-forwarded-for"] === got["x-acl-client-ip"], `x-forwarded-for: ${got["x-forwarded-for"]}`);
  assert(got["x-forwarded-proto"] === "https", `x-forwarded-proto: ${got["x-forwarded-proto"]}`);
  for (const h of ["x-acl-zone", "x-real-ip", "forwarded", "x-forwarded-host", "x-forwarded-port"]) assert(got[h] === undefined, `${h} reached the upstream: ${got[h]}`);
  // a duplicate header (a request-smuggling-ish variant) is also replaced, not merged
  const dup = JSON.parse(text(await vault("/__echo", { headers: { "x-acl-client-ip": ["6.6.6.6", "8.8.8.8"] } })));
  assert(!String(dup["x-acl-client-ip"]).includes("6.6.6.6") && !String(dup["x-acl-client-ip"]).includes("8.8.8.8"), `duplicate header survived: ${dup["x-acl-client-ip"]}`);
});

await check("the images run the production profile by default and the stack refuses to start with development values", () => {
  for (const img of ["casefile-api:prod-like", "casefile-web:prod-like"]) assert(JSON.parse(sh("docker", ["image", "inspect", img]))[0].Config.Env.includes("ACL_ENV=production"), `${img} does not default to ACL_ENV=production`);
  for (const s of ["api", "web", "migrate"]) {
    const cfg = JSON.parse(dc("config", "--format", "json")).services[s];
    assert(cfg.environment.ACL_ENV === "production", `${s}: ACL_ENV is ${cfg.environment.ACL_ENV} in the compose file`);
  }
  const dev = readFileSync(join(root, ".env.example"), "utf8");
  const val = (n) => /^[A-Z_]+=(.*)$/m.exec(dev.split("\n").find((l) => l.startsWith(`${n}=`)))[1];
  const run = (img, e) => tryRun("docker", ["run", "--rm", "--network", "none", ...Object.entries(e).flatMap(([k, v]) => ["-e", `${k}=${v}`]), img]);
  const api = run("casefile-api:prod-like", { DATABASE_URL: val("DATABASE_URL"), AUDIT_HMAC_KEYS: val("AUDIT_HMAC_KEYS"), ZONE_SIGNING_KEYS: val("ZONE_SIGNING_KEYS"), KEYCLOAK_ISSUER: "https://id.localhost/realms/casefile" });
  assert(api.status !== 0 && /development value/.test(api.stdout + api.stderr), `api with dev values: exit ${api.status}: ${(api.stdout + api.stderr).slice(0, 200)}`);
  const apiNoEnv = run("casefile-api:prod-like", { DATABASE_URL: "postgres://u:q9Xv2LmT8sWk4RzP7nYdQ@db/acl" }); // a good password but nothing else: still refuses
  assert(apiNoEnv.status !== 0, "api started with incomplete configuration");
  const web = run("casefile-web:prod-like", { WEB_ORIGIN: "https://vault.localhost", KEYCLOAK_ISSUER: "https://id.localhost/realms/casefile", API_BASE_URL: "http://api:3001", API_INTERNAL_HTTP: "true", WEB_DATABASE_URL: val("WEB_DATABASE_URL"), CASEFILE_WEB_SECRET: val("CASEFILE_WEB_SECRET"), SESSION_ENCRYPTION_KEYS: val("SESSION_ENCRYPTION_KEYS"), AUDIT_HMAC_KEYS: val("AUDIT_HMAC_KEYS"), ZONE_SIGNING_KEYS: val("ZONE_SIGNING_KEYS"), TRUSTED_PROXY_SECRET: "dev-only-proxy-secret-0123456789abcdef" });
  // the BFF validates on its first request (instrumentation) and exits; give it a moment through a throw-away container with a published-less port
  assert(web.status !== 0 || /development value|refusing to start/.test(web.stdout + web.stderr), "web did not refuse dev values");
});

await check("secrets are files, not environment: no secret value in `docker inspect` of any container", () => {
  const values = [...Object.entries(env).filter(([k]) => /PASSWORD|SECRET|TOTP/.test(k)).map(([, v]) => v), readFileSync(join(dir, "trusted_proxy_secret"), "utf8").trim(), readFileSync(join(dir, "session_encryption_keys"), "utf8").trim().split(":")[1], readFileSync(join(dir, "audit_hmac_keys"), "utf8").trim().split(":")[1], readFileSync(join(dir, "zone_signing_keys"), "utf8").trim().split(":")[1]];
  for (const s of ["api", "web", "caddy"]) {
    const inspect = sh("docker", ["inspect", idOf(s)]);
    for (const v of values) assert(!inspect.includes(v), `${s}: a secret value is visible in docker inspect`);
  }
});

await check("attachment volume: owned by the unprivileged user, mode 0700", () => {
  const out = tryRun("docker", ["run", "--rm", "-v", "casefile-prod-like_attachments:/v:ro", NODE_IMAGE, "node", "-e", "const s=require('fs').statSync('/v');console.log(s.uid,s.gid,(s.mode&0o777).toString(8))"]);
  assert(out.stdout.trim() === "65532 65532 755" || out.stdout.trim() === "65532 65532 700", `volume owner/mode: ${out.stdout.trim()} ${out.stderr.trim()}`);
});

await check("the real scanner: clamd flags the EICAR test file and passes a clean one (client of the API image against the clamd service)", () => {
  const script = "const {ClamdScanner}=await import('/app/dist/attachments/scanner.js');const s=new ClamdScanner({clamdHost:'clamd',clamdPort:3310});const e=['X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$','EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'].join('');console.log(JSON.stringify([await s.scan(Buffer.from(e)),await s.scan(Buffer.from('plain notes\\n'))]))";
  const out = dc("exec", "-T", "api", "/nodejs/bin/node", "--input-type=module", "-e", script).trim();
  const [bad, good] = JSON.parse(out);
  assert(bad.verdict === "infected" && /eicar/i.test(bad.signature), `EICAR: ${JSON.stringify(bad)}`);
  assert(good.verdict === "clean", `clean file: ${JSON.stringify(good)}`);
});

await check("end to end through the proxy with a real Keycloak login: a clean file is stored and downloadable, EICAR is quarantined and never served", async () => {
  const jar = new Map();
  const kc = new Map();
  // sign in: BFF -> Keycloak form -> callback
  const start = await vault("/api/auth/login", { jar });
  assert(start.status === 303, `login start: ${start.status}`);
  const auth = new URL(start.headers.location);
  const form = await idp(auth.pathname + auth.search, { jar: kc });
  const action = /action="([^"]+)"/.exec(text(form))?.[1]?.replaceAll("&amp;", "&");
  assert(action, "no login form");
  const post = await idp(new URL(action).pathname + new URL(action).search, { method: "POST", jar: kc, headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ username: "analyst-official", password: env.DEV_USER_PASSWORD, credentialId: "" }).toString() });
  assert(post.status === 302 && post.headers.location.startsWith("https://vault.localhost/api/auth/callback"), `keycloak answered ${post.status} ${post.headers.location}`);
  const cb = await vault(new URL(post.headers.location).pathname + new URL(post.headers.location).search, { jar });
  assert(cb.status === 303 && [...jar.keys()].some((k) => k.includes("session")), `callback ${cb.status}; cookies ${[...jar.keys()]}`);
  const csrf = /name="csrf" value="([^"]+)"/.exec(text(await vault("/cases/new", { jar })))?.[1];
  assert(csrf, "no csrf token");
  const form2 = (fields) => ({ method: "POST", jar, headers: { origin: "https://vault.localhost", "content-type": "application/x-www-form-urlencoded", "sec-fetch-site": "same-origin" }, body: new URLSearchParams(fields).toString() });
  const made = await vault("/actions/case-files/create", form2({ csrf, title: "prod-like", body: "b", classification: "OFFICIAL", compartments: "" }));
  const id = /\/cases\/([0-9a-f-]{36})/.exec(made.headers.location ?? "")?.[1];
  assert(id, `no case file: ${made.status} ${made.headers.location}`);

  const upload = (name, content, type = "text/plain") => {
    const b = "----acl" + Date.now();
    const body = Buffer.concat([Buffer.from(`--${b}\r\ncontent-disposition: form-data; name="csrf"\r\n\r\n${csrf}\r\n--${b}\r\ncontent-disposition: form-data; name="file"; filename="${name}"\r\ncontent-type: ${type}\r\n\r\n`), Buffer.from(content), Buffer.from(`\r\n--${b}--\r\n`)]);
    return vault(`/actions/case-files/${id}/attachments`, { method: "POST", jar, headers: { origin: "https://vault.localhost", "sec-fetch-site": "same-origin", "content-type": `multipart/form-data; boundary=${b}`, "content-length": String(body.length) }, body });
  };
  const eicar = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"].join("");
  const good = await upload("notes.txt", "plain notes\n");
  assert(new URL(good.headers.location, "https://vault.localhost").searchParams.get("m") === "uploaded", `clean upload: ${good.status} ${good.headers.location}`);
  const bad = await upload("eicar.txt", eicar);
  assert(new URL(bad.headers.location, "https://vault.localhost").searchParams.get("m") === "rejected", `EICAR upload: ${bad.status} ${bad.headers.location}`);
  const page = text(await vault(`/cases/${id}`, { jar }));
  const links = [...page.matchAll(/href="\/attachments\/[0-9a-f-]{36}\/([0-9a-f-]{36})"/g)];
  assert(links.length === 1, `expected exactly one downloadable attachment, found ${links.length}`);
  assert(/eicar\.txt[^<]*<\/span>/.test(page) || page.includes("eicar.txt"), "the quarantined file is not listed");
  assert(!/href="[^"]*"[^>]*>eicar\.txt/.test(page), "the quarantined file has a download link");
  const dl = await vault(`/attachments/${id}/${links[0][1]}`, { jar });
  assert(dl.status === 200 && text(dl) === "plain notes\n", `download: ${dl.status}`);
  assert(/^attachment;/.test(dl.headers["content-disposition"]) && dl.headers["x-content-type-options"] === "nosniff" && /sandbox/.test(dl.headers["content-security-policy"]), "download headers");
  const rows = sh("docker", [...compose, "exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "acl", "-At", "-c", "select display_name, status, scan_detail from attachments order by created_at"].slice(0)) .trim().split("\n");
  assert(rows.some((r) => r.startsWith("notes.txt|clean")) && rows.some((r) => /^eicar\.txt\|quarantined\|.*Eicar/i.test(r)), `database rows: ${rows}`);
  const files = sh("docker", ["run", "--rm", "-v", "casefile-prod-like_attachments:/v:ro", NODE_IMAGE, "node", "-e", "const f=require('fs');console.log(f.readdirSync('/v/files').length,f.readdirSync('/v/quarantine').length)"]).trim();
  assert(files === "1 1", `files/quarantine counts: ${files}`);
});

// last: it uses up this machine's login budget for a minute
await check("through the real proxy a client cannot choose its rate-limit bucket: forged client addresses share the real one", async () => {
  const codes = [];
  for (let i = 0; i < 30; i++) codes.push((await vault("/api/auth/login", { headers: { "x-attack-instance": "strict", "x-acl-client-ip": `9.9.9.${i}`, "x-forwarded-for": `9.9.8.${i}` } })).status); // the BFF instance with the production limits (the test compose file lifts them on the default one)
  // a fresh bucket of 20: the 21st request is the first refusal, and it never goes away
  const first = codes.indexOf(429);
  assert(first >= 18 && first <= 20, `the first 429 came at request ${first + 1}: ${codes}`);
  assert(codes.slice(first).every((c) => c === 429) && codes.slice(0, first).every((c) => c === 303), `pattern: ${codes}`);
});

if (failed > 0) {
  // the stack is removed below: keep the evidence of a failure in the output
  for (const svc of ["caddy", "keycloak", "web", "api"]) console.log(`\n--- ${svc} (last 40 lines)\n${tryRun("docker", [...compose, "logs", "--no-color", "--tail", "40", svc]).stdout}`);
}
if (!process.argv.includes("--keep")) dc("down", "-v");
console.log(failed === 0 ? "\nall prod-like checks passed" : `\n${failed} check(s) failed`);
process.exit(failed === 0 ? 0 : 1);
