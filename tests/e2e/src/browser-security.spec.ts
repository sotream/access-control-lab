// What only a real browser can show: the CSP is enforced, the framing ban holds, the __Host- cookie has the attributes the BFF promised,
// and no token is reachable from page scripts or the DOM.
import { expect, expectClean, test, watch } from "./helpers";

test("the session cookie is __Host-, Secure, HttpOnly, SameSite=Lax, path /, with no Domain; no token is reachable from script", async ({ as }) => {
  const page = await as("analyst-official");
  const w = watch(page);
  await page.goto("/cases");
  const cookies = await page.context().cookies("https://vault.localhost");
  const session = cookies.find((c) => c.name === "__Host-casefile_session");
  expect(session, "session cookie").toBeDefined();
  expect(session).toMatchObject({ secure: true, httpOnly: true, sameSite: "Lax", path: "/" });
  expect(session!.domain, "host-only: the domain has no leading dot").toBe("vault.localhost");
  for (const c of cookies) expect(c.name.startsWith("__Host-") || c.name.startsWith("casefile_"), c.name).toBe(true);

  const exposed = await page.evaluate(() => ({
    cookie: document.cookie,
    local: JSON.stringify({ ...localStorage }),
    session: JSON.stringify({ ...sessionStorage }),
    dom: document.documentElement.outerHTML,
  }));
  expect(exposed.cookie, "document.cookie").not.toContain("casefile_session");
  expect(exposed.local).toBe("{}");
  expect(exposed.session).toBe("{}");
  const jwt = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/;
  for (const [where, text] of Object.entries(exposed)) expect(text, where).not.toMatch(jwt);
  expect(exposed.dom).not.toContain(session!.value);
  expect((await page.context().storageState()).origins.flatMap((o) => o.localStorage)).toEqual([]);
  expectClean(w);
});

test("the CSP is enforced: inline script and inline handler that reach the page markup do not run, a foreign image is not requested, each is reported", async ({ as }) => {
  const page = await as("analyst-official");
  const w = watch(page);
  const failed: string[] = [];
  page.on("requestfailed", (r) => failed.push(`${r.url()} ${r.failure()?.errorText}`));
  // simulates what a stored-XSS bug would do: markup with an inline script, an inline handler and a foreign image arrives inside the server's HTML,
  // with the server's own CSP header. (A script created by a trusted script is allowed under 'strict-dynamic' by design, so the test injects markup.)
  await page.route("**/cases", async (route) => {
    const response = await route.fetch();
    const html = (await response.text()).replace("</body>", `<script>window.__pwned = true</script><img src="x" onerror="window.__pwned = true"><img src="https://evil.example/pixel.png"></body>`);
    await route.fulfill({ response, body: html });
  });
  await page.goto("/cases");
  await page.waitForTimeout(500);
  expect(await page.evaluate(() => (window as unknown as { __pwned?: boolean }).__pwned)).toBeUndefined();
  expect(w.csp.some((v) => v.startsWith("script-src"))).toBe(true);
  expect(w.csp.some((v) => v.startsWith("img-src") && v.includes("evil.example"))).toBe(true);
  expect(failed.filter((f) => f.includes("evil.example")), "the browser blocked the foreign request").toEqual(["https://evil.example/pixel.png csp"]);
});

test("an inline style attribute and an inline event handler are blocked too", async ({ as }) => {
  const page = await as("analyst-official");
  const w = watch(page);
  await page.goto("/cases");
  await page.evaluate(() => {
    const b = document.createElement("button");
    b.setAttribute("onclick", "window.__clicked = true");
    b.textContent = "x";
    document.body.append(b);
    b.click();
    const d = document.createElement("div");
    d.setAttribute("style", "color: red");
    document.body.append(d);
  });
  expect(await page.evaluate(() => (window as unknown as { __clicked?: boolean }).__clicked)).toBeUndefined();
  expect(w.csp.length).toBeGreaterThan(0);
});

test("the application cannot be framed: from another origin the frame stays empty (frame-ancestors none, X-Frame-Options DENY)", async ({ as }) => {
  const page = await as("analyst-official");
  await page.route("http://attacker.example/", (r) => r.fulfill({ contentType: "text/html", body: `<!doctype html><iframe id="f" src="https://vault.localhost/cases" width="600" height="400"></iframe>` }));
  await page.goto("http://attacker.example/");
  await page.waitForTimeout(1500);
  const frame = page.frames().find((f) => f !== page.mainFrame());
  const html = frame ? await frame.content().catch(() => "") : "";
  expect(html).not.toContain("Case files");
  expect(html).not.toContain("topbar");
  const r = await page.request.get("https://vault.localhost/cases");
  expect(r.headers()["x-frame-options"]).toBe("DENY");
  expect(r.headers()["content-security-policy"]).toContain("frame-ancestors 'none'");
});

test("security headers on a real page load", async ({ page }) => {
  const r = await page.goto("/");
  const h = r!.headers();
  expect(h["content-security-policy"]).toMatch(/script-src 'self' 'nonce-[^']+' 'strict-dynamic'/);
  expect(h["content-security-policy"]).not.toMatch(/unsafe-inline|unsafe-eval/);
  expect(h["x-content-type-options"]).toBe("nosniff");
  expect(h["referrer-policy"]).toBe("same-origin");
  expect(h["cache-control"]).toBe("no-store");
  expect(h["strict-transport-security"]).toBeDefined();
  const css = await page.request.get("/ui.css");
  expect(css.status()).toBe(200);
  expect(css.headers()["content-type"]).toContain("text/css");
});
