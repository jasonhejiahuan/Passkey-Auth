/** Local-only browser acceptance run. No external account, database or credential. */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { chromium, expect } from "@playwright/test";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

const workerRoot = fileURLToPath(new URL("../..", import.meta.url));
const temporary = await mkdtemp(path.join(tmpdir(), "passkey-native-browser-"));
const screenshotRoot =
  process.env.PASSKEY_BROWSER_ARTIFACTS || path.join(temporary, "screenshots");
await mkdir(screenshotRoot, { recursive: true });
const server = createServer();
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const port = server.address().port;
await new Promise((resolve) => server.close(resolve));
const origin = `http://localhost:${port}`;
const hash = (value) => createHash("sha256").update(value).digest("base64url");
const recoveryToken = randomBytes(32).toString("base64url");
const clientSecret = randomBytes(32).toString("base64url");
const clientId = "browser-acceptance-client";
const redirectUri = `${origin}/test/browser/callback`;
const observedErrors = [];
const telemetryRequests = [];
const failedResponses = [];
let worker, browser;
let currentPage;
let screenshotCount = 0;

async function capture(page, name) {
  await page
    .locator("img")
    .evaluateAll((images) =>
      Promise.all(images.map((image) => image.decode().catch(() => {}))),
    );
  await page.screenshot({
    path: path.join(screenshotRoot, `${name}.png`),
    fullPage: true,
    animations: "disabled",
  });
  screenshotCount++;
  assert.equal(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
    true,
    `${name}: horizontal overflow`,
  );
}

async function newPage() {
  const context = await browser.newContext({
    viewport: { width: 1280, height: 900 },
    colorScheme: "light",
  });
  const page = await context.newPage();
  currentPage = page;
  page.on("pageerror", (error) => observedErrors.push(error.name));
  page.on("request", (request) => {
    const pathname = new URL(request.url()).pathname;
    if (
      pathname.startsWith("/api/telemetry/") ||
      pathname === "/static/telemetry.js"
    )
      telemetryRequests.push(pathname);
  });
  page.on("response", (response) => {
    if (response.status() >= 400)
      failedResponses.push({
        path: new URL(response.url()).pathname.replace(
          /\/[\w-]{32,}/g,
          "/[redacted]",
        ),
        status: response.status(),
      });
  });
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return page;
}

async function oauthSignIn(page, signup) {
  const verifier = randomBytes(32).toString("base64url");
  const state = randomBytes(24).toString("base64url");
  let callback;
  await page.route(`${redirectUri}**`, async (route) => {
    callback = new URL(route.request().url());
    await route.fulfill({
      contentType: "text/html",
      body: "<main>OAuth callback received</main>",
    });
  });
  const query = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    code_challenge: hash(verifier),
    code_challenge_method: "S256",
    ...(signup ? { screen_hint: "signup", login_hint: "Browser Learner" } : {}),
  });
  await page.goto(`${origin}/oauth/authorize?${query}`);
  await page.waitForURL((url) => url.pathname === "/test/browser/callback");
  assert.equal(
    callback?.searchParams.get("state"),
    state,
    "OAuth state must round trip",
  );
  assert.equal(callback.searchParams.has("error"), false, "OAuth must succeed");
  const tokenResponse = await page.request.post(`${origin}/oauth/token`, {
    form: {
      grant_type: "authorization_code",
      client_id: clientId,
      client_secret: clientSecret,
      code: callback.searchParams.get("code"),
      redirect_uri: redirectUri,
      code_verifier: verifier,
    },
  });
  assert.equal(tokenResponse.status(), 200, "Server-side PKCE token exchange");
  const token = await tokenResponse.json();
  const userinfoResponse = await page.request.get(`${origin}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${token.access_token}` },
  });
  assert.equal(userinfoResponse.status(), 200, "Authenticated userinfo");
  const userinfo = await userinfoResponse.json();
  assert.equal(userinfo.username, "Browser Learner");
  assert.equal(typeof userinfo.sub, "string");
  await page.unroute(`${redirectUri}**`);
  return userinfo;
}

try {
  const bundle = await build({
    entryPoints: [path.join(workerRoot, "src/index.ts")],
    bundle: true,
    write: false,
    format: "esm",
    platform: "browser",
    external: ["cloudflare:workers", "node:*"],
  });
  const assetsRoot = path.join(workerRoot, "public");
  worker = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: bundle.outputFiles[0].text,
      compatibilityDate: "2026-10-01",
      compatibilityFlags: ["nodejs_compat"],
      host: "127.0.0.1",
      port,
      d1Databases: ["DB"],
      d1Persist: path.join(temporary, "d1"),
      bindings: {
        PASSKEY_ORIGIN: origin,
        PASSKEY_RP_ID: "localhost",
        PASSKEY_RP_NAME: "JSTU Passkey",
      },
      serviceBindings: {
        ASSETS: async (request) => {
          const pathname = new URL(request.url).pathname;
          const assetPath = path.resolve(assetsRoot, `.${pathname}`);
          if (!assetPath.startsWith(`${assetsRoot}${path.sep}`))
            return new Response(null, { status: 404 });
          try {
            const mime = pathname.endsWith(".css")
              ? "text/css"
              : pathname.endsWith(".js")
                ? "application/javascript"
                : pathname.endsWith(".png")
                  ? "image/png"
                  : "application/octet-stream";
            return new Response(await readFile(assetPath), {
              headers: { "Content-Type": mime },
            });
          } catch {
            return new Response(null, { status: 404 });
          }
        },
      },
    }),
  );
  await worker.ready;
  const db = await worker.getD1Database("DB");
  const schema = await readFile(
    path.join(workerRoot, "migrations/0001_native_auth.sql"),
    "utf8",
  );
  await db.batch(
    schema
      .replace(/--[^\n]*/g, "")
      .split(";")
      .map((sql) => sql.trim())
      .filter(Boolean)
      .map((sql) => db.prepare(sql)),
  );
  const now = Math.floor(Date.now() / 1000);
  await db.batch([
    db
      .prepare(
        "INSERT INTO admin_recovery_tokens(token_hash,created_at,expires_at) VALUES(?,?,?)",
      )
      .bind(hash(recoveryToken), now, now + 600),
    db
      .prepare(
        "INSERT INTO app_settings(setting_key,setting_value,updated_at) VALUES(?,?,?)",
      )
      .bind("registration_mode", "closed", now),
    db
      .prepare(
        "INSERT INTO oauth_clients(client_id,name,secret_hash,redirect_uris,enabled,is_demo,created_at,updated_at) VALUES(?,?,?,?,1,0,?,?)",
      )
      .bind(
        clientId,
        "Browser acceptance",
        hash(clientSecret),
        JSON.stringify([redirectUri]),
        now,
        now,
      ),
    db
      .prepare(
        "INSERT INTO oauth_clients(client_id,name,secret_hash,redirect_uris,enabled,is_demo,created_at,updated_at) VALUES(?,?,?,?,1,1,?,?)",
      )
      .bind(
        "browser-demo-client",
        "Browser demo",
        hash(randomBytes(32).toString("base64url")),
        JSON.stringify(
          ["oauth", "third-party", "link-login"].map(
            (name) => `${origin}/demo/${name}/callback`,
          ),
        ),
        now,
        now,
      ),
  ]);
  browser = await chromium.launch({ channel: "chrome", headless: true });
  const admin = await newPage();
  await admin.goto(origin);
  await expect(admin.locator("#logo-button")).toBeVisible();
  await capture(admin, "desktop-home");
  assert.equal(
    (await admin.request.get(`${origin}/api/ui/register-client.js`)).status(),
    403,
    "Registration is closed by default",
  );
  await admin.setViewportSize({ width: 390, height: 844 });
  await capture(admin, "mobile-home");
  await admin.goto(`${origin}/${recoveryToken}`);
  await capture(admin, "mobile-recovery");
  await admin.locator("#recovery-username").fill("Browser Administrator");
  const recoveryOptions = admin.waitForResponse((response) =>
    new URL(response.url()).pathname.endsWith("/options"),
  );
  await admin.locator("#recovery-form button").click();
  assert.equal(
    (await (await recoveryOptions).json()).publicKey.authenticatorSelection
      .userVerification,
    "required",
    "Administrator recovery requires verified user presence",
  );
  await admin.waitForURL((url) => url.pathname === "/management");
  await expect(
    admin.locator("#overview-summary .metric-card").first(),
  ).toBeVisible();
  for (const [name, viewport] of [
    ["desktop", { width: 1280, height: 900 }],
    ["mobile", { width: 390, height: 844 }],
  ]) {
    await admin.setViewportSize(viewport);
    for (const view of [
      "overview",
      "users",
      "platforms",
      "login-history",
      "audit-logs",
      "telemetry",
      "settings",
      "passkey-settings",
    ]) {
      await admin.locator(`[data-view="${view}"]`).click();
      await expect(admin.locator(`#${view}-view`)).toBeVisible();
      await capture(admin, `${name}-management-${view}`);
    }
    await admin.emulateMedia({ colorScheme: "dark" });
    await admin.locator('[data-view="overview"]').click();
    await capture(admin, `${name}-management-dark`);
    await admin.emulateMedia({ colorScheme: "light" });
  }
  await admin.locator('[data-view="settings"]').click();
  const changed = admin.waitForResponse(
    (response) =>
      new URL(response.url()).pathname ===
        "/api/management/settings/registration" &&
      response.request().method() === "PATCH",
  );
  await admin
    .locator('#registration-settings [name="mode"]')
    .selectOption("open");
  assert.equal(
    (await changed).status(),
    200,
    "Original autosave works with rotating management authorization",
  );
  await expect
    .poll(
      async () =>
        (
          await db
            .prepare(
              "SELECT setting_value FROM app_settings WHERE setting_key='registration_mode'",
            )
            .first()
        ).setting_value,
    )
    .toBe("open");
  const csv = await admin.request.get(
    `${origin}/api/management/export/users.csv`,
  );
  assert.equal(csv.status(), 200);
  assert.match(csv.headers()["content-type"], /text\/csv/);

  const learner = await newPage();
  await learner.goto(origin);
  assert.equal(
    (await learner.request.get(`${origin}/api/ui/register-client.js`)).status(),
    403,
    "Open registration still requires an intent unlock",
  );
  await learner.keyboard.press("Alt+r");
  await expect(learner.locator("#username")).toBeVisible();
  await capture(learner, "desktop-register");
  await learner.setViewportSize({ width: 390, height: 844 });
  await capture(learner, "mobile-register");
  await learner.keyboard.press("Escape");
  const firstIdentity = await oauthSignIn(learner, true);
  const secondIdentity = await oauthSignIn(learner, false);
  assert.equal(
    firstIdentity.sub,
    secondIdentity.sub,
    "OAuth user identity is stable",
  );
  let unexpectedRegistration = false;
  const countRegistration = (request) => {
    if (new URL(request.url()).pathname === "/api/register/options")
      unexpectedRegistration = true;
  };
  learner.on("request", countRegistration);
  const reusedIdentity = await oauthSignIn(learner, true);
  learner.off("request", countRegistration);
  assert.equal(
    reusedIdentity.sub,
    firstIdentity.sub,
    "Existing signup uses the original identity",
  );
  assert.equal(
    unexpectedRegistration,
    false,
    "Existing signup performs fresh login instead of creating a credential",
  );
  for (const [demo, title] of [
    ["oauth", "登录成功"],
    ["third-party", "已跳回第三方网页"],
    ["link-login", "原网站登录成功"],
  ]) {
    await learner.goto(`${origin}/demo/${demo}`);
    await capture(learner, `mobile-demo-${demo}`);
    if (demo === "link-login") {
      await learner.locator("#username").fill("Browser Learner");
      const started = learner.waitForResponse(
        (response) =>
          new URL(response.url()).pathname === "/demo/link-login/start",
      );
      await learner.locator(".login-form button").click();
      const startResponse = await started;
      assert.equal(
        startResponse.status(),
        302,
        `Link form must redirect; request origin=${startResponse.request().headers().origin || "(absent)"}, site=${startResponse.request().headers()["sec-fetch-site"] || "(absent)"}`,
      );
    } else {
      await learner.locator(".primary-link").click();
    }
    await learner.waitForURL(
      (url) => url.pathname === `/demo/${demo}/callback`,
    );
    await expect(learner.locator("#title")).toHaveText(title);
    const callback = new URL(learner.url());
    const visible = await learner.locator("body").textContent();
    for (const field of ["code", "challenge_result"]) {
      const value = callback.searchParams.get(field);
      if (value)
        assert.equal(
          visible.includes(value),
          false,
          "Demo debug data must redact secrets",
        );
    }
    await capture(learner, `mobile-demo-${demo}-success`);
  }
  const denied = await learner.goto(`${origin}/management`);
  assert.equal(denied.status(), 403, "Ordinary users cannot enter management");

  const homeUser = await newPage();
  await homeUser.goto(origin);
  await homeUser.keyboard.press("Alt+r");
  await homeUser.locator("#username").fill("Browser Home Learner");
  await homeUser.locator("#passkey-form .primary").click();
  await expect
    .poll(
      async () =>
        (await (await homeUser.request.get(`${origin}/api/me`)).json())
          .authenticated,
    )
    .toBe(true);
  await homeUser.reload();
  assert.equal(
    (await (await homeUser.request.get(`${origin}/api/me`)).json()).user
      .username,
    "Browser Home Learner",
  );
  await homeUser.locator("#logo-button").click({ clickCount: 5, delay: 40 });
  await expect
    .poll(
      async () =>
        (await (await homeUser.request.get(`${origin}/api/me`)).json())
          .authenticated,
    )
    .toBe(false);
  let assertionOptions = 0;
  homeUser.on("request", (request) => {
    if (new URL(request.url()).pathname === "/auth/passkey/options")
      assertionOptions++;
  });
  await homeUser.locator("#logo-button").click({ clickCount: 5, delay: 40 });
  await expect
    .poll(
      async () =>
        (await (await homeUser.request.get(`${origin}/api/me`)).json())
          .authenticated,
    )
    .toBe(true);
  assert.equal(
    new URL(homeUser.url()).pathname,
    "/",
    "Home logo login stays on the original page",
  );
  assert.equal(
    assertionOptions,
    1,
    "Logo login starts only one WebAuthn ceremony",
  );
  assert.deepEqual(
    telemetryRequests,
    [],
    "Disabled telemetry creates no browser work",
  );
  assert.deepEqual(
    observedErrors,
    [],
    "No uncaught application JavaScript errors",
  );
  console.log(
    `Browser acceptance passed: original UI, ${screenshotCount} screenshots, recovery, management autosave/CSV, home registration, OAuth PKCE/userinfo and existing-user signup.`,
  );
} catch (error) {
  if (currentPage)
    console.error("Browser failure context:", {
      path: new URL(currentPage.url()).pathname.replace(
        /\/[\w-]{32,}/g,
        "/[redacted]",
      ),
      messages: await currentPage.locator("output").allTextContents(),
      failedResponses,
    });
  throw error;
} finally {
  await browser?.close();
  await worker?.dispose();
  // Removes all synthetic users, credentials, cookies and test database state.
  await rm(temporary, { recursive: true, force: true });
}
