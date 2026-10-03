/** Local-only browser acceptance run. No external account, database or credential. */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, mkdir, readFile, readdir, rm } from "node:fs/promises";
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
let learnerName = "Browser Learner";
const redirectUri = `${origin}/test/browser/callback`;
const observedErrors = [];
const telemetryRequests = [];
const failedResponses = [];
let worker, browser;
let currentPage;
let releaseHeldAck;
let screenshotCount = 0;
const devices = new WeakMap();
const keyTransports = new Map();

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

async function newPage(transport = "internal") {
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
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport,
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  devices.set(page, { cdp, authenticatorId });
  return page;
}

async function virtualCredentials(page) {
  const { cdp, authenticatorId } = devices.get(page);
  return (await cdp.send("WebAuthn.getCredentials", { authenticatorId })).credentials;
}

async function freshKeyLogin(credential, succeeds = true) {
  const page = await newPage(keyTransports.get(credential.credentialId) || "internal");
  const { cdp, authenticatorId } = devices.get(page);
  await cdp.send("WebAuthn.addCredential", { authenticatorId, credential });
  const verified = page.waitForResponse(response =>
    new URL(response.url()).pathname === "/auth/passkey/verify");
  await page.goto(`${origin}/auth/passkey?return_to=/`);
  const response = await verified;
  assert.equal(response.ok(), succeeds, succeeds ? "Stored Passkey signs in" : "Disabled/deleted Passkey cannot sign in");
  if (succeeds) {
    await page.waitForURL(url => url.pathname === "/");
    assert.equal((await (await page.request.get(`${origin}/api/me`)).json()).user.username, learnerName);
  }
  Object.assign(credential, (await virtualCredentials(page))[0]);
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
    ...(signup ? { screen_hint: "signup", login_hint: learnerName } : {}),
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
  assert.equal(userinfo.username, learnerName);
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
  for (const migration of (await readdir(path.join(workerRoot, "migrations"))).filter(name => name.endsWith(".sql")).sort()) {
    const schema = await readFile(path.join(workerRoot, "migrations", migration), "utf8");
    await db.batch(schema.replace(/--[^\n]*/g, "").split(";")
      .map(sql => sql.trim()).filter(Boolean).map(sql => db.prepare(sql)));
  }
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
  let admin = await newPage();
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
      await learner.locator("#username").fill(learnerName);
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
  // Existing account enrollment is independent of new-account registration.
  currentPage = admin;
  await admin.locator('[data-view="settings"]').click();
  const registrationClosed = admin.waitForResponse(response =>
    new URL(response.url()).pathname === "/api/management/settings/registration" && response.request().method() === "PATCH");
  await admin.locator('#registration-settings [name="mode"]').selectOption("closed");
  assert.equal((await registrationClosed).status(), 200);
  const target = await db.prepare("SELECT id,user_handle FROM users WHERE username=?").bind(learnerName).first();
  const originalKey = await db.prepare("SELECT * FROM credentials WHERE user_id=?").bind(target.id).first();
  const adminKey = await db.prepare("SELECT cr.id FROM credentials cr JOIN users u ON u.id=cr.user_id WHERE u.username=?").bind("Browser Administrator").first();
  await db.prepare("UPDATE sessions SET reauthenticated_at=0 WHERE user_id=?").bind(target.id).run();
  currentPage = learner;
  await learner.goto(origin);
  await learner.locator("#account-passkeys-button").click();
  await expect(learner.locator("#account-passkeys-add")).toBeEnabled();
  await expect(learner.locator("#account-passkeys-list li")).toHaveCount(1);
  await learner.locator("#account-passkeys-authenticator").selectOption("security-key");
  let firstDeviceKey, secondDeviceKey;
  const enrollmentStatuses = [];
  const reauthModes = [];
  learner.on("request", request => {
    if (new URL(request.url()).pathname === "/auth/passkey/options")
      reauthModes.push(request.postDataJSON()?.mode);
  });
  const optionsRoute = `${origin}/api/account/passkeys/options`;
  await learner.route(optionsRoute, async route => {
    const response = await route.fetch();
    enrollmentStatuses.push(response.status());
    if (response.ok()) {
      const data = await response.json();
      assert.equal(data.publicKey.user.id, target.user_handle);
      assert.equal(data.publicKey.user.displayName, learnerName);
      assert.equal(data.publicKey.authenticatorSelection.userVerification, "required");
      assert.deepEqual(data.publicKey.excludeCredentials.map(item => item.id), [originalKey.credential_id]);
      firstDeviceKey = (await virtualCredentials(learner))[0];
      keyTransports.set(firstDeviceKey.credentialId, "internal");
      assert.equal(data.publicKey.authenticatorSelection.authenticatorAttachment, "cross-platform", "Security-key choice requests an external authenticator");
      assert.deepEqual(data.publicKey.hints, ["security-key"]);
      const device = devices.get(learner);
      // Disconnect the first virtual device only after its real UV reauthentication.
      await device.cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: device.authenticatorId });
      const added = await device.cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
        protocol: "ctap2", transport: "usb", hasResidentKey: true,
        hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
      } });
      device.authenticatorId = added.authenticatorId;
    }
    await route.fulfill({ response });
  });
  const enrolled = learner.waitForResponse(response => new URL(response.url()).pathname === "/api/account/passkeys/verify");
  await learner.locator("#account-passkeys-add").click();
  const enrollmentResponse = await enrolled;
  assert.equal(enrollmentResponse.status(), 200);
  assert.equal(enrollmentResponse.request().postDataJSON().credential.authenticatorAttachment, "cross-platform");
  await expect(learner.locator("#account-passkeys-list li")).toHaveCount(2);
  await learner.unroute(optionsRoute);
  assert.deepEqual(enrollmentStatuses, [403, 200], "Expired UV is refreshed inline before enrollment");
  assert.deepEqual(reauthModes, ["reauth"]);
  assert.equal(new URL(learner.url()).pathname, "/", "Inline reauthentication keeps the original page");
  secondDeviceKey = (await virtualCredentials(learner))[0];
  keyTransports.set(secondDeviceKey.credentialId, "usb");
  const accountKeys = async page => {
    const response = await page.request.get(`${origin}/api/account/passkeys`);
    assert.equal(response.status(), 200);
    const data = await response.json();
    assert.equal(data.username, learnerName);
    return data.passkeys;
  };
  const keys = await accountKeys(learner);
  const secondKeyId = keys.find(key => key.id !== originalKey.id)?.id;
  assert.ok(secondKeyId);
  for (const [name, viewport] of [["desktop", { width: 1280, height: 900 }], ["mobile", { width: 390, height: 844 }]]) {
    await learner.setViewportSize(viewport);
    assert.equal(await learner.locator("#account-passkeys-dialog").evaluate(element => {
      const rect = element.getBoundingClientRect();
      return element.scrollWidth <= element.clientWidth && rect.left >= 0 && rect.right <= innerWidth;
    }), true, "Passkeys dialog fits its viewport");
    await capture(learner, `${name}-account-passkeys`);
  }
  await learner.evaluate(() => {
    const create = navigator.credentials.create.bind(navigator.credentials);
    navigator.credentials.create = async function (...args) {
      navigator.credentials.create = create;
      throw new DOMException("Cancelled by test user", "NotAllowedError");
    };
  });
  await learner.locator("#account-passkeys-add").click();
  await expect(learner.locator("#account-passkeys-status")).toHaveText("已取消");
  await expect(learner.locator("#account-passkeys-add")).toBeEnabled();
  assert.equal((await accountKeys(learner)).length, 2, "Cancelling enrollment adds no database credential");
  await learner.locator("#account-passkeys-close").click();
  await expect(learner.locator("#account-passkeys-dialog")).not.toBeVisible();
  await expect(learner.locator("#logo-button .logo")).toBeVisible();
  assert.equal(await learner.locator("#logo-button").evaluate(element => Number(getComputedStyle(element).opacity) > 0.8), true);
  await capture(learner, "mobile-home-after-passkeys-close");
  const secondSession = await freshKeyLogin(secondDeviceKey);
  assert.deepEqual((await accountKeys(secondSession)).map(key => key.id), keys.map(key => key.id));
  const sameIdentity = await oauthSignIn(secondSession, false);
  assert.equal(sameIdentity.sub, firstIdentity.sub, "Second device preserves the OAuth identity");
  Object.assign(secondDeviceKey, (await virtualCredentials(secondSession))[0]);

  currentPage = admin;
  await admin.goto(`${origin}/management`);
  await expect(admin.locator("#account-passkeys-button")).toBeVisible();
  await db.prepare("UPDATE sessions SET reauthenticated_at=0 WHERE user_id=(SELECT id FROM users WHERE username=?)").bind("Browser Administrator").run();
  await admin.locator("#account-passkeys-button").click();
  await expect(admin.locator("#account-passkeys-list li")).toHaveCount(1);
  await expect(admin.locator("#account-passkeys-add")).toBeEnabled();
  await admin.evaluate(() => {
    const create = navigator.credentials.create.bind(navigator.credentials);
    navigator.credentials.create = async function () {
      navigator.credentials.create = create;
      throw new DOMException("Cancelled by test user", "NotAllowedError");
    };
  });
  const adminReauthenticated = admin.waitForResponse(response => new URL(response.url()).pathname === "/auth/passkey/verify");
  await admin.locator("#account-passkeys-add").click();
  assert.equal((await adminReauthenticated).status(), 200);
  await expect(admin.locator("#account-passkeys-status")).toHaveText("已取消");
  await expect(admin.locator("#account-passkeys-list li")).toHaveCount(1);
  assert.equal(new URL(admin.url()).pathname, "/management", "Management reauthentication stays inline");
  for (const [name, viewport] of [["desktop", { width: 1280, height: 900 }], ["mobile", { width: 390, height: 844 }]]) {
    await admin.setViewportSize(viewport);
    assert.equal(await admin.locator("#account-passkeys-dialog").evaluate(element => {
      const rect = element.getBoundingClientRect();
      return element.scrollWidth <= element.clientWidth && rect.left >= 0 && rect.right <= innerWidth;
    }), true, "Management Passkeys dialog fits its viewport");
    await capture(admin, `${name}-management-account-passkeys`);
  }
  await admin.locator("#account-passkeys-close").click();
  await admin.locator('[data-view="users"]').click();
  async function manageSecondKey(action) {
    currentPage = admin;
    await admin.locator(`[data-edit-user="${target.id}"]`).click();
    const endpoint = `/api/management/users/${target.id}/credentials/${secondKeyId}`;
    const response = admin.waitForResponse(response => new URL(response.url()).pathname === endpoint && response.request().method() === (action === "delete" ? "DELETE" : "PATCH"));
    if (action === "delete") admin.once("dialog", dialog => dialog.accept());
    const button = admin.locator(action === "delete" ? `[data-delete-credential="${secondKeyId}"]` : `[data-toggle-credential="${secondKeyId}"]`);
    if (action !== "delete") await expect(button).toHaveAttribute("data-next-disabled", String(action === "disable"));
    await button.click();
    if (releaseHeldAck) {
      // Real user intent arrives while an earlier signed ACK is still in flight.
      await new Promise(resolve => setTimeout(resolve, 75));
      const release = releaseHeldAck;
      releaseHeldAck = null;
      release();
    }
    assert.equal((await response).status(), 200, `Administrator can ${action} the selected credential`);
    await expect(admin.locator("#editor-dialog")).not.toBeVisible();
    assert.equal((await db.prepare("SELECT disabled_at FROM credentials WHERE id=?").bind(originalKey.id).first()).disabled_at, null);
    assert.ok(await db.prepare("SELECT id FROM credentials WHERE id=?").bind(adminKey.id).first(), "Administrator's own credential remains unchanged");
  }
  await manageSecondKey("disable");
  await freshKeyLogin(secondDeviceKey, false);
  await freshKeyLogin(firstDeviceKey);
  await manageSecondKey("enable");
  await freshKeyLogin(secondDeviceKey);

  // Match the remote path: a recovery-created administrator, a page reload,
  // and its first signed mutation without a prior inline reauthentication.
  const freshGrant = randomBytes(32).toString("base64url");
  const freshTime = Math.floor(Date.now() / 1000);
  await db.prepare("INSERT INTO admin_recovery_tokens(token_hash,created_at,expires_at) VALUES(?,?,?)").bind(hash(freshGrant), freshTime, freshTime + 600).run();
  learnerName = "native-passkeys-local-acceptance-01234567-member";
  await db.prepare("UPDATE users SET admin=1,username=? WHERE id=?").bind(learnerName, target.id).run();
  admin = await newPage();
  await admin.goto(`${origin}/${freshGrant}`);
  await admin.locator("#recovery-username").fill("native-passkeys-local-acceptance-01234567-admin");
  await admin.locator("#recovery-form button").click();
  await admin.waitForURL(url => url.pathname === "/management");
  await expect(admin.locator("#overview-summary .metric-card").first()).toBeVisible();
  let delayedAck, ackHeld;
  let ackDelivered = false, writeBeforeAck = false;
  if (process.env.PASSKEY_BROWSER_DELAY_CHANNEL === "1") {
    let acknowledgeHeld;
    ackHeld = new Promise(resolve => { acknowledgeHeld = resolve; });
    let heldOnce = false;
    await admin.route(`${origin}/api/management/channel/events**`, async route => {
      try {
        const response = await route.fetch();
        await new Promise(resolve => setTimeout(resolve, 600));
        await route.fulfill({ response });
      } catch { /* A previous document may close during the explicit reload. */ }
    });
    await admin.route(`${origin}/api/management/channel/ack`, async route => {
      const response = await route.fetch();
      if (!heldOnce) {
        heldOnce = true;
        const release = new Promise(resolve => { releaseHeldAck = resolve; });
        acknowledgeHeld();
        await release;
        ackDelivered = true;
      }
      await route.fulfill({ response });
    });
    admin.on("request", request => {
      if (new URL(request.url()).pathname.includes("/credentials/") && !ackDelivered) writeBeforeAck = true;
    });
    delayedAck = admin.waitForResponse(response => new URL(response.url()).pathname === "/api/management/channel/ack");
    void delayedAck.catch(() => {});
  }
  await admin.goto(`${origin}/management`);
  if (ackHeld) await ackHeld;
  await admin.locator("#account-passkeys-button").click();
  await expect(admin.locator("#account-passkeys-list li")).toHaveCount(1);
  await admin.setViewportSize({ width: 390, height: 844 });
  await admin.locator("#account-passkeys-close").click();
  await admin.locator('[data-view="users"]').click();
  await manageSecondKey("disable");
  if (delayedAck) {
    const response = await delayedAck;
    const data = await response.json();
    const reasons = ["channel_signature_invalid", "channel_replay", "channel_proof_missing", "channel_missing"];
    console.log("Delayed channel diagnostic:", { status: response.status(), reason: reasons.includes(data.reason) ? data.reason : "other-or-none", writeBeforeAck });
    assert.equal(response.status(), 200, "Delayed SSE must not invalidate the first management acknowledgement");
    assert.equal(writeBeforeAck, false, "A management write must wait for the earlier signed ACK response");
  }
  await freshKeyLogin(secondDeviceKey, false);
  await freshKeyLogin(firstDeviceKey);
  await manageSecondKey("enable");
  await freshKeyLogin(secondDeviceKey);
  await manageSecondKey("delete");
  await freshKeyLogin(secondDeviceKey, false);
  await freshKeyLogin(firstDeviceKey);
  assert.equal((await db.prepare("SELECT COUNT(*) n FROM credentials WHERE user_id=?").bind(target.id).first()).n, 1);
  assert.equal((await db.prepare("SELECT setting_value FROM app_settings WHERE setting_key='registration_mode'").first()).setting_value, "closed");
  assert.deepEqual(
    telemetryRequests,
    [],
    "Disabled telemetry creates no browser work",
  );
  assert.deepEqual(failedResponses.filter(response => response.status >= 500), [], "No server failures during browser acceptance");
  assert.deepEqual(
    observedErrors,
    [],
    "No uncaught application JavaScript errors",
  );
  console.log(
    `Browser acceptance passed: original UI, ${screenshotCount} screenshots, recovery, management autosave/CSV, home registration, OAuth PKCE/userinfo, existing-user signup, two-device Passkeys and per-key administration.`,
  );
} catch (error) {
  if (currentPage)
    console.error("Browser failure context:", {
      path: new URL(currentPage.url()).pathname.replace(
        /\/[\w-]{32,}/g,
        "/[redacted]",
      ),
      messages: await currentPage.locator("output").allTextContents().catch(() => []),
      failedResponses,
    });
  throw error;
} finally {
  releaseHeldAck?.();
  await browser?.close();
  await worker?.dispose();
  // Removes all synthetic users, credentials, cookies and test database state.
  await rm(temporary, { recursive: true, force: true });
}
