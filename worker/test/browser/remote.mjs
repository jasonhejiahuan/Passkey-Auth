/** Explicit operator-run beta verification. Secrets are read only from protected files. */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, stat, writeFile, rename } from "node:fs/promises";
import path from "node:path";
import { chromium, expect } from "@playwright/test";
import { scopedResolver } from "./resolver.mjs";

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
};
const hash = (value) => createHash("sha256").update(value).digest("base64url");
async function protectedJSON(filename) {
  const info = await stat(filename);
  if (!info.isFile() || (info.mode & 0o077) !== 0)
    throw new Error("Credential files must be private regular files");
  return JSON.parse(await readFile(filename, "utf8"));
}

let browser;
let resolver;
let manifest;
let manifestPath;
let manifestCreated = false;
let stage = "configuration";
const contexts = [];

async function checkpoint(nextStage) {
  stage = nextStage;
  manifest.lastStage = nextStage;
  const temporary = `${manifestPath}.next`;
  await writeFile(temporary, JSON.stringify(manifest, null, 2) + "\n", {
    mode: 0o600,
  });
  await rename(temporary, manifestPath);
}

try {
  const origin = new URL(required("PASSKEY_REMOTE_ORIGIN")).origin;
  assert.equal(
    new URL(origin).protocol,
    "https:",
    "Use an explicitly deployed HTTPS beta",
  );
  const recovery = await protectedJSON(
    required("PASSKEY_REMOTE_RECOVERY_FILE"),
  );
  const client = await protectedJSON(required("PASSKEY_REMOTE_CLIENT_FILE"));
  const recoveryURL = new URL(recovery.url || `/${recovery.token}`, origin);
  assert.equal(
    recoveryURL.origin,
    origin,
    "Recovery belongs to the selected beta",
  );
  assert.match(recoveryURL.pathname, /^\/[A-Za-z0-9_-]{32,128}$/);
  const recoveryToken = recoveryURL.pathname.slice(1);
  const redirectUri = client.redirectUri || client.redirectUris?.[0];
  const callbackURL = new URL(redirectUri);
  assert.equal(
    callbackURL.origin,
    origin,
    "Use a dedicated callback on this beta",
  );
  assert.equal(
    callbackURL.pathname,
    "/test/browser/callback",
    "The test must not visit another application",
  );
  assert.equal(callbackURL.search + callbackURL.hash, "");
  assert.ok(
    client.clientId && client.clientSecret,
    "A dedicated confidential test client is required",
  );

  resolver = await scopedResolver(
    origin,
    process.env.PASSKEY_REMOTE_RESOLVER || "system",
  );

  manifestPath = path.resolve(required("PASSKEY_REMOTE_MANIFEST"));
  await mkdir(path.dirname(manifestPath), { recursive: true, mode: 0o700 });
  const prefix = `native-browser-${Date.now().toString(36)}-${randomBytes(4).toString("hex")}`;
  manifest = {
    schema: 1,
    runId: prefix,
    startedAt: new Date().toISOString(),
    cleanupPending: true,
    completed: false,
    lastStage: stage,
    resolver: resolver.name,
    testClientId: client.clientId,
    recoveryTokenHash: hash(recoveryToken),
    users: [],
    sessionHashes: [],
    failures: [],
  };
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n", {
    mode: 0o600,
    flag: "wx",
  });
  manifestCreated = true;
  browser = await chromium.launch({
    channel: "chrome",
    headless: true,
    args: resolver.chromeArgs,
  });
  const jsErrors = [];
  const telemetryRequests = [];

  async function pageFor() {
    const context = await browser.newContext({
      viewport: { width: 1280, height: 900 },
      colorScheme: "light",
    });
    contexts.push(context);
    const page = await context.newPage();
    page.setDefaultTimeout(30_000);
    page.setDefaultNavigationTimeout(45_000);
    page.on("pageerror", (error) => jsErrors.push(error.name));
    page.on("request", (request) => {
      const pathname = new URL(request.url()).pathname;
      if (
        pathname.startsWith("/api/telemetry/") ||
        pathname === "/static/telemetry.js"
      )
        telemetryRequests.push(pathname);
    });
    page.on("response", (response) => {
      if (response.status() >= 500)
        manifest.failures.push({
          stage,
          status: response.status(),
          kind: "server-response",
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

  async function rememberSessions() {
    for (const context of contexts) {
      for (const cookie of await context.cookies(origin)) {
        if (cookie.name === "session") {
          const value = hash(cookie.value);
          if (!manifest.sessionHashes.includes(value))
            manifest.sessionHashes.push(value);
        }
      }
    }
    await checkpoint(stage);
  }

  await checkpoint("public-home");
  const admin = await pageFor();
  const home = await admin.goto(origin);
  assert.equal(home.status(), 200);
  await expect(admin.locator("#logo-button")).toBeVisible();
  assert.equal(
    await admin.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
    true,
  );
  await rememberSessions();

  const adminName = `${prefix}-admin`;
  manifest.users.push({
    username: adminName,
    purpose: "recovery-administrator",
    status: "pending",
  });
  await checkpoint("administrator-recovery");
  await admin.goto(recoveryURL.toString());
  await admin.locator("#recovery-username").fill(adminName);
  const options = admin.waitForResponse((response) =>
    new URL(response.url()).pathname.endsWith("/options"),
  );
  await admin.locator("#recovery-form button").click();
  assert.equal(
    (await (await options).json()).publicKey.authenticatorSelection
      .userVerification,
    "required",
  );
  await admin.waitForURL((url) => url.pathname === "/management");
  await expect(
    admin.locator("#overview-summary .metric-card").first(),
  ).toBeVisible();
  const overviewResponse = await admin.request.get(
    `${origin}/api/management/overview`,
  );
  assert.equal(overviewResponse.status(), 200);
  const administrator = (await overviewResponse.json()).users.find(
    (user) => user.username === adminName,
  );
  assert.ok(administrator);
  Object.assign(manifest.users[0], {
    id: administrator.id,
    sub: administrator.sub,
    status: "created",
  });
  await rememberSessions();
  await checkpoint("management-ui");
  for (const viewport of [
    { width: 1280, height: 900 },
    { width: 390, height: 844 },
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
      assert.equal(
        await admin.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
        true,
      );
    }
  }
  const exported = await admin.request.get(
    `${origin}/api/management/export/users.csv`,
  );
  assert.equal(exported.status(), 200);
  assert.match(exported.headers()["content-type"], /text\/csv/);

  const learner = await pageFor();
  const learnerName = `${prefix}-learner`;
  await checkpoint("registration-preflight");
  await learner.goto(origin);
  assert.equal(
    (await learner.request.get(`${origin}/api/ui/register-client.js`)).status(),
    403,
  );
  await learner.keyboard.press("Alt+r");
  await expect(learner.locator("#username")).toBeVisible();
  await learner.keyboard.press("Escape");
  manifest.users.push({
    username: learnerName,
    purpose: "oauth-learner",
    status: "pending",
  });
  await rememberSessions();

  async function oauthFlow(signup, label) {
    await checkpoint(label);
    const verifier = randomBytes(32).toString("base64url");
    const state = randomBytes(24).toString("base64url");
    let callback;
    await learner.route(`${redirectUri}**`, async (route) => {
      callback = new URL(route.request().url());
      await route.fulfill({
        contentType: "text/html",
        body: "<main>Verification callback received</main>",
      });
    });
    const query = new URLSearchParams({
      response_type: "code",
      client_id: client.clientId,
      redirect_uri: redirectUri,
      state,
      code_challenge: hash(verifier),
      code_challenge_method: "S256",
      ...(signup ? { screen_hint: "signup", login_hint: learnerName } : {}),
    });
    await learner.goto(`${origin}/oauth/authorize?${query}`);
    await learner.waitForURL((url) => url.pathname === callbackURL.pathname);
    assert.equal(callback.searchParams.get("state"), state);
    assert.equal(callback.searchParams.has("error"), false);
    const exchanged = await learner.request.post(`${origin}/oauth/token`, {
      form: {
        grant_type: "authorization_code",
        client_id: client.clientId,
        client_secret: client.clientSecret,
        code: callback.searchParams.get("code"),
        redirect_uri: redirectUri,
        code_verifier: verifier,
      },
    });
    assert.equal(exchanged.status(), 200);
    const token = await exchanged.json();
    const checked = await learner.request.get(`${origin}/oauth/userinfo`, {
      headers: { Authorization: `Bearer ${token.access_token}` },
    });
    assert.equal(checked.status(), 200);
    const identity = await checked.json();
    assert.equal(identity.username, learnerName);
    Object.assign(manifest.users[1], {
      id: identity.id,
      sub: identity.sub,
      status: "created",
    });
    await learner.unroute(`${redirectUri}**`);
    await rememberSessions();
    return identity;
  }

  const created = await oauthFlow(true, "oauth-signup");
  const loggedIn = await oauthFlow(false, "oauth-login");
  const reused = await oauthFlow(true, "oauth-existing-signup");
  assert.equal(created.sub, loggedIn.sub);
  assert.equal(created.sub, reused.sub);
  await checkpoint("authorization-boundary");
  assert.equal((await learner.goto(`${origin}/management`)).status(), 403);
  assert.deepEqual(jsErrors, []);
  assert.deepEqual(
    telemetryRequests,
    [],
    "This acceptance run expects telemetry disabled",
  );
  assert.deepEqual(manifest.failures, []);
  manifest.completed = true;
  manifest.completedAt = new Date().toISOString();
  await checkpoint("complete-awaiting-operator-cleanup");
  console.log(
    "Remote browser acceptance passed. Exact test identities are recorded in the private cleanup manifest.",
  );
} catch (error) {
  if (manifestCreated) {
    manifest.failures.push({ stage, kind: error.name || "Error" });
    await checkpoint(stage);
  }
  // Browser exceptions can embed authorization URLs. Never print their messages or stacks.
  console.error(
    `Remote browser acceptance failed at stage: ${stage}. ${manifestCreated ? "See the private cleanup manifest." : "No remote test writes were started."}`,
  );
  process.exitCode = 1;
} finally {
  try {
    if (manifestCreated && browser) {
      for (const context of contexts) {
        for (const cookie of await context.cookies()) {
          if (cookie.name === "session") {
            const value = hash(cookie.value);
            if (!manifest.sessionHashes.includes(value))
              manifest.sessionHashes.push(value);
          }
        }
      }
      await checkpoint(stage);
    }
  } finally {
    try {
      await browser?.close();
    } finally {
      resolver?.restore();
    }
  }
}
