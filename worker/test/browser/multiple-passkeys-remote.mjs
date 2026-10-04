/** Explicit operator-run multi-device acceptance. Never changes registration settings. */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { lstat, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { chromium, expect } from "@playwright/test";
import { scopedResolver } from "./resolver.mjs";

const hash = value => createHash("sha256").update(value).digest("base64url");
const required = name => {
  if (!process.env[name]) throw new Error(`Missing ${name}`);
  return process.env[name];
};
const devices = new WeakMap();
const keyTransports = new Map();
const safeReasons = new Set(["channel_missing", "channel_counter_invalid", "channel_replay", "channel_proof_missing", "channel_signature_invalid", "action_token_missing", "action_token_mismatch", "channel_stale", "authorization_changed"]);
const contexts = [];
const pendingHeaders = [];
let browser, resolver, manifest, manifestPath;
let manifestCreated = false;
let stage = "configuration";

async function checkpoint(nextStage) {
  stage = nextStage;
  manifest.lastStage = stage;
  const temporary = `${manifestPath}.${randomBytes(8).toString("hex")}.next`;
  await writeFile(temporary, JSON.stringify(manifest, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  await rename(temporary, manifestPath);
}

try {
  const origin = new URL(required("PASSKEY_REMOTE_ORIGIN")).origin;
  assert.equal(new URL(origin).protocol, "https:");
  const grantPath = required("PASSKEY_REMOTE_RECOVERY_FILE");
  const grantFile = await lstat(grantPath);
  assert.ok(grantFile.isFile() && (grantFile.mode & 0o077) === 0, "Use a private regular grant file");
  const config = JSON.parse(await readFile(grantPath, "utf8"));
  assert.equal(config.grants?.length, 2, "Supply two independent operator-created test grants");
  const grants = config.grants.map(grant => {
    const url = new URL(grant.url);
    assert.equal(url.origin, origin);
    assert.match(url.pathname, /^\/[A-Za-z0-9_-]{32,128}$/);
    assert.equal(url.search + url.hash, "");
    return url;
  });
  assert.notEqual(grants[0].pathname, grants[1].pathname);
  resolver = await scopedResolver(origin, process.env.PASSKEY_REMOTE_RESOLVER || "system");
  manifestPath = path.resolve(required("PASSKEY_REMOTE_MANIFEST"));
  await mkdir(path.dirname(manifestPath), { recursive: true, mode: 0o700 });
  const prefix = `native-passkeys-${Date.now().toString(36)}-${randomBytes(4).toString("hex")}`;
  manifest = {
    schema: 1, runId: prefix, startedAt: new Date().toISOString(), resolver: resolver.name,
    cleanupPending: true, completed: false, lastStage: stage,
    recoveryTokenHashes: grants.map(url => hash(url.pathname.slice(1))),
    users: [], sessionHashes: [], credentialActions: [], failures: [], responses: [], uiChecks: [],
  };
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  manifestCreated = true;
  browser = await chromium.launch({ channel: "chrome", headless: true, args: resolver.chromeArgs });
  const jsErrors = [], telemetryRequests = [];

  function rememberCookie(header = "") {
    const value = header.split(";").map(item => item.trim()).find(item => item.startsWith("session="))?.slice(8);
    if (value) {
      const digest = hash(value);
      if (!manifest.sessionHashes.includes(digest)) manifest.sessionHashes.push(digest);
    }
  }
  async function pageFor(credential) {
    const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, colorScheme: "light" });
    contexts.push(context);
    const page = await context.newPage();
    page.setDefaultTimeout(30_000);
    page.setDefaultNavigationTimeout(45_000);
    page.on("pageerror", error => jsErrors.push(error.name));
    page.on("request", request => {
      const url = new URL(request.url());
      if (url.origin !== origin) return;
      if (url.pathname.startsWith("/api/telemetry/") || url.pathname === "/static/telemetry.js") telemetryRequests.push(url.pathname);
      pendingHeaders.push(request.allHeaders().then(headers => rememberCookie(headers.cookie)).catch(() => {}));
    });
    page.on("response", response => {
      const pathname = new URL(response.url()).pathname;
      if (pathname.startsWith("/api/management/") || response.status() >= 400) {
        const category = pathname.startsWith("/api/management/channel/") ? "management-channel"
          : pathname.includes("/credentials/") ? "credential-management"
          : pathname === "/api/management/overview" ? "management-overview"
          : pathname.startsWith("/api/account/passkeys") ? "account-passkeys"
          : "other";
        const diagnostic = { stage, category, method: response.request().method(), status: response.status(), elapsedMs: Date.now() - Date.parse(manifest.startedAt) };
        if (category === "management-channel") {
          const endpoint = pathname.split("/").at(-1);
          if (["start", "events", "ack"].includes(endpoint)) diagnostic.operation = endpoint;
        }
        manifest.responses.push(diagnostic);
        if (response.status() >= 400 && ["management-channel", "credential-management"].includes(category)) {
          pendingHeaders.push(response.json().then(data => {
            if (safeReasons.has(data.reason)) diagnostic.reason = data.reason;
            if (typeof data.reauth_required === "boolean") diagnostic.reauthenticationRequired = data.reauth_required;
          }).catch(() => {}));
        }
      }
      if (response.status() >= 500) manifest.failures.push({ stage, kind: "server-response", status: response.status() });
    });
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
      protocol: "ctap2", transport: credential ? (keyTransports.get(credential.credentialId) || "internal") : "internal", hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true,
    } });
    devices.set(page, { cdp, authenticatorId });
    if (credential) await cdp.send("WebAuthn.addCredential", { authenticatorId, credential });
    return page;
  }
  async function deviceKey(page) {
    const { cdp, authenticatorId } = devices.get(page);
    const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
    assert.equal(credentials.length, 1, "Each test device holds one credential");
    return credentials[0]; // Raw key remains in memory only; never checkpoint it.
  }
  async function rememberSessions() {
    await Promise.all(pendingHeaders.splice(0));
    for (const context of contexts) {
      for (const cookie of await context.cookies(origin)) {
        if (cookie.name === "session") rememberCookie(`session=${cookie.value}`);
      }
    }
    await checkpoint(stage);
  }
  async function overview(page) {
    const response = await page.request.get(`${origin}/api/management/overview`);
    assert.equal(response.status(), 200);
    return response.json();
  }
  async function keysFor(page, username) {
    const response = await page.request.get(`${origin}/api/account/passkeys`);
    assert.equal(response.status(), 200);
    const data = await response.json();
    assert.equal(data.username, username);
    return data.passkeys;
  }
  async function fits(page, selector) {
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    assert.equal(await page.locator(selector).evaluate(element => {
      const rect = element.getBoundingClientRect();
      return element.scrollWidth <= element.clientWidth && rect.left >= 0 && rect.right <= innerWidth;
    }), true);
  }
  async function recover(index) {
    const username = `${prefix}-${index ? "member" : "admin"}`;
    const entry = { username, purpose: index ? "multi-device-target" : "scoped-key-administrator", status: "pending", credentialIds: [] };
    manifest.users.push(entry);
    await checkpoint(index ? "target-recovery" : "administrator-recovery");
    const page = await pageFor();
    await page.goto(grants[index].toString());
    await rememberSessions();
    await page.locator("#recovery-username").fill(username);
    const options = page.waitForResponse(response => new URL(response.url()).pathname.endsWith("/options"));
    await page.locator("#recovery-form button").click();
    assert.equal((await (await options).json()).publicKey.authenticatorSelection.userVerification, "required");
    await page.waitForURL(url => url.pathname === "/management");
    await expect(page.locator("#overview-summary .metric-card").first()).toBeVisible();
    const data = await overview(page);
    const user = data.users.find(item => item.username === username);
    assert.ok(user && user.id === data.currentUserId);
    assert.equal(user.credentials.length, 1);
    Object.assign(entry, { id: user.id, sub: user.sub, status: "created", credentialIds: user.credentials.map(key => key.id) });
    await rememberSessions();
    return { page, entry };
  }

  const administrator = await recover(0);
  const initial = await overview(administrator.page);
  // A dedicated grant can enroll tests while ordinary registration remains closed.
  const registration = initial.registration;
  assert.ok(registration, "Overview must expose the existing registration state");
  assert.equal(registration.mode, "closed", "This test expects closed public registration and never changes it");
  manifest.registrationState = registration;
  await checkpoint("registration-closed-preflight");
  const target = await recover(1);
  assert.notEqual(target.entry.id, administrator.entry.id);
  const firstKeyId = target.entry.credentialIds[0];
  const adminKeyId = administrator.entry.credentialIds[0];
  let firstDeviceKey = await deviceKey(target.page);
  keyTransports.set(firstDeviceKey.credentialId, "internal");
  await target.page.goto(origin);
  await target.page.locator("#account-passkeys-button").click();
  await expect(target.page.locator("#account-passkeys-list li")).toHaveCount(1);
  await expect(target.page.locator("#account-passkeys-add")).toBeEnabled();
  await target.page.locator("#account-passkeys-authenticator").selectOption("security-key");
  await checkpoint("second-device-enrollment");
  const optionsRoute = `${origin}/api/account/passkeys/options`;
  await target.page.route(optionsRoute, async route => {
    try {
    const response = await route.fetch();
    if (response.ok()) {
      const options = await response.json();
      assert.equal(options.publicKey.user.id, target.entry.sub);
      assert.equal(options.publicKey.user.displayName, target.entry.username);
      assert.equal(options.publicKey.authenticatorSelection.userVerification, "required");
      assert.equal(options.publicKey.authenticatorSelection.authenticatorAttachment, "cross-platform");
      assert.deepEqual(options.publicKey.hints, ["security-key"]);
      assert.equal(options.publicKey.excludeCredentials.length, 1);
      assert.equal(options.publicKey.excludeCredentials[0].id, Buffer.from(firstDeviceKey.credentialId, "base64").toString("base64url"));
      firstDeviceKey = await deviceKey(target.page);
      const device = devices.get(target.page);
      await device.cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: device.authenticatorId });
      const added = await device.cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
        protocol: "ctap2", transport: "usb", hasResidentKey: true, hasUserVerification: true,
        isUserVerified: true, automaticPresenceSimulation: true,
      } });
      device.authenticatorId = added.authenticatorId;
    }
    await route.fulfill({ response });
    } catch {
      manifest.failures.push({ stage, kind: "enrollment-contract" });
      await route.abort().catch(() => {});
    }
  });
  const verified = target.page.waitForResponse(response => new URL(response.url()).pathname === "/api/account/passkeys/verify");
  await target.page.locator("#account-passkeys-add").click();
  const enrolled = await verified;
  assert.equal(enrolled.status(), 200);
  assert.equal(enrolled.request().postDataJSON().credential.authenticatorAttachment, "cross-platform");
  await expect(target.page.locator("#account-passkeys-list li")).toHaveCount(2);
  await target.page.unroute(optionsRoute);
  const secondDeviceKey = await deviceKey(target.page);
  keyTransports.set(secondDeviceKey.credentialId, "usb");
  const targetKeys = await keysFor(target.page, target.entry.username);
  const secondKeyId = targetKeys.find(key => key.id !== firstKeyId)?.id;
  assert.ok(secondKeyId);
  target.entry.credentialIds.push(secondKeyId);
  manifest.credentialActions.push({ userId: target.entry.id, credentialId: secondKeyId, action: "created", verified: true });
  await rememberSessions();
  await checkpoint("desktop-mobile-dialog");
  for (const viewport of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) {
    await target.page.setViewportSize(viewport);
    await fits(target.page, "#account-passkeys-dialog");
  }
  await checkpoint("cancel-enrollment");
  await target.page.evaluate(() => {
    const create = navigator.credentials.create.bind(navigator.credentials);
    navigator.credentials.create = async function () {
      navigator.credentials.create = create;
      throw new DOMException("Cancelled by test user", "NotAllowedError");
    };
  });
  await target.page.locator("#account-passkeys-add").click();
  await expect(target.page.locator("#account-passkeys-status")).toHaveText("已取消");
  await expect(target.page.locator("#account-passkeys-add")).toBeEnabled();
  assert.equal((await keysFor(target.page, target.entry.username)).length, 2);
  await target.page.locator("#account-passkeys-close").click();

  async function freshLogin(credential, succeeds, failureStatus = 403) {
    const page = await pageFor(credential);
    const verified = page.waitForResponse(response => new URL(response.url()).pathname === "/auth/passkey/verify");
    await page.goto(`${origin}/auth/passkey?return_to=/`);
    assert.equal((await verified).status(), succeeds ? 200 : failureStatus);
    Object.assign(credential, await deviceKey(page));
    if (succeeds) {
      await page.waitForURL(url => url.pathname === "/");
      const data = await overview(page);
      assert.equal(data.currentUserId, target.entry.id);
      const user = data.users.find(item => item.id === target.entry.id);
      assert.equal(user.sub, target.entry.sub);
      assert.equal(user.username, target.entry.username);
    }
    await rememberSessions();
    return page;
  }
  await checkpoint("second-device-fresh-login");
  await freshLogin(secondDeviceKey, true);
  await administrator.page.goto(`${origin}/management`);
  await expect(administrator.page.locator("#account-passkeys-button")).toBeVisible();
  await administrator.page.locator("#account-passkeys-button").click();
  await expect(administrator.page.locator("#account-passkeys-list li")).toHaveCount(1);
  for (const viewport of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) {
    await administrator.page.setViewportSize(viewport);
    await fits(administrator.page, "#account-passkeys-dialog");
  }
  await administrator.page.locator("#account-passkeys-close").click();
  await administrator.page.locator('[data-view="users"]').click();

  async function manage(action) {
    const page = administrator.page;
    assert.ok(target.entry.username.startsWith(`${prefix}-`) && target.entry.id !== administrator.entry.id);
    assert.ok(secondKeyId !== firstKeyId && secondKeyId !== adminKeyId);
    await checkpoint(`administrator-${action}-second-key`);
    const record = { userId: target.entry.id, credentialId: secondKeyId, action, verified: false };
    manifest.credentialActions.push(record);
    await checkpoint(stage);
    const editor = page.locator(`[data-edit-user="${target.entry.id}"]`);
    manifest.uiChecks.push({ stage, control: "synthetic-target-editor", count: await editor.count(), visible: await editor.isVisible(), managementPage: new URL(page.url()).pathname === "/management" });
    await checkpoint(`administrator-${action}-open-editor`);
    await editor.click();
    const endpoint = `/api/management/users/${target.entry.id}/credentials/${secondKeyId}`;
    const method = action === "delete" ? "DELETE" : "PATCH";
    const response = page.waitForResponse(response => new URL(response.url()).pathname === endpoint && response.request().method() === method);
    void response.catch(() => {});
    if (action === "delete") page.once("dialog", dialog => dialog.accept());
    const button = page.locator(action === "delete" ? `[data-delete-credential="${secondKeyId}"]` : `[data-toggle-credential="${secondKeyId}"]`);
    manifest.uiChecks.push({ stage, control: "synthetic-second-key", count: await button.count(), visible: await button.isVisible(), enabled: await button.isEnabled() });
    await checkpoint(`administrator-${action}-click-key-action`);
    if (action !== "delete") await expect(button).toHaveAttribute("data-next-disabled", String(action === "disable"));
    await button.click();
    await checkpoint(`administrator-${action}-await-key-response`);
    const result = await response;
    record.responseStatus = result.status();
    await checkpoint(`administrator-${action}-validate-response`);
    assert.equal(result.status(), 200);
    await expect(page.locator("#editor-dialog")).not.toBeVisible();
    await checkpoint(`administrator-${action}-verify-scoped-state`);
    const data = await overview(page);
    const user = data.users.find(item => item.id === target.entry.id);
    const administratorUser = data.users.find(item => item.id === administrator.entry.id);
    assert.equal(user.credentials.find(key => key.id === firstKeyId)?.disabledAt, null);
    assert.deepEqual(administratorUser.credentials.map(key => key.id), [adminKeyId]);
    assert.equal(administratorUser.credentials[0].disabledAt, null);
    const modified = user.credentials.find(key => key.id === secondKeyId);
    if (action === "delete") assert.equal(modified, undefined);
    else assert.equal(modified.disabledAt !== null, action === "disable");
    assert.deepEqual(data.registration, registration);
    record.verified = true;
    await rememberSessions();
  }
  await manage("disable");
  await checkpoint("disabled-second-key-rejected-first-key-works");
  await freshLogin(secondDeviceKey, false);
  await freshLogin(firstDeviceKey, true);
  await manage("enable");
  await checkpoint("enabled-second-key-works");
  await freshLogin(secondDeviceKey, true);
  await manage("delete");
  await checkpoint("deleted-second-key-rejected-first-key-works");
  await freshLogin(secondDeviceKey, false, 404);
  await freshLogin(firstDeviceKey, true);
  assert.deepEqual(jsErrors, []);
  assert.deepEqual(telemetryRequests, []);
  assert.deepEqual(manifest.failures, []);
  manifest.completed = true;
  manifest.completedAt = new Date().toISOString();
  await rememberSessions();
  await checkpoint("complete");
  console.log("Remote multiple-Passkeys acceptance passed; exact test identities remain recorded for operator cleanup.");
} catch (error) {
  if (manifestCreated) {
    manifest.failedAt = new Date().toISOString();
    manifest.failures.push({ stage, kind: "acceptance-failure", errorName: ["Error", "AssertionError", "ExpectError", "TimeoutError", "TypeError"].includes(error?.name) ? error.name : "OtherError" });
    try {
      await Promise.all(pendingHeaders);
      for (const context of contexts) for (const cookie of await context.cookies()) {
        if (cookie.name === "session") {
          const value = hash(cookie.value);
          if (!manifest.sessionHashes.includes(value)) manifest.sessionHashes.push(value);
        }
      }
      await checkpoint(stage);
    } catch { /* Preserve the last private checkpoint if interrupted. */ }
  }
  console.error(`Remote multiple-Passkeys acceptance failed during ${stage}; consult the private manifest and clean up before another run.`);
  process.exitCode = 1;
} finally {
  await browser?.close();
  resolver?.restore();
}
