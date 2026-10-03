#!/usr/bin/env node
import { createHash, randomBytes } from "node:crypto";
import { mkdir, writeFile, rm } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2),
  command = args.shift();
const flag = (name) => args.includes("--" + name);
const option = (name, fallback) => {
  const i = args.indexOf("--" + name);
  return i < 0 ? fallback : args[i + 1];
};
const now = Math.floor(Date.now() / 1000),
  random = () => randomBytes(32).toString("base64url");
const hash = (value) => createHash("sha256").update(value).digest("base64url");
const quote = (value) => "'" + String(value).replaceAll("'", "''") + "'";
const origin = option("origin", "http://localhost:8787");
const remote = flag("remote");
const privateDir = resolve(root, ".local");
await mkdir(privateDir, { recursive: true, mode: 0o700 });
async function execute(sql) {
  const path = resolve(
    privateDir,
    `operation-${randomBytes(8).toString("hex")}.sql`,
  );
  await writeFile(path, sql, { mode: 0o600 });
  try {
    const result = spawnSync(
      process.execPath,
      [
        resolve(root, "node_modules/wrangler/bin/wrangler.js"),
        "d1",
        "execute",
        "DB",
        remote ? "--remote" : "--local",
        "--file",
        path,
      ],
      { cwd: root, encoding: "utf8", env: process.env },
    );
    if (result.status !== 0)
      throw new Error(
        "D1 operation failed. Check your account, database binding and applied migrations. No credential has been printed.",
      );
  } finally {
    await rm(path, { force: true });
  }
}
async function saveSecret(name, data) {
  const path = resolve(privateDir, `${name}-${Date.now()}.json`);
  await writeFile(path, JSON.stringify(data, null, 2) + "\n", { mode: 0o600 });
  console.log(`Saved operator material (mode 0600): ${path}`);
}
if (command === "recovery") {
  const ttl = Number(option("minutes", "15"));
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 60)
    throw Error("--minutes must be 1–60");
  const token = random(),
    expires = now + ttl * 60;
  await execute(
    `INSERT INTO admin_recovery_tokens(token_hash,created_at,expires_at) VALUES(${quote(hash(token))},${now},${expires});`,
  );
  await saveSecret("recovery", {
    url: new URL("/" + token, origin).toString(),
    expiresAt: new Date(expires * 1000).toISOString(),
    environment: remote ? "remote" : "local",
  });
} else if (command === "demo-client") {
  const id = option("id", "passkey-demo"),
    secret = random();
  const url = new URL(origin);
  if (
    url.origin !== origin ||
    !(
      url.protocol === "https:" ||
      (url.protocol === "http:" &&
        ["localhost", "127.0.0.1"].includes(url.hostname))
    )
  )
    throw Error(
      "Provide an exact HTTPS origin (or localhost for local development).",
    );
  const redirects = [
    "/demo/oauth/callback",
    "/demo/third-party/callback",
    "/demo/link-login/callback",
  ].map((path) => origin + path);
  // Deliberately insert only: rerunning never rotates a client secret unexpectedly.
  await execute(
    `INSERT INTO oauth_clients(client_id,name,secret_hash,redirect_uris,enabled,is_demo,created_at,updated_at) VALUES(${quote(id)},'Passkey Demo',${quote(hash(secret))},${quote(JSON.stringify(redirects))},1,1,${now},${now});`,
  );
  await saveSecret("demo-client", {
    clientId: id,
    clientSecret: secret,
    redirectUris: redirects,
    environment: remote ? "remote" : "local",
  });
} else if (command === "registration") {
  const mode = args.find((v) => ["open", "closed"].includes(v));
  if (!mode) throw Error("Use registration open|closed [--remote].");
  await execute(
    `INSERT INTO app_settings(setting_key,setting_value,updated_at) VALUES('registration_mode',${quote(mode)},${now}) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=excluded.updated_at;`,
  );
  console.log(`Registration ${mode}.`);
} else {
  console.log(
    "Usage: npm run operator -- recovery [--origin https://auth.example.com] [--minutes 15] [--remote]\n       npm run operator -- demo-client [--origin https://auth.example.com] [--remote]\n       npm run operator -- registration open|closed [--remote]\nApply D1 migrations before initialization. Bootstrap URLs/client secrets are written only to ignored .local files.",
  );
  process.exitCode = command ? 1 : 0;
}
