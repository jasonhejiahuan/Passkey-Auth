import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";
import { request as httpRequest } from "node:http";
import { readMigrations } from "./migrations";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

const origin = "https://auth.test";
const callback = "https://ppq.test/callback";
const digest = (value: string | Buffer) =>
  createHash("sha256").update(value).digest();
const hash = (value: string) => digest(value).toString("base64url");
let runtime: Miniflare;
let address: string;

// Minimal CBOR encoder for an attestation-none WebAuthn credential.
function cbor(value: unknown): Buffer {
  const head = (major: number, size: number): Buffer => {
    if (size < 24) return Buffer.from([(major << 5) | size]);
    if (size < 256) return Buffer.from([(major << 5) | 24, size]);
    const result = Buffer.alloc(3);
    result[0] = (major << 5) | 25;
    result.writeUInt16BE(size, 1);
    return result;
  };
  if (typeof value === "number")
    return head(value >= 0 ? 0 : 1, value >= 0 ? value : -value - 1);
  if (typeof value === "string") {
    const bytes = Buffer.from(value);
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value))
    return Buffer.concat([head(2, value.length), value]);
  if (value instanceof Map)
    return Buffer.concat([
      head(5, value.size),
      ...[...value].flatMap(([key, item]) => [cbor(key), cbor(item)]),
    ]);
  throw new Error("Unsupported fixture CBOR value");
}

class Authenticator {
  id = randomBytes(32).toString("base64url");
  privateKey: KeyObject;
  publicKey: Buffer;
  userHandle = "";
  counter = 0;

  constructor() {
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    this.privateKey = pair.privateKey;
    const jwk = pair.publicKey.export({ format: "jwk" });
    this.publicKey = cbor(
      new Map<number, unknown>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, Buffer.from(jwk.x!, "base64url")],
        [-3, Buffer.from(jwk.y!, "base64url")],
      ]),
    );
  }

  registration(options: any, credentialOrigin = origin, userVerified = true) {
    this.userHandle = options.user.id;
    const client = Buffer.from(
      JSON.stringify({
        type: "webauthn.create",
        challenge: options.challenge,
        origin: credentialOrigin,
        crossOrigin: false,
      }),
    );
    const credential = Buffer.from(this.id, "base64url");
    const length = Buffer.alloc(2);
    length.writeUInt16BE(credential.length);
    const authData = Buffer.concat([
      digest(options.rp.id),
      Buffer.from([userVerified ? 0x45 : 0x41]),
      Buffer.alloc(4),
      Buffer.alloc(16),
      length,
      credential,
      this.publicKey,
    ]);
    const attestation = cbor(
      new Map<string, unknown>([
        ["fmt", "none"],
        ["attStmt", new Map()],
        ["authData", authData],
      ]),
    );
    return {
      id: this.id,
      rawId: this.id,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        attestationObject: attestation.toString("base64url"),
        clientDataJSON: client.toString("base64url"),
        transports: ["internal"],
      },
    };
  }

  assertion(
    options: any,
    changes: {
      origin?: string;
      challenge?: string;
      userHandle?: string;
      userVerified?: boolean;
    } = {},
  ) {
    const client = Buffer.from(
      JSON.stringify({
        type: "webauthn.get",
        challenge: changes.challenge ?? options.challenge,
        origin: changes.origin ?? origin,
        crossOrigin: false,
      }),
    );
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(++this.counter);
    const authData = Buffer.concat([
      digest(options.rpId),
      Buffer.from([changes.userVerified === false ? 0x01 : 0x05]),
      counter,
    ]);
    const signature = sign(
      "sha256",
      Buffer.concat([authData, digest(client)]),
      this.privateKey,
    );
    return {
      id: this.id,
      rawId: this.id,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        authenticatorData: authData.toString("base64url"),
        clientDataJSON: client.toString("base64url"),
        signature: signature.toString("base64url"),
        userHandle: changes.userHandle ?? this.userHandle,
      },
    };
  }
}

class Browser {
  cookie = "";
  async request(
    path: string,
    method = "GET",
    data?: unknown,
    extra: Record<string, string> = {},
  ) {
    const response = await fetch(`${address}${path}`, {
      method,
      redirect: "manual",
      headers: {
        origin,
        ...(this.cookie ? { cookie: this.cookie } : {}),
        ...(data !== undefined ? { "content-type": "application/json" } : {}),
        ...extra,
      },
      ...(data !== undefined ? { body: JSON.stringify(data) } : {}),
    });
    const session = response.headers
      .getSetCookie()
      .find((value) => value.startsWith("session="));
    if (session) this.cookie = session.split(";")[0];
    return response;
  }
  async json(path: string, method = "GET", data?: unknown) {
    const response = await this.request(path, method, data);
    const result = (await response.json()) as any;
    expect(response.status, JSON.stringify(result)).toBe(200);
    return result;
  }
}

async function sql(
  statement: string,
  bindings: unknown[] = [],
): Promise<{ results: Record<string, any>[] }> {
  const response = await fetch(`${address}/__test/sql`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ statement, bindings }),
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json() as Promise<{ results: Record<string, any>[] }>;
}
async function signup(name = "Alice") {
  const browser = new Browser(),
    authenticator = new Authenticator();
  await browser.json("/api/ui/intent", "POST", { intent: "register" });
  const options = (
    await browser.json("/api/register/options", "POST", { username: name })
  ).publicKey;
  await browser.json("/api/register/verify", "POST", {
    credential: authenticator.registration(options),
  });
  return { browser, authenticator, options };
}
async function additionalOptions(browser: Browser) {
  const { csrfToken } = await browser.json("/api/account/passkeys");
  const { publicKey } = await browser.json(
    "/api/account/passkeys/options",
    "POST",
    { csrfToken },
  );
  return { csrfToken, publicKey };
}
async function loginOptions(browser: Browser, name = "Alice") {
  const flow = await browser.json("/auth/passkey/flow", "POST", {});
  const options = (
    await browser.json("/auth/passkey/options", "POST", {
      mode: "login",
      username: name,
      authFlowToken: flow.authFlowToken,
    })
  ).publicKey;
  return { options, flow: flow.authFlowToken };
}
async function authorization(browser: Browser, authenticator: Authenticator) {
  const verifier = randomBytes(32).toString("base64url");
  const params = {
    response_type: "code",
    client_id: "ppq-test",
    redirect_uri: callback,
    state: "browser-bound-state",
    code_challenge: hash(verifier),
    code_challenge_method: "S256",
    login_hint: "Alice",
  };
  const response = await browser.request(
    "/oauth/authorize?" + new URLSearchParams(params),
  );
  expect(response.status, await response.text()).toBe(200);
  const values = {
    client_id: params.client_id,
    redirect_uri: callback,
    state: params.state,
  };
  expect(
    (await browser.request("/oauth/authorize/complete", "POST", values)).status,
  ).toBe(401);
  const { authFlowToken } = await browser.json(
    "/auth/passkey/flow",
    "POST",
    {},
  );
  const { publicKey } = await browser.json("/auth/passkey/options", "POST", {
    mode: "code",
    username: "Alice",
    authFlowToken,
  });
  await browser.json("/auth/passkey/verify", "POST", {
    credential: authenticator.assertion(publicKey),
    authFlowToken,
  });
  expect(
    (
      await browser.request("/oauth/authorize/complete", "POST", {
        ...values,
        state: "changed-state",
      })
    ).status,
  ).toBe(400);
  const { redirectUrl } = await browser.json(
    "/oauth/authorize/complete",
    "POST",
    values,
  );
  const code = new URL(redirectUrl).searchParams.get("code");
  expect(code).toBeTruthy();
  return { code, verifier, values };
}
function exchange(
  browser: Browser,
  code: string | null,
  verifier: string,
  changes: Record<string, string> = {},
) {
  return browser.request("/oauth/token", "POST", {
    grant_type: "authorization_code",
    client_id: "ppq-test",
    client_secret: "test-client-secret",
    redirect_uri: callback,
    code,
    code_verifier: verifier,
    ...changes,
  });
}

beforeAll(async () => {
  const bundle = await build({
    stdin: {
      contents: `import app from './src/index.ts';export default {scheduled:app.scheduled,async fetch(request,env,ctx){
      const path=new URL(request.url).pathname;
      if(path==='/__test/sql'){const {statement,bindings}=await request.json();return Response.json(await env.DB.prepare(statement).bind(...bindings).all());}
      if(path==='/__test/migration')return Response.json(await env.DB.batch((await request.text()).replace(/^--.*$/gm,'').split(';').map(s=>s.trim()).filter(Boolean).map(s=>env.DB.prepare(s))));
      const before=request.headers.get('x-test-before-batch-sql');
      if(before){const db=env.DB;let changed=false;env={...env,DB:{prepare:db.prepare.bind(db),async batch(statements){if(!changed){changed=true;await db.prepare(before).run();}return db.batch(statements);}}};}
      const beforeRun=request.headers.get('x-test-before-run-sql');
      if(beforeRun){const db=env.DB;let changed=false;const wrap=s=>new Proxy(s,{get(target,key){if(key==='bind')return(...bindings)=>wrap(target.bind(...bindings));if(key==='run')return async()=>{if(!changed){changed=true;await db.prepare(beforeRun).run();}return target.run();};const value=target[key];return typeof value==='function'?value.bind(target):value;}});env={...env,DB:{prepare:query=>query.startsWith('UPDATE sessions SET data_json=')?wrap(db.prepare(query)):db.prepare(query),batch:db.batch.bind(db)}};}
      const url=new URL(request.url);
      return app.fetch(new Request(env.PASSKEY_ORIGIN+url.pathname+url.search,request),env,ctx);
    }};`,
      resolveDir: process.cwd(),
      sourcefile: "auth-fixture.ts",
    },
    bundle: true,
    write: false,
    format: "esm",
    platform: "browser",
    target: "es2023",
  });
  runtime = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      compatibilityDate: "2026-10-03",
      compatibilityFlags: ["nodejs_compat"],
      script: bundle.outputFiles[0].text,
      d1Databases: ["DB"],
      bindings: {
        PASSKEY_ORIGIN: origin,
        PASSKEY_RP_ID: "auth.test",
        PASSKEY_RP_NAME: "Fixture Passkey",
        PASSKEY_SERVER_API_TOKEN: "fixture-server-api-token",
      },
      serviceBindings: {
        ASSETS: () => new Response("fixture asset", { status: 404 }),
      },
    }),
  );
  address = String(await runtime.ready).replace(/\/$/, "");
  const response = await fetch(`${address}/__test/migration`, {
    method: "POST",
    body: await readMigrations(),
  });
  expect(response.ok, await response.text()).toBe(true);
}, 30_000);
afterAll(async () => {
  await runtime?.dispose();
});
beforeEach(async () => {
  for (const table of [
    "audit_logs",
    "login_history",
    "sessions",
    "users",
    "oauth_clients",
    "app_settings",
    "admin_recovery_tokens",
  ])
    await sql(`DELETE FROM ${table}`);
  const time = Math.floor(Date.now() / 1000);
  await sql(
    "INSERT INTO app_settings(setting_key,setting_value,updated_at) VALUES ('registration_mode','open',?)",
    [time],
  );
  await sql(
    "INSERT INTO oauth_clients(client_id,name,secret_hash,redirect_uris,created_at,updated_at) VALUES (?,?,?,?,?,?)",
    [
      "ppq-test",
      "PPQ",
      hash("test-client-secret"),
      JSON.stringify([callback]),
      time,
      time,
    ],
  );
});

describe("native authentication routes with real WebAuthn signatures", () => {
  it("returns registration_not_allowed with intact state and preserves existing sign-in", async () => {
    await signup();
    await sql("UPDATE app_settings SET setting_value='closed' WHERE setting_key='registration_mode'");
    const browser = new Browser();
    const query = new URLSearchParams({response_type:'code',client_id:'ppq-test',redirect_uri:callback,state:'bound-closed-state',screen_hint:'signup',login_hint:'NewPerson',code_challenge:'a'.repeat(43),code_challenge_method:'S256'});
    const denied=await browser.request('/oauth/authorize?'+query);
    const target=new URL(denied.headers.get('location')!);
    expect(target.origin+target.pathname).toBe(callback);
    expect(target.searchParams.get('error')).toBe('registration_not_allowed');
    expect(target.searchParams.get('state')).toBe('bound-closed-state');
    expect((await (await browser.request('/api/ui/intent','POST',{intent:'register'})).json() as any).code).toBe('registration_not_allowed');
    const client=await browser.request('/api/ui/register-client.js');
    expect(await client.text()).toContain("code:'registration_not_allowed'");
    query.set('login_hint','Alice');
    const existing=await browser.request('/oauth/authorize?'+query);
    expect(existing.status).toBe(200);
    expect(await existing.text()).toContain('data-screen-hint=""');
  });
  it("adds a second passkey to the same identity when signup is closed and both keys support named and discoverable login", async () => {
    const { browser, authenticator } = await signup();
    await signup("Other User");
    const original = (
      await sql("SELECT * FROM users WHERE username_key='alice'")
    ).results[0];
    const sessionHash = hash(browser.cookie.slice("session=".length));
    const originalSession = (
      await sql("SELECT * FROM sessions WHERE token_hash=?", [sessionHash])
    ).results[0];
    await sql(
      "UPDATE app_settings SET setting_value='closed' WHERE setting_key='registration_mode'",
    );
    const list = await browser.json("/api/account/passkeys");
    expect(list.passkeys).toHaveLength(1);
    expect(Object.keys(list.passkeys[0]).sort()).toEqual([
      "backedUp",
      "createdAt",
      "deviceType",
      "disabledAt",
      "id",
      "updatedAt",
    ]);
    const second = new Authenticator(),
      { csrfToken, publicKey } = await additionalOptions(browser);
    expect(publicKey.user).toEqual({
      id: authenticator.userHandle, name: "Alice", displayName: "Alice",
    });
    expect(publicKey.authenticatorSelection.userVerification).toBe("required");
    expect(publicKey.excludeCredentials.map((row: any) => row.id)).toEqual([
      authenticator.id,
    ]);
    const response = await browser.request(
      "/api/account/passkeys/verify",
      "POST",
      {
        csrfToken,
        credential: second.registration(publicKey),
        userId: original.id + 1,
        username: "Other User",
      },
    );
    expect(response.status).toBe(200);
    expect(response.headers.getSetCookie()).toHaveLength(0);
    expect(
      (await sql("SELECT * FROM users WHERE id=?", [original.id])).results[0],
    ).toEqual(original);
    expect(
      (await sql("SELECT * FROM sessions WHERE token_hash=?", [sessionHash]))
        .results[0],
    ).toEqual(originalSession);
    expect(
      (
        await sql("SELECT user_id FROM credentials WHERE user_id=?", [
          original.id,
        ])
      ).results,
    ).toEqual([{ user_id: original.id }, { user_id: original.id }]);
    expect(
      (
        await sql(
          "SELECT actor_user_id,target_type FROM audit_logs WHERE action='credential.add' AND actor_user_id=?",
          [original.id],
        )
      ).results,
    ).toEqual([{ actor_user_id: original.id, target_type: "credential" }]);
    expect((await browser.json("/api/account/passkeys")).passkeys).toHaveLength(
      2,
    );
    for (const key of [authenticator, second]) {
      for (const name of ["Alice", ""]) {
        const fresh = new Browser(),
          { options, flow } = await loginOptions(fresh, name);
        await fresh.json("/auth/passkey/verify", "POST", {
          credential: key.assertion(options),
          authFlowToken: flow,
        });
        expect(await fresh.json("/api/me")).toMatchObject({
          authenticated: true,
          user: { username: "Alice" },
        });
      }
    }
  });

  it("requires a signed-in session, same origin, session CSRF, and recent verified authentication to add passkeys", async () => {
    const guest = new Browser();
    expect((await guest.request("/api/account/passkeys")).status).toBe(401);
    for (const path of ["options", "verify"])
      expect(
        (await guest.request(`/api/account/passkeys/${path}`, "POST", {}))
          .status,
      ).toBe(401);
    const { browser, authenticator } = await signup();
    const { csrfToken } = await browser.json("/api/account/passkeys");
    for (const path of ["options", "verify"]) {
      expect(
        (
          await browser.request(`/api/account/passkeys/${path}`, "POST", {
            csrfToken: "wrong",
          })
        ).status,
      ).toBe(403);
      expect(
        (
          await browser.request(
            `/api/account/passkeys/${path}`,
            "POST",
            { csrfToken },
            { origin: "https://evil.test" },
          )
        ).status,
      ).toBe(403);
    }
    const tokenHash = hash(browser.cookie.slice("session=".length));
    await sql(
      "UPDATE sessions SET reauthenticated_at=unixepoch()-301 WHERE token_hash=?",
      [tokenHash],
    );
    for (const path of ["options", "verify"]) {
      const response = await browser.request(
        `/api/account/passkeys/${path}`,
        "POST",
        { csrfToken },
      );
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ reauthRequired: true });
    }
    const presenceOnly = new Browser(),
      { options, flow } = await loginOptions(presenceOnly);
    await presenceOnly.json("/auth/passkey/verify", "POST", {
      credential: authenticator.assertion(options, { userVerified: false }),
      authFlowToken: flow,
    });
    const presenceCsrf = (await presenceOnly.json("/api/account/passkeys"))
      .csrfToken;
    const denied = await presenceOnly.request(
      "/api/account/passkeys/options",
      "POST",
      { csrfToken: presenceCsrf },
    );
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ reauthRequired: true });
    expect(
      (
        await sql(
          "SELECT id FROM ceremonies WHERE purpose='additional_passkey'",
        )
      ).results,
    ).toHaveLength(0);
  });

  it("targets an explicitly chosen USB security key without changing the default ceremony or weakening UV", async () => {
    const { browser, authenticator } = await signup();
    const automatic = await additionalOptions(browser);
    expect(automatic.publicKey.authenticatorSelection).toEqual({
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required",
    });
    expect(automatic.publicKey.hints).toEqual([
      "client-device", "security-key", "hybrid",
    ]);
    expect(automatic.publicKey.pubKeyCredParams.map((row: any) => row.alg)).toEqual([
      -7, -8, -257,
    ]);
    await sql(
      "INSERT INTO app_settings(setting_key,setting_value,updated_at) VALUES ('passkey_algorithms','[-7]',unixepoch()),('passkey_hints','[\"hybrid\"]',unixepoch())",
    );
    let publicKey: any;
    for (const attachment of ["any", "cross-platform"]) {
      await sql(
        "INSERT INTO app_settings(setting_key,setting_value,updated_at) VALUES ('passkey_authenticator_attachment',?,unixepoch()) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value",
        [attachment],
      );
      ({ publicKey } = await browser.json(
        "/api/account/passkeys/options", "POST",
        { csrfToken: automatic.csrfToken, authenticator: "security-key" },
      ));
      expect(publicKey.authenticatorSelection).toEqual({
        authenticatorAttachment: "cross-platform",
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "required",
      });
      expect(publicKey.hints).toEqual(["security-key"]);
      expect(publicKey.pubKeyCredParams).toEqual([{ alg: -7, type: "public-key" }]);
      expect(publicKey.attestation).toBe("none");
      expect(publicKey.user).toEqual({
        id: authenticator.userHandle, name: "Alice", displayName: "Alice",
      });
      expect(publicKey.excludeCredentials.map((row: any) => row.id)).toEqual([
        authenticator.id,
      ]);
    }
    const usbKey = new Authenticator();
    const usbRegistration = (verified: boolean) => {
      const credential = usbKey.registration(publicKey, origin, verified);
      credential.authenticatorAttachment = "cross-platform";
      credential.response.transports = ["usb"];
      return credential;
    };
    const rejected = await browser.request(
      "/api/account/passkeys/verify", "POST",
      { csrfToken: automatic.csrfToken, credential: usbRegistration(false) },
    );
    expect(rejected.status).toBe(400);
    expect((await sql("SELECT id FROM credentials")).results).toHaveLength(1);
    expect((await sql(
      "SELECT id FROM audit_logs WHERE action='credential.add'",
    )).results).toHaveLength(0);
    expect((await sql(
      "SELECT consumed_at FROM ceremonies WHERE purpose='additional_passkey' AND challenge=?",
      [publicKey.challenge],
    )).results).toEqual([{ consumed_at: null }]);
    await browser.json("/api/account/passkeys/verify", "POST", {
      csrfToken: automatic.csrfToken, credential: usbRegistration(true),
    });
    expect((await sql(
      "SELECT transports,device_type,disabled_at FROM credentials WHERE credential_id=?",
      [usbKey.id],
    )).results).toEqual([{
      transports: '["usb"]', device_type: "singleDevice", disabled_at: null,
    }]);
    const fresh = new Browser(), { options, flow } = await loginOptions(fresh);
    expect(options.allowCredentials.find((row: any) => row.id === usbKey.id)).toMatchObject({
      transports: ["usb"],
    });
    await fresh.json("/auth/passkey/verify", "POST", {
      authFlowToken: flow, credential: usbKey.assertion(options),
    });
    expect(await fresh.json("/api/me")).toMatchObject({ authenticated: true });
    const nextAutomatic = await additionalOptions(browser);
    expect(nextAutomatic.publicKey.hints).toEqual(["hybrid"]);
    expect(nextAutomatic.publicKey.authenticatorSelection.userVerification).toBe("required");
    expect(nextAutomatic.publicKey.authenticatorSelection.authenticatorAttachment)
      .toBe("cross-platform");
    const { authFlowToken } = await browser.json("/auth/passkey/flow", "POST", {});
    const reauth = await browser.json("/auth/passkey/options", "POST", {
      mode: "reauth", authFlowToken,
    });
    expect(reauth.publicKey.userVerification).toBe("required");
  });

  it("rejects invalid device choices and respects platform-only policy without replacing an existing ceremony", async () => {
    const { browser } = await signup();
    const { csrfToken, publicKey } = await additionalOptions(browser);
    for (const authenticator of [null, "", "auto", "platform", {}, true]) {
      const response = await browser.request(
        "/api/account/passkeys/options", "POST", { csrfToken, authenticator },
      );
      expect(response.status).toBe(400);
    }
    await sql(
      "INSERT INTO app_settings(setting_key,setting_value,updated_at) VALUES ('passkey_authenticator_attachment','platform',unixepoch())",
    );
    const denied = await browser.request(
      "/api/account/passkeys/options", "POST",
      { csrfToken, authenticator: "security-key" },
    );
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ error: "当前 Passkey 策略不允许安全密钥" });
    expect((await sql(
      "SELECT challenge,consumed_at FROM ceremonies WHERE purpose='additional_passkey'",
    )).results).toEqual([{ challenge: publicKey.challenge, consumed_at: null }]);
    expect((await sql("SELECT id FROM credentials")).results).toHaveLength(1);
    const automatic = await additionalOptions(browser);
    expect(automatic.publicKey.authenticatorSelection.authenticatorAttachment).toBe("platform");
    expect(automatic.publicKey.hints).toEqual(["client-device", "security-key", "hybrid"]);
  });

  it("binds additional-passkey ceremonies to the original session, user and strong UV response", async () => {
    const { browser, authenticator } = await signup();
    const secondSession = new Browser(),
      { options, flow } = await loginOptions(secondSession);
    await secondSession.json("/auth/passkey/verify", "POST", {
      credential: authenticator.assertion(options),
      authFlowToken: flow,
    });
    const other = await signup("Bob");
    const { csrfToken, publicKey } = await additionalOptions(browser);
    const key = new Authenticator(),
      credential = key.registration(publicKey);
    for (const foreign of [secondSession, other.browser]) {
      const foreignCsrf = (await foreign.json("/api/account/passkeys"))
        .csrfToken;
      expect(
        (
          await foreign.request("/api/account/passkeys/verify", "POST", {
            csrfToken: foreignCsrf,
            credential,
          })
        ).status,
      ).toBe(400);
    }
    for (const invalid of [
      key.registration(publicKey, origin, false),
      key.registration(publicKey, "https://evil.test"),
      key.registration({
        ...publicKey,
        challenge: randomBytes(32).toString("base64url"),
      }),
    ]) {
      expect(
        (
          await browser.request("/api/account/passkeys/verify", "POST", {
            csrfToken,
            credential: invalid,
          })
        ).status,
      ).toBe(400);
    }
    expect((await sql("SELECT id FROM credentials")).results).toHaveLength(2);
    expect(
      (
        await browser.request("/api/account/passkeys/verify", "POST", {
          csrfToken,
          credential,
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await browser.request("/api/account/passkeys/verify", "POST", {
          csrfToken,
          credential,
        })
      ).status,
    ).toBe(400);
  });

  it("rejects duplicate and disabled existing credentials without consuming a usable add ceremony", async () => {
    const { browser, authenticator } = await signup();
    await sql(
      "UPDATE credentials SET disabled_at=unixepoch() WHERE credential_id=?",
      [authenticator.id],
    );
    const { csrfToken, publicKey } = await additionalOptions(browser);
    expect(publicKey.excludeCredentials.map((row: any) => row.id)).toEqual([
      authenticator.id,
    ]);
    const listed = await browser.json("/api/account/passkeys");
    expect(listed.passkeys[0].disabledAt).toEqual(expect.any(Number));
    const duplicate = await browser.request(
      "/api/account/passkeys/verify",
      "POST",
      { csrfToken, credential: authenticator.registration(publicKey) },
    );
    expect(duplicate.status).toBe(409);
    expect(
      (
        await sql(
          "SELECT consumed_at FROM ceremonies WHERE purpose='additional_passkey'",
        )
      ).results[0].consumed_at,
    ).toBeNull();
    expect((await sql("SELECT id FROM credentials")).results).toHaveLength(1);
    expect(
      (await sql("SELECT id FROM audit_logs WHERE action='credential.add'"))
        .results,
    ).toHaveLength(0);
  });

  it("inserts and audits only one additional passkey when verification races", async () => {
    const { browser } = await signup();
    const { csrfToken, publicKey } = await additionalOptions(browser),
      key = new Authenticator();
    const credential = key.registration(publicKey),
      cookie = browser.cookie;
    const responses = await Promise.all(
      Array.from({ length: 8 }, () =>
        fetch(`${address}/api/account/passkeys/verify`, {
          method: "POST",
          headers: { origin, cookie, "content-type": "application/json" },
          body: JSON.stringify({ csrfToken, credential }),
        }),
      ),
    );
    expect(
      responses.filter((response) => response.status === 200),
    ).toHaveLength(1);
    expect(
      responses.filter(
        (response) => response.status >= 400 && response.status < 500,
      ),
    ).toHaveLength(7);
    expect((await sql("SELECT id FROM credentials")).results).toHaveLength(2);
    expect(
      (await sql("SELECT id FROM audit_logs WHERE action='credential.add'"))
        .results,
    ).toHaveLength(1);
    expect((await sql("SELECT * FROM operation_guards")).results).toHaveLength(
      0,
    );
  });

  it("atomically rejects adding a key after user/session revocation or freshness expiry during verification", async () => {
    for (const [index, mutation] of [
      "UPDATE users SET session_version=session_version+1",
      "UPDATE users SET login=0",
      "UPDATE users SET disabled_at=unixepoch()",
      "UPDATE sessions SET reauthenticated_at=unixepoch()-301",
      "UPDATE sessions SET expires_at=unixepoch()-1",
      "DELETE FROM sessions",
    ].entries()) {
      const { browser } = await signup(`Revoked${index}`),
        { csrfToken, publicKey } = await additionalOptions(browser),
        key = new Authenticator();
      const beforeCount = (await sql("SELECT id FROM credentials")).results
        .length;
      const response = await browser.request(
        "/api/account/passkeys/verify",
        "POST",
        { csrfToken, credential: key.registration(publicKey) },
        { "x-test-before-batch-sql": mutation },
      );
      expect(response.status, mutation).toBe(403);
      expect(await response.json()).toMatchObject({ reauthRequired: true });
      expect((await sql("SELECT id FROM credentials")).results).toHaveLength(
        beforeCount,
      );
      expect(
        (await sql("SELECT id FROM audit_logs WHERE action='credential.add'"))
          .results,
      ).toHaveLength(0);
    }
  });

  it("invalidates an outstanding add flow when its authenticating credential is disabled or removed", async () => {
    for (const remove of [false, true]) {
      const { browser, authenticator } = await signup(
        remove ? "Removed" : "Disabled",
      );
      const { csrfToken, publicKey } = await additionalOptions(browser),
        key = new Authenticator();
      await sql(
        remove
          ? "DELETE FROM credentials WHERE credential_id=?"
          : "UPDATE credentials SET disabled_at=unixepoch() WHERE credential_id=?",
        [authenticator.id],
      );
      await sql(
        "UPDATE users SET session_version=session_version+1 WHERE user_handle=?",
        [authenticator.userHandle],
      );
      expect(
        (
          await browser.request("/api/account/passkeys/verify", "POST", {
            csrfToken,
            credential: key.registration(publicKey),
          })
        ).status,
      ).toBe(401);
      expect(
        (
          await sql("SELECT id FROM credentials WHERE credential_id=?", [
            key.id,
          ])
        ).results,
      ).toHaveLength(0);
    }
  });

  it("rechecks authorization before issuing an add ceremony and refuses an expired creation challenge", async () => {
    const { browser } = await signup();
    const { csrfToken } = await browser.json("/api/account/passkeys");
    const denied = await browser.request(
      "/api/account/passkeys/options",
      "POST",
      { csrfToken },
      {
        "x-test-before-batch-sql":
          "UPDATE sessions SET reauthenticated_at=unixepoch()-301",
      },
    );
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ reauthRequired: true });
    expect(
      (
        await sql(
          "SELECT id FROM ceremonies WHERE purpose='additional_passkey'",
        )
      ).results,
    ).toHaveLength(0);
    await sql("UPDATE sessions SET reauthenticated_at=unixepoch()");
    const { publicKey } = await additionalOptions(browser),
      key = new Authenticator();
    await sql(
      "UPDATE ceremonies SET expires_at=unixepoch()-1 WHERE purpose='additional_passkey'",
    );
    expect(
      (
        await browser.request("/api/account/passkeys/verify", "POST", {
          csrfToken,
          credential: key.registration(publicKey),
        })
      ).status,
    ).toBe(400);
    expect((await sql("SELECT id FROM credentials")).results).toHaveLength(1);
  });

  it("omits disabled keys from named login and rejects them in discoverable login and atomic races", async () => {
    const { browser, authenticator } = await signup();
    const second = new Authenticator(),
      { csrfToken, publicKey } = await additionalOptions(browser);
    await browser.json("/api/account/passkeys/verify", "POST", {
      csrfToken,
      credential: second.registration(publicKey),
    });
    await sql(
      "UPDATE credentials SET disabled_at=unixepoch() WHERE credential_id=?",
      [authenticator.id],
    );
    const named = new Browser(),
      allowed = await loginOptions(named);
    expect(allowed.options.allowCredentials.map((row: any) => row.id)).toEqual([
      second.id,
    ]);
    expect(
      (
        await named.request("/auth/passkey/verify", "POST", {
          credential: authenticator.assertion(allowed.options),
          authFlowToken: allowed.flow,
        })
      ).status,
    ).toBe(403);
    const discoverable = new Browser(),
      discovered = await loginOptions(discoverable, "");
    expect(
      (
        await discoverable.request("/auth/passkey/verify", "POST", {
          credential: authenticator.assertion(discovered.options),
          authFlowToken: discovered.flow,
        })
      ).status,
    ).toBe(403);
    const race = new Browser(),
      pending = await loginOptions(race);
    const response = await race.request(
      "/auth/passkey/verify",
      "POST",
      {
        credential: second.assertion(pending.options),
        authFlowToken: pending.flow,
      },
      {
        "x-test-before-batch-sql": `UPDATE credentials SET disabled_at=unixepoch() WHERE credential_id='${second.id}'`,
      },
    );
    expect(response.status).toBe(409);
    expect((await race.json("/api/me")).authenticated).toBe(false);
    expect(
      (
        await sql("SELECT sign_count FROM credentials WHERE credential_id=?", [
          second.id,
        ])
      ).results[0].sign_count,
    ).toBe(0);
    const none = new Browser(),
      { authFlowToken } = await none.json("/auth/passkey/flow", "POST", {});
    expect(
      (
        await none.request("/auth/passkey/options", "POST", {
          username: "Alice",
          authFlowToken,
        })
      ).status,
    ).toBe(404);
  });

  it("rejects username controls before normalization while accepting Unicode letters and ordinary spaces", async () => {
    const browser = new Browser();
    await browser.json("/api/ui/intent", "POST", { intent: "register" });
    for (const separator of [
      "\0",
      "\t",
      "\n",
      "\r",
      "\v",
      "\f",
      "\u001b",
      "\u007f",
      "\u0085",
      "\u00a0",
      "\u2003",
      "\u2028",
      "\u3000",
      "\ufeff",
    ]) {
      for (const name of [
        `Alice${separator}Smith`,
        `${separator}Alice`,
        `Alice${separator}`,
      ]) {
        const response = await browser.request(
          "/api/register/options",
          "POST",
          { username: name },
        );
        expect(response.status).toBe(400);
      }
    }
    expect((await sql("SELECT id FROM ceremonies")).results).toHaveLength(0);
    const { browser: signedIn, options } = await signup(
      "  张伟 José Ｊａｓｏｎ １２  ",
    );
    expect(options.user).toMatchObject({
      name: "张伟 José Jason 12", displayName: "张伟 José Jason 12",
    });
    const additional = await additionalOptions(signedIn);
    expect(additional.publicKey.user).toEqual(options.user);
    expect(await signedIn.json("/api/me")).toMatchObject({
      authenticated: true,
      user: { username: "张伟 José Jason 12" },
    });
  });

  it("authenticates server session verification and honors live permission and version revocation", async () => {
    const { browser, authenticator } = await signup();
    const server = new Browser();
    const headers = { authorization: "Bearer fixture-server-api-token" };
    const verify = (data: Record<string, string>) =>
      server.request("/api/server/session/verify", "POST", data, headers);
    expect(
      (
        await server.request("/api/server/session/verify", "POST", {
          sessionCookie: browser.cookie,
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await server.request(
          "/api/server/session/verify",
          "POST",
          { sessionCookie: browser.cookie },
          { authorization: "Bearer incorrect-token" },
        )
      ).status,
    ).toBe(401);
    for (const data of [
      { sessionCookie: browser.cookie },
      { session_cookie: browser.cookie.slice("session=".length) },
    ]) {
      const response = await verify(data);
      expect(response.status).toBe(200);
      expect(response.headers.getSetCookie()).toHaveLength(0);
      expect(await response.json()).toMatchObject({
        ok: true,
        authenticated: true,
        user: { username: "Alice", sub: authenticator.userHandle },
      });
    }
    expect(
      await (
        await browser.request("/api/server/session/verify", "POST", {}, headers)
      ).json(),
    ).toMatchObject({ authenticated: true });
    expect(
      await (await verify({ sessionCookie: "missing-session" })).json(),
    ).toMatchObject({ authenticated: false });
    await sql("UPDATE users SET login=0 WHERE username_key='alice'");
    expect(
      await (await verify({ sessionCookie: browser.cookie })).json(),
    ).toMatchObject({ authenticated: false });
    await sql(
      "UPDATE users SET login=1,disabled_at=unixepoch() WHERE username_key='alice'",
    );
    expect(
      await (await verify({ sessionCookie: browser.cookie })).json(),
    ).toMatchObject({ authenticated: false });
    await sql(
      "UPDATE users SET disabled_at=NULL,session_version=session_version+1 WHERE username_key='alice'",
    );
    expect(
      await (await verify({ sessionCookie: browser.cookie })).json(),
    ).toMatchObject({ authenticated: false });
    expect(
      await (
        await browser.request("/api/server/session/verify", "POST", {}, headers)
      ).json(),
    ).toMatchObject({ authenticated: false });
  });

  it("runs scheduled D1 cleanup with expiry, cascading children, and configured telemetry retention", async () => {
    const time = Math.floor(Date.now() / 1000);
    const user = (
      await sql(
        "INSERT INTO users(username,username_key,user_handle,created_at) VALUES ('Cleanup','cleanup','cleanup-handle',?) RETURNING id",
        [time],
      )
    ).results[0];
    await sql(
      "INSERT INTO app_settings(setting_key,setting_value,updated_at) VALUES ('telemetry_config',?,?)",
      [JSON.stringify({ retentionDays: 2 }), time],
    );
    await sql(
      "INSERT INTO delivery_state(id,queued,delivered,updated_at) VALUES (1,99,7,?)",
      [time],
    );
    for (const [id, expiry] of [
      ["expired", time - 60],
      ["retained", time + 3600],
    ] as const) {
      await sql(
        "INSERT INTO sessions(token_hash,csrf_token,user_id,user_version,created_at,expires_at) VALUES (?,?,?,1,?,?)",
        [id, "csrf", user.id, time, expiry],
      );
    }
    for (const [id, expiry] of [
      ["expired", time - 60],
      ["retained", time + 3600],
    ] as const) {
      await sql(
        "INSERT INTO ceremonies(id,session_hash,purpose,challenge,expires_at) VALUES (?,'retained','registration','challenge',?)",
        [id, expiry],
      );
      await sql(
        "INSERT INTO registration_reservations(username_key,ceremony_id,expires_at) VALUES (?,?,?)",
        [id, id, expiry],
      );
      await sql(
        "INSERT INTO oauth_requests(id,session_hash,client_id,redirect_uri,state,expires_at) VALUES (?,'retained','ppq-test',?,'state',?)",
        [id, callback, expiry],
      );
      await sql(
        "INSERT INTO oauth_codes(code_hash,client_id,redirect_uri,user_id,user_version,created_at,expires_at) VALUES (?,'ppq-test',?,?,1,?,?)",
        [id, callback, user.id, time, expiry],
      );
      await sql(
        "INSERT INTO access_tokens(token_hash,user_id,user_version,client_id,created_at,expires_at) VALUES (?,?,1,'ppq-test',?,?)",
        [id, user.id, time, expiry],
      );
      await sql(
        "INSERT INTO oauth_challenges(challenge_id,client_id,return_uri,username,username_key,state,created_at,expires_at) VALUES (?,'ppq-test',?,'Cleanup','cleanup','state',?,?)",
        [id, callback, time, expiry],
      );
      await sql(
        "INSERT INTO admin_recovery_tokens(token_hash,created_at,expires_at) VALUES (?,?,?)",
        [id, time, expiry],
      );
      await sql(
        "INSERT INTO management_channels(id,user_id,session_hash,public_key_jwk,server_nonce,created_at,expires_at,last_seen_at) VALUES (?,?,'retained','{}','nonce',?,?,?)",
        [id, user.id, time, expiry, time],
      );
      await sql(
        "INSERT INTO telemetry_receipts(token_id,expires_at,state) VALUES (?,?,'queued')",
        [id, expiry],
      );
      await sql(
        "INSERT INTO telemetry_tokens(token_hash,policy_key,created_at,expires_at) VALUES (?,'policy',?,?)",
        [id, time, expiry],
      );
      await sql(
        "INSERT INTO telemetry_events(token_id,policy_key,path,payload_bytes,created_at) VALUES (?,'policy','/',10,?)",
        [id, time - (id === "expired" ? 3 : 1) * 86400],
      );
    }
    await sql(
      "INSERT INTO ceremonies(id,session_hash,purpose,challenge,expires_at) VALUES ('cascade','expired','registration','challenge',?)",
      [time + 3600],
    );
    await sql(
      "INSERT INTO registration_reservations(username_key,ceremony_id,expires_at) VALUES ('cascade','cascade',?)",
      [time + 3600],
    );
    await sql(
      "INSERT INTO telemetry_receipts(token_id,expires_at,state) VALUES ('delivered',?,'delivered')",
      [time + 3600],
    );

    const result = await (
      await runtime.getWorker()
    ).scheduled({ cron: "0 * * * *", scheduledTime: new Date() });
    expect(result.outcome).toBe("ok");
    for (const [table, key] of [
      ["sessions", "token_hash"],
      ["ceremonies", "id"],
      ["registration_reservations", "username_key"],
      ["oauth_requests", "id"],
      ["oauth_codes", "code_hash"],
      ["access_tokens", "token_hash"],
      ["oauth_challenges", "challenge_id"],
      ["admin_recovery_tokens", "token_hash"],
      ["management_channels", "id"],
      ["telemetry_tokens", "token_hash"],
      ["telemetry_events", "token_id"],
    ]) {
      expect(
        (await sql(`SELECT ${key} AS id FROM ${table}`)).results,
        table,
      ).toEqual([{ id: "retained" }]);
    }
    expect(
      (await sql("SELECT token_id FROM telemetry_receipts ORDER BY token_id"))
        .results,
    ).toEqual([{ token_id: "delivered" }, { token_id: "retained" }]);
    expect(
      (await sql("SELECT queued,delivered FROM delivery_state WHERE id=1"))
        .results,
    ).toEqual([{ queued: 1, delivered: 7 }]);
    expect(
      (await sql("SELECT id FROM users WHERE id=?", [user.id])).results,
    ).toHaveLength(1);
  });

  it("registers an ordinary user, preserves its stable handle, and requires a fresh signature to log in", async () => {
    const { browser, authenticator } = await signup();
    const user = (await sql("SELECT * FROM users WHERE username_key='alice'"))
      .results[0];
    expect(user.admin).toBe(0);
    expect(user.user_handle).toBe(authenticator.userHandle);
    expect((await browser.json("/api/me")).authenticated).toBe(true);
    const staleCookie = browser.cookie;
    expect((await browser.request("/api/logout", "POST", {})).status).toBe(200);
    const fresh = new Browser();
    fresh.cookie = staleCookie;
    expect((await fresh.json("/api/me")).authenticated).toBe(false);
    const { options, flow } = await loginOptions(fresh);
    const response = await fresh.json("/auth/passkey/verify", "POST", {
      credential: authenticator.assertion(options),
      authFlowToken: flow,
    });
    expect(response.ok).toBe(true);
    expect((await fresh.json("/api/me")).authenticated).toBe(true);
    expect(
      (await sql("SELECT user_handle FROM users WHERE id=?", [user.id]))
        .results[0].user_handle,
    ).toBe(authenticator.userHandle);
  });

  it("does not accept a client origin, challenge or user handle that differs from the server ceremony", async () => {
    const { authenticator } = await signup();
    for (const changes of [
      { origin: "https://evil.test" },
      { challenge: randomBytes(32).toString("base64url") },
      { userHandle: "wrong-handle" },
    ]) {
      const browser = new Browser(),
        { options, flow } = await loginOptions(browser);
      const response = await browser.request("/auth/passkey/verify", "POST", {
        credential: authenticator.assertion(options, changes),
        authFlowToken: flow,
      });
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect((await browser.json("/api/me")).authenticated).toBe(false);
    }
    const failures = (
      await sql(
        "SELECT result,sub_snapshot FROM login_history WHERE result!='success'",
      )
    ).results;
    expect(failures.length).toBeGreaterThan(0);
    expect(
      failures.every(
        (row: any) =>
          row.result === "failure" &&
          row.sub_snapshot === authenticator.userHandle,
      ),
    ).toBe(true);
  });

  it("allows one verification when the same registration is submitted concurrently", async () => {
    const browser = new Browser(),
      authenticator = new Authenticator();
    await browser.json("/api/ui/intent", "POST", { intent: "register" });
    const options = (
      await browser.json("/api/register/options", "POST", {
        username: "Concurrent",
      })
    ).publicKey;
    const credential = authenticator.registration(options),
      cookie = browser.cookie;
    const responses = await Promise.all(
      Array.from({ length: 6 }, () =>
        fetch(`${address}/api/register/verify`, {
          method: "POST",
          headers: { origin, cookie, "content-type": "application/json" },
          body: JSON.stringify({ credential }),
        }),
      ),
    );
    expect(
      responses.filter((response) => response.status === 200),
    ).toHaveLength(1);
    expect(
      responses.filter(
        (response) => response.status >= 400 && response.status < 500,
      ),
    ).toHaveLength(5);
    expect(
      (await sql("SELECT id FROM users WHERE username_key='concurrent'"))
        .results,
    ).toHaveLength(1);
    expect((await sql("SELECT id FROM credentials")).results).toHaveLength(1);
    expect((await sql("SELECT * FROM operation_guards")).results).toHaveLength(
      0,
    );
  });

  it("rechecks registration closure before the verified credential creates an identity", async () => {
    const browser = new Browser(),
      authenticator = new Authenticator();
    await browser.json("/api/ui/intent", "POST", { intent: "register" });
    const options = (
      await browser.json("/api/register/options", "POST", { username: "Late" })
    ).publicKey;
    await sql(
      "UPDATE app_settings SET setting_value='closed' WHERE setting_key='registration_mode'",
    );
    const response = await browser.request("/api/register/verify", "POST", {
      credential: authenticator.registration(options),
    });
    expect(response.status).toBe(403);
    expect(
      (await sql("SELECT id FROM users WHERE username_key='late'")).results,
    ).toHaveLength(0);
  });

  it("revokes existing opaque sessions through the user version and disabled state", async () => {
    const { browser } = await signup();
    await sql("UPDATE users SET session_version=session_version+1");
    expect((await browser.json("/api/me")).authenticated).toBe(false);
    const next = await signup("Disabled");
    await sql(
      "UPDATE users SET disabled_at=unixepoch() WHERE username_key='disabled'",
    );
    expect((await next.browser.json("/api/me")).authenticated).toBe(false);
  });

  it("rejects cross-origin mutations before creating a registration ceremony", async () => {
    const browser = new Browser();
    const response = await browser.request(
      "/api/ui/intent",
      "POST",
      { intent: "register" },
      { origin: "https://evil.test" },
    );
    expect(response.status).toBe(403);
    expect((await sql("SELECT id FROM ceremonies")).results).toHaveLength(0);
  });

  it("does not give management freshness to a presence-only login", async () => {
    const { authenticator } = await signup();
    const browser = new Browser(),
      { options, flow } = await loginOptions(browser);
    await browser.json("/auth/passkey/verify", "POST", {
      credential: authenticator.assertion(options, { userVerified: false }),
      authFlowToken: flow,
    });
    const tokenHash = hash(browser.cookie.slice("session=".length));
    expect(
      (
        await sql(
          "SELECT reauthenticated_at FROM sessions WHERE token_hash=?",
          [tokenHash],
        )
      ).results[0].reauthenticated_at,
    ).toBeNull();
  });

  it("binds OAuth completion to state and fresh authentication, then exchanges a code exactly once", async () => {
    const { browser, authenticator } = await signup();
    const { code, verifier, values } = await authorization(
      browser,
      authenticator,
    );
    expect(
      (await browser.request("/oauth/authorize/complete", "POST", values))
        .status,
    ).toBeGreaterThanOrEqual(400);
    expect((await exchange(browser, code, "x".repeat(43))).status).toBe(400);
    expect(
      (
        await exchange(browser, code, verifier, {
          redirect_uri: "https://evil.test/callback",
        })
      ).status,
    ).toBe(400);
    const results = await Promise.all(
      Array.from({ length: 8 }, () => exchange(browser, code, verifier)),
    );
    expect(results.filter((response) => response.status === 200)).toHaveLength(
      1,
    );
    expect(results.filter((response) => response.status === 400)).toHaveLength(
      7,
    );
    const token = (
      (await results.find((response) => response.status === 200)!.json()) as any
    ).access_token;
    const info = await browser.request("/oauth/userinfo", "GET", undefined, {
      authorization: "Bearer " + token,
    });
    expect(info.status).toBe(200);
    expect(await info.json()).toMatchObject({
      username: "Alice",
      sub: authenticator.userHandle,
    });
    await sql(
      "UPDATE users SET session_version=session_version+1 WHERE username_key='alice'",
    );
    expect(
      (
        await browser.request("/oauth/userinfo", "GET", undefined, {
          authorization: "Bearer " + token,
        })
      ).status,
    ).toBe(401);
  });

  it("denies a code exchange revoked between validation and its atomic consumption", async () => {
    const { browser, authenticator } = await signup();
    const { code, verifier } = await authorization(browser, authenticator);
    const response = await browser.request(
      "/oauth/token",
      "POST",
      {
        grant_type: "authorization_code",
        client_id: "ppq-test",
        client_secret: "test-client-secret",
        redirect_uri: callback,
        code,
        code_verifier: verifier,
      },
      {
        "x-test-before-batch-sql":
          "UPDATE users SET session_version=session_version+1 WHERE username_key='alice'",
      },
    );
    expect(response.status).toBe(400);
    expect(
      (
        await sql("SELECT consumed_at FROM oauth_codes WHERE code_hash=?", [
          hash(code!),
        ])
      ).results[0].consumed_at,
    ).toBeNull();
    expect(
      (await sql("SELECT token_hash FROM access_tokens")).results,
    ).toHaveLength(0);
  });

  it("does not accept a link result when permissions change after request preflight", async () => {
    const { browser } = await signup();
    const user = (await sql("SELECT * FROM users WHERE username_key='alice'"))
      .results[0];
    const time = Math.floor(Date.now() / 1000);
    await sql(
      "UPDATE oauth_clients SET is_demo=1,redirect_uris=? WHERE client_id=?",
      [
        JSON.stringify([callback, origin + "/demo/link-login/callback"]),
        "ppq-test",
      ],
    );
    await sql("UPDATE sessions SET data_json=? WHERE token_hash=?", [
      JSON.stringify({ link_login_state: "bound-state" }),
      hash(browser.cookie.slice("session=".length)),
    ]);
    await sql(
      "INSERT INTO oauth_challenges(challenge_id,client_id,return_uri,username,username_key,state,user_id,user_version,result_hash,created_at,expires_at,completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
      [
        "link",
        "ppq-test",
        origin + "/demo/link-login/callback",
        "Alice",
        "alice",
        "bound-state",
        user.id,
        user.session_version,
        hash("result-secret"),
        time,
        time + 300,
        time,
      ],
    );
    const response = await browser.request(
      "/demo/link-login/callback?challenge=link&challenge_result=result-secret&state=bound-state&status=success",
      "GET",
      undefined,
      {
        "x-test-before-batch-sql":
          "UPDATE users SET login=0 WHERE username_key='alice'",
      },
    );
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("invalid_challenge_result");
    expect(
      (
        await sql(
          "SELECT consumed_at FROM oauth_challenges WHERE challenge_id='link'",
        )
      ).results[0].consumed_at,
    ).toBeNull();
  });

  it("supports client-authenticated link challenges and requires a real one-use result instead of status=success", async () => {
    const { browser, authenticator } = await signup();
    const server = new Browser();
    const created = await server.request(
      "/api/server/challenges",
      "POST",
      { return_uri: callback, username: "Alice", state: "server-bound-state" },
      {
        authorization:
          "Basic " +
          Buffer.from("ppq-test:test-client-secret").toString("base64"),
      },
    );
    expect(created.status, await created.clone().text()).toBe(200);
    const { challenge, authorizationUrl, expires_in } =
      (await created.json()) as any;
    expect(expires_in).toBe(300);
    expect(authorizationUrl).toBe(origin + "/oauth/challenge/" + challenge);
    const values = {
      client_id: "ppq-test",
      client_secret: "test-client-secret",
      challenge,
      return_uri: callback,
      state: "server-bound-state",
    };
    expect(
      (
        await server.request("/api/server/challenges/consume", "POST", {
          ...values,
          status: "success",
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await server.request("/api/server/challenges/consume", "POST", {
          ...values,
          challenge_result: "fabricated",
        })
      ).status,
    ).toBe(400);
    expect(
      (await browser.request("/oauth/challenge/" + challenge)).status,
    ).toBe(200);
    const { authFlowToken } = await browser.json(
      "/auth/passkey/flow",
      "POST",
      {},
    );
    const { publicKey } = await browser.json("/auth/passkey/options", "POST", {
      mode: "challenge",
      username: "Alice",
      authFlowToken,
    });
    await browser.json("/auth/passkey/verify", "POST", {
      credential: authenticator.assertion(publicKey),
      authFlowToken,
    });
    const complete = await browser.json(
      "/oauth/challenge/" + challenge + "/complete",
      "POST",
      {},
    );
    const result = new URL(complete.redirectUrl).searchParams.get(
      "challenge_result",
    );
    expect(result).toBeTruthy();
    expect(
      (
        await server.request("/api/server/challenges/consume", "POST", {
          ...values,
          challenge_result: result,
          state: "wrong-state",
        })
      ).status,
    ).toBe(400);
    const responses = await Promise.all(
      Array.from({ length: 6 }, () =>
        server.request("/api/server/challenges/consume", "POST", {
          ...values,
          challenge_result: result,
        }),
      ),
    );
    expect(
      responses.filter((response) => response.status === 200),
    ).toHaveLength(1);
    expect(
      responses.filter((response) => response.status === 400),
    ).toHaveLength(5);
    expect(
      await responses.find((response) => response.status === 200)!.json(),
    ).toMatchObject({
      ok: true,
      authenticated: true,
      user: { username: "Alice", sub: authenticator.userHandle },
    });
  });

  it("rejects an unauthenticated client, an unregistered callback, and empty challenge state", async () => {
    const server = new Browser();
    const data = {
      client_id: "ppq-test",
      client_secret: "test-client-secret",
      return_uri: callback,
      username: "Alice",
      state: "state",
    };
    expect(
      (
        await server.request("/api/server/challenges", "POST", {
          ...data,
          client_secret: "wrong",
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await server.request("/api/server/challenges", "POST", {
          ...data,
          return_uri: "https://evil.test/callback",
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await server.request("/api/server/challenges", "POST", {
          ...data,
          state: "",
        })
      ).status,
    ).toBe(400);
    expect(
      (await sql("SELECT challenge_id FROM oauth_challenges")).results,
    ).toHaveLength(0);
  });

  it("rejects control-character return URLs that browsers would normalize into external navigation", async () => {
    const browser = new Browser();
    for (const returnTo of [
      "/\t/evil.test",
      "//evil.test",
      "/\\evil.test",
      "/\n/evil.test",
    ]) {
      const response = await browser.request(
        "/auth/passkey?" + new URLSearchParams({ return_to: returnTo }),
      );
      expect(response.status).toBe(200);
      expect(await response.text()).toContain('data-return-to="/"');
    }
    const response = await browser.request(
      "/auth/passkey?" +
        new URLSearchParams({ return_to: "/management#users" }),
    );
    expect(await response.text()).toContain(
      'data-return-to="/management#users"',
    );
  });

  it("does not allocate anonymous browser sessions for machine challenge calls", async () => {
    const server = new Browser();
    const response = await server.request("/api/server/challenges", "POST", {
      client_id: "ppq-test",
      client_secret: "wrong",
      return_uri: callback,
      username: "Alice",
      state: "state",
    });
    expect(response.status).toBe(401);
    expect(response.headers.getSetCookie()).toHaveLength(0);
    expect((await sql("SELECT token_hash FROM sessions")).results).toHaveLength(
      0,
    );
  });

  it("allocates a browser session only after a validated stateful interaction", async () => {
    const browser = new Browser();
    for (const [path, status] of [
      ["/", 200],
      ["/api/me", 200],
      ["/missing-page", 404],
      ["/api/management/overview", 401],
      ["/oauth/authorize?client_id=unknown", 400],
    ] as const) {
      const response = await browser.request(path);
      expect(response.status).toBe(status);
      expect(response.headers.getSetCookie()).toHaveLength(0);
    }
    expect(
      (
        await browser.request(
          "/api/ui/intent",
          "POST",
          { intent: "register" },
          { origin: "https://evil.test" },
        )
      ).status,
    ).toBe(403);
    expect((await browser.request("/api/ui/intent", "POST", null)).status).toBe(
      400,
    );
    expect(
      (
        await browser.request("/api/register/options", "POST", {
          username: "Locked",
        })
      ).status,
    ).toBe(403);
    expect((await sql("SELECT token_hash FROM sessions")).results).toHaveLength(
      0,
    );
    expect(browser.cookie).toBe("");
    await browser.json("/api/ui/intent", "POST", { intent: "register" });
    expect(browser.cookie).toMatch(/^session=.+/);
    await browser.json("/auth/passkey/flow", "POST", {});
    const rows = (await sql("SELECT data_json FROM sessions")).results;
    expect(rows).toHaveLength(1);
    expect(JSON.parse(rows[0].data_json)).toMatchObject({
      registration_unlock_expires_at: expect.any(Number),
      auth_flow_token: expect.any(String),
    });
  });

  it("preserves a concurrent management channel when saving an unrelated flow token", async () => {
    const { browser } = await signup();
    const tokenHash = hash(browser.cookie.slice("session=".length));
    const response = await browser.request(
      "/auth/passkey/flow",
      "POST",
      {},
      {
        "x-test-before-run-sql": `UPDATE sessions SET data_json=json_set(data_json,'$.management_channel_id','concurrent-channel') WHERE token_hash='${tokenHash}'`,
      },
    );
    expect(response.status).toBe(200);
    const row = (
      await sql("SELECT data_json FROM sessions WHERE token_hash=?", [
        tokenHash,
      ])
    ).results[0];
    expect(JSON.parse(row.data_json)).toMatchObject({
      management_channel_id: "concurrent-channel",
      auth_flow_token: expect.any(String),
    });
  });

  it("preserves the bound channel during reauthentication and clears it when rotating to a new session", async () => {
    const { browser, authenticator } = await signup();
    const tokenHash = hash(browser.cookie.slice("session=".length));
    const user = (await sql("SELECT id FROM users WHERE username_key='alice'"))
      .results[0];
    await sql(
      "INSERT INTO management_channels(id,user_id,session_hash,public_key_jwk,server_nonce,created_at,expires_at,last_seen_at,ack_after_ms) VALUES (?,?,?,?,?,unixepoch(),unixepoch()+300,unixepoch(),45000)",
      ["channel", user.id, tokenHash, "{}", "nonce"],
    );
    await sql(
      "UPDATE sessions SET data_json=json_set(data_json,'$.management_channel_id','channel') WHERE token_hash=?",
      [tokenHash],
    );
    for (const mode of ["reauth", "login"]) {
      const { authFlowToken } = await browser.json(
        "/auth/passkey/flow",
        "POST",
        {},
      );
      const { publicKey } = await browser.json(
        "/auth/passkey/options",
        "POST",
        { mode, username: "Alice", authFlowToken },
      );
      await browser.json("/auth/passkey/verify", "POST", {
        credential: authenticator.assertion(publicKey),
        authFlowToken,
      });
      const currentHash = hash(browser.cookie.slice("session=".length));
      const row = (
        await sql("SELECT data_json FROM sessions WHERE token_hash=?", [
          currentHash,
        ])
      ).results[0];
      if (mode === "reauth") {
        expect(currentHash).toBe(tokenHash);
        expect(JSON.parse(row.data_json).management_channel_id).toBe("channel");
        expect(
          (await sql("SELECT id FROM management_channels")).results,
        ).toHaveLength(1);
      } else {
        expect(currentHash).not.toBe(tokenHash);
        expect(JSON.parse(row.data_json).management_channel_id).toBeUndefined();
        expect(
          (await sql("SELECT id FROM management_channels")).results,
        ).toHaveLength(0);
      }
    }
  });

  it("accepts an opaque-Origin native form only with same-origin navigation metadata and session CSRF", async () => {
    await sql(
      "UPDATE oauth_clients SET is_demo=1,redirect_uris=? WHERE client_id=?",
      [
        JSON.stringify([callback, origin + "/demo/link-login/callback"]),
        "ppq-test",
      ],
    );
    const browser = new Browser();
    const page = await browser.request("/demo/link-login");
    expect(page.status).toBe(200);
    const csrf = (
      await sql("SELECT csrf_token FROM sessions WHERE token_hash=?", [
        hash(browser.cookie.slice("session=".length)),
      ])
    ).results[0].csrf_token;
    expect(await page.text()).toContain(`name="csrf_token" value="${csrf}"`);
    // Node fetch overwrites Sec-Fetch-Mode with cors. A raw request preserves
    // the browser navigation headers whose server-side checks are under test.
    const submit = (changes: Record<string, string> = {}, token = csrf) =>
      new Promise<Response>((resolve, reject) => {
        const request = httpRequest(
          `${address}/demo/link-login/start`,
          {
            method: "POST",
            headers: {
              cookie: browser.cookie,
              origin: "null",
              "sec-fetch-site": "same-origin",
              "sec-fetch-mode": "navigate",
              "content-type": "application/x-www-form-urlencoded",
              ...changes,
            },
          },
          (response) => {
            const chunks: Buffer[] = [];
            response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
            response.on("end", () =>
              resolve(
                new Response(Buffer.concat(chunks), {
                  status: response.statusCode,
                  headers: {
                    location: String(response.headers.location || ""),
                  },
                }),
              ),
            );
          },
        );
        request.on("error", reject);
        request.end(
          new URLSearchParams({
            username: "Alice",
            csrf_token: token,
          }).toString(),
        );
      });
    expect(
      (
        await submit({
          origin: "https://evil.test",
          "sec-fetch-site": "cross-site",
        })
      ).status,
    ).toBe(403);
    expect((await submit({ "sec-fetch-site": "cross-site" })).status).toBe(403);
    expect((await submit({}, "wrong-csrf")).status).toBe(403);
    const success = await submit();
    expect(success.status).toBe(302);
    expect(success.headers.get("location")).toMatch(
      /^https:\/\/auth\.test\/oauth\/challenge\//,
    );
    expect(
      (await sql("SELECT challenge_id FROM oauth_challenges")).results,
    ).toHaveLength(1);
  });
});
