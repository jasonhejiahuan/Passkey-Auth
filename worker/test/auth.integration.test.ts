import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";
import { request as httpRequest } from "node:http";
import { readFile } from "node:fs/promises";
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

  registration(options: any, credentialOrigin = origin) {
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
      Buffer.from([0x45]),
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
    body: await readFile(
      new URL("../migrations/0001_native_auth.sql", import.meta.url),
      "utf8",
    ),
  });
  expect(response.ok, await response.text()).toBe(true);
}, 30_000);
afterAll(async () => {
  await runtime?.dispose();
});
beforeEach(async () => {
  for (const table of [
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
    expect(options.user.name).toBe("张伟 José Jason 12");
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
