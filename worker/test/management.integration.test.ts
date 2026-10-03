import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
} from "node:crypto";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

const origin = "https://auth.example.com";
const hash = (s: string) => createHash("sha256").update(s).digest("base64url");
let runtime: Miniflare, address: string;
const outbound: {
  url: string;
  method: string;
  body: any;
  headers: Record<string, string>;
}[] = [];
let failBackend = false;
let backendDelay = 0;
async function sql(statement: string, bindings: unknown[] = []): Promise<any> {
  const r = await fetch(address + "/__test/sql", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ statement, bindings }),
  });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}
class Admin {
  token = "action-1";
  constructor(public name = "alice") {}
  async request(
    path: string,
    method = "GET",
    data?: unknown,
    extra: Record<string, string> = {},
  ) {
    return fetch(address + path, {
      method,
      headers: {
        origin,
        cookie: `session=session-${this.name}`,
        "X-CSRF-Token": `csrf-${this.name}`,
        "X-Action-Token": this.token,
        ...(data !== undefined ? { "content-type": "application/json" } : {}),
        ...extra,
      },
      body: data === undefined ? undefined : JSON.stringify(data),
    });
  }
  async json(
    path: string,
    method = "GET",
    data?: unknown,
    extra: Record<string, string> = {},
  ) {
    const r = await this.request(path, method, data, extra),
      p = (await r.json()) as any;
    expect(r.status, JSON.stringify(p)).toBe(200);
    if (p.next_action_token) this.token = p.next_action_token;
    return p;
  }
}
async function configure(data: Record<string, unknown>) {
  const admin = new Admin();
  return admin.json("/api/management/settings/telemetry", "PATCH", {
    enabled: true,
    anonymousEnabled: true,
    defaultFeatures: ["screen"],
    ...data,
  });
}
async function collectionToken() {
  const r = await fetch(address + "/"),
    html = await r.text();
  expect(r.status, html).toBe(200);
  const token = html.match(/data-passkey-telemetry-token="([^"]+)"/)?.[1];
  expect(token).toBeTruthy();
  return token!;
}
function sample(token: string) {
  return {
    token,
    path: "/demo/oauth?access_token=never-store#secret",
    referrerOrigin: "https://site.example.org/private?a=secret",
    features: ["screen"],
    client: { osFamily: "macos", deviceClass: "desktop" },
    signals: { screen: { width: 1440, height: 900, unapproved: "secret" } },
  };
}
async function collect(token: string) {
  return fetch(address + "/api/telemetry/collect", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "User-Agent": "Fixture Chrome/140.0",
    },
    body: JSON.stringify(sample(token)),
  });
}

beforeAll(async () => {
  const bundle = await build({
    stdin: {
      contents: `import app from './src/index.ts';export default {async fetch(request,env,ctx){
    const path=new URL(request.url).pathname;
    if(path==='/__test/sql'){const {statement,bindings}=await request.json();return Response.json(await env.DB.prepare(statement).bind(...bindings).all());}
    if(path==='/__test/migration')return Response.json(await env.DB.batch((await request.text()).replace(/^--.*$/gm,'').split(';').map(s=>s.trim()).filter(Boolean).map(s=>env.DB.prepare(s))));
    const before=request.headers.get('x-test-before-batch-sql');
    if(before){const db=env.DB;let changed=false;env={...env,DB:{prepare:db.prepare.bind(db),async batch(statements){if(!changed){changed=true;await db.prepare(before).run();}return db.batch(statements);}}};}
    globalThis.fetch=(input,init)=>env.OUTBOUND.fetch(new Request(input,init));
    const url=new URL(request.url);return app.fetch(new Request(env.PASSKEY_ORIGIN+url.pathname+url.search,request),env,ctx);
  }};`,
      resolveDir: process.cwd(),
      sourcefile: "management-fixture.ts",
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
      bindings: { PASSKEY_ORIGIN: origin, PASSKEY_RP_ID: "auth.example.com" },
      serviceBindings: {
        ASSETS: () => new Response("", { status: 404 }),
        OUTBOUND: async (request: Request) => {
          const raw = await request.text();
          outbound.push({
            url: request.url,
            method: request.method,
            body: raw ? JSON.parse(raw) : undefined,
            headers: Object.fromEntries(request.headers),
          });
          if (backendDelay)
            await new Promise((resolve) => setTimeout(resolve, backendDelay));
          if (failBackend) return new Response("", { status: 503 });
          const path = new URL(request.url).pathname;
          return Response.json(
            path.endsWith("/challenge")
              ? { challenge_id: "pair-challenge", server_nonce: "server-nonce" }
              : path.endsWith("/complete")
                ? { api_key: "paired-private-key", server_version: "13" }
                : path.endsWith("/browser-collection-token")
                  ? { token: "short-lived-public-token" }
                  : { ok: true },
          );
        },
      },
    }),
  );
  address = String(await runtime.ready).replace(/\/$/, "");
  const r = await fetch(address + "/__test/migration", {
    method: "POST",
    body: await readFile(
      new URL("../migrations/0001_native_auth.sql", import.meta.url),
      "utf8",
    ),
  });
  expect(r.ok, await r.text()).toBe(true);
}, 30000);
afterAll(async () => {
  await runtime?.dispose();
});
beforeEach(async () => {
  failBackend = false;
  backendDelay = 0;
  outbound.length = 0;
  for (const table of [
    "users",
    "sessions",
    "oauth_clients",
    "app_settings",
    "audit_logs",
    "maintenance_events",
    "telemetry_tokens",
    "telemetry_events",
    "telemetry_receipts",
    "delivery_state",
  ])
    await sql(`DELETE FROM ${table}`);
  const time = Math.floor(Date.now() / 1000);
  for (const [id, name, admin] of [
    [1, "alice", 1],
    [2, "bob", 1],
    [3, "learner", 0],
  ]) {
    await sql(
      "INSERT INTO users(id,username,username_key,user_handle,admin,created_at) VALUES(?,?,?,?,?,?)",
      [id, name, name, `handle-${name}`, admin, time],
    );
    await sql(
      "INSERT INTO sessions(token_hash,csrf_token,user_id,user_version,reauthenticated_at,action_token_hash,created_at,expires_at) VALUES(?,?,?,1,?,?,?,?)",
      [
        hash(`session-${name}`),
        `csrf-${name}`,
        id,
        time,
        hash("action-1"),
        time,
        time + 3600,
      ],
    );
  }
});

describe("management authorization with real workerd and D1", () => {
  it("requires administrator, same-origin CSRF, recent authentication and current action token", async () => {
    expect(
      (await new Admin("learner").request("/api/management/overview")).status,
    ).toBe(403);
    const a = new Admin();
    for (const headers of [
      { origin: "https://evil.example.com" },
      { "X-CSRF-Token": "wrong" },
      { "X-Action-Token": "" },
    ])
      expect(
        (
          await a.request(
            "/api/management/settings/registration",
            "PATCH",
            { mode: "open" },
            headers,
          )
        ).status,
      ).toBeGreaterThanOrEqual(400);
    await sql("UPDATE sessions SET reauthenticated_at=0 WHERE user_id=1");
    expect(
      (
        await a.request("/api/management/settings/registration", "PATCH", {
          mode: "open",
        })
      ).status,
    ).toBe(428);
    expect((await sql("SELECT * FROM app_settings")).results).toHaveLength(0);
  });
  it("accepts exactly one concurrent operation and rotates the hash without storing the plaintext token", async () => {
    const a = new Admin(),
      responses = await Promise.all(
        Array.from({ length: 6 }, () =>
          a.request("/api/management/settings/registration", "PATCH", {
            mode: "open",
          }),
        ),
      );
    expect(responses.map((r) => r.status).sort()).toEqual([
      200, 409, 409, 409, 409, 409,
    ]);
    const p = (await responses.find((r) => r.status === 200)!.json()) as any;
    expect(
      (await sql("SELECT action_token_hash FROM sessions WHERE user_id=1"))
        .results[0].action_token_hash,
    ).toBe(hash(p.next_action_token));
    expect((await sql("SELECT * FROM audit_logs")).results).toHaveLength(1);
    expect(
      (
        await a.request("/api/management/settings/registration", "PATCH", {
          mode: "closed",
        })
      ).status,
    ).toBe(409);
  });
  it("rolls back token rotation and every mutation on a uniqueness failure", async () => {
    const a = new Admin();
    expect(
      (await a.request("/api/management/users/3", "PATCH", { username: "bob" }))
        .status,
    ).toBe(409);
    expect(
      (await sql("SELECT username,session_version FROM users WHERE id=3"))
        .results[0],
    ).toEqual({ username: "learner", session_version: 1 });
    expect(
      (await sql("SELECT action_token_hash FROM sessions WHERE user_id=1"))
        .results[0].action_token_hash,
    ).toBe(hash("action-1"));
    await a.json("/api/management/users/3", "PATCH", {
      username: "Learner renamed",
    });
  });
  it("rechecks actor privileges in the write transaction after the request has already authenticated", async () => {
    const a = new Admin();
    const r = await a.request(
      "/api/management/settings/registration",
      "PATCH",
      { mode: "open" },
      { "x-test-before-batch-sql": "UPDATE users SET admin=0 WHERE id=1" },
    );
    expect(r.status).toBe(409);
    expect((await sql("SELECT * FROM app_settings")).results).toHaveLength(0);
    expect(
      (await sql("SELECT action_token_hash FROM sessions WHERE user_id=1"))
        .results[0].action_token_hash,
    ).toBe(hash("action-1"));
  });
  it("protects target state from a concurrent privilege update", async () => {
    const r = await new Admin().request(
      "/api/management/users/3",
      "PATCH",
      { permissions: { demo: false } },
      {
        "x-test-before-batch-sql":
          "UPDATE users SET session_version=session_version+1,admin=1 WHERE id=3",
      },
    );
    expect(r.status).toBe(409);
    expect(
      (await sql("SELECT admin,demo FROM users WHERE id=3")).results[0],
    ).toEqual({ admin: 1, demo: 1 });
  });
  it("cannot remove own access and preserves an administrator under concurrent cross-demotion", async () => {
    const a = new Admin(),
      b = new Admin("bob");
    expect(
      (
        await a.request("/api/management/users/1", "PATCH", {
          permissions: { admin: false },
        })
      ).status,
    ).toBe(409);
    const r = await Promise.all([
      a.request("/api/management/users/2", "PATCH", {
        permissions: { admin: false },
      }),
      b.request("/api/management/users/1", "PATCH", {
        permissions: { admin: false },
      }),
    ]);
    expect(r.filter((x) => x.status === 200)).toHaveLength(1);
    expect(
      (
        await sql(
          "SELECT COUNT(*) n FROM users WHERE admin=1 AND login=1 AND disabled_at IS NULL",
        )
      ).results[0].n,
    ).toBe(1);
  });
  it("keeps the editing administrator logged in after their own safe profile update", async () => {
    const a = new Admin();
    await a.json("/api/management/users/1", "PATCH", {
      username: "Alice renamed",
    });
    const result = await a.json("/api/management/overview");
    expect(result.users.find((u: any) => u.id === 1).username).toBe(
      "Alice renamed",
    );
    await a.json("/api/management/settings/registration", "PATCH", {
      mode: "open",
    });
  });
  it("returns a client secret once, stores only its hash and excludes secrets and credential keys from exports", async () => {
    const a = new Admin(),
      r = await a.json("/api/management/platforms", "POST", {
        clientId: "ppq",
        name: "PPQ",
        redirectUris: ["https://ppq.example.com/callback"],
      });
    expect(
      (await sql("SELECT secret_hash FROM oauth_clients")).results[0]
        .secret_hash,
    ).toBe(hash(r.clientSecret));
    expect(
      JSON.stringify(await a.json("/api/management/overview")),
    ).not.toContain(r.clientSecret);
    const csv = await (
      await a.request("/api/management/export/platforms.csv")
    ).text();
    expect(csv).not.toContain(r.clientSecret);
    expect(csv).not.toContain(hash(r.clientSecret));
  });
  it("leaves a separate maintenance record when an administrator clears audit history", async () => {
    const a = new Admin();
    await a.json("/api/management/settings/registration", "PATCH", {
      mode: "open",
    });
    expect((await a.json("/api/management/logs/audit/count")).count).toBe(1);
    expect(
      (await a.json("/api/management/logs/audit/clear", "POST", {})).deleted,
    ).toBe(1);
    expect((await sql("SELECT * FROM audit_logs")).results).toHaveLength(0);
    expect(
      (await sql("SELECT deleted_count FROM maintenance_events")).results[0]
        .deleted_count,
    ).toBe(1);
  });
  it("persists channel proofs, rejects replay and requires signatures on writes after channel start", async () => {
    const a = new Admin(),
      key = generateKeyPairSync("ec", { namedCurve: "prime256v1" }),
      jwk = key.publicKey.export({ format: "jwk" });
    const channel = await a.json("/api/management/channel/start", "POST", {
      publicKeyJwk: jwk,
    });
    expect(
      (
        await a.request("/api/management/settings/registration", "PATCH", {
          mode: "open",
        })
      ).status,
    ).toBe(409);
    const events = await a.request("/api/management/channel/events"),
      sse = await events.text();
    expect(sse).toContain("event: challenge");
    const payload = JSON.parse(sse.split("data: ")[1].trim());
    const data = {
      channelId: channel.channel_id,
      counter: 1,
      clientNonce: randomBytes(18).toString("base64url"),
      visibility: "visible",
      effectiveType: "4g",
      saveData: false,
      rttMs: 0,
      signature: "",
    };
    const message = [
      "passkey-management-channel-v1",
      "ack",
      channel.channel_id,
      "1",
      payload.server_nonce,
      data.clientNonce,
      "POST",
      "/api/management/channel/ack",
      "visible",
      "4g",
      "0",
      "0",
    ].join("\n");
    data.signature = sign("sha256", Buffer.from(message), {
      key: key.privateKey,
      dsaEncoding: "ieee-p1363",
    }).toString("base64url");
    await a.json("/api/management/channel/ack", "POST", data);
    expect(
      (await a.request("/api/management/channel/ack", "POST", data)).status,
    ).toBe(409);
    expect(
      (await sql("SELECT last_counter FROM management_channels")).results[0]
        .last_counter,
    ).toBe(1);
    const nonce = randomBytes(18).toString("base64url"),
      writePath = "/api/management/settings/registration";
    const writeMessage = [
      "passkey-management-channel-v1",
      "write",
      channel.channel_id,
      "2",
      payload.server_nonce,
      nonce,
      "PATCH",
      writePath,
      "visible",
      "4g",
      "0",
      "",
    ].join("\n");
    const headers = {
      "X-Management-Channel-Id": channel.channel_id,
      "X-Management-Channel-Counter": "2",
      "X-Management-Channel-Client-Nonce": nonce,
      "X-Management-Channel-Signature": sign(
        "sha256",
        Buffer.from(writeMessage),
        { key: key.privateKey, dsaEncoding: "ieee-p1363" },
      ).toString("base64url"),
      "X-Management-Channel-Visibility": "visible",
      "X-Management-Channel-Effective-Type": "4g",
      "X-Management-Channel-Save-Data": "0",
    };
    await a.json(writePath, "PATCH", { mode: "open" }, headers);
    expect(
      (await a.request(writePath, "PATCH", { mode: "closed" }, headers)).status,
    ).toBe(409);
  });
});

describe("telemetry policies and optional external integrations", () => {
  it("off leaves HTML and all collection tables untouched", async () => {
    const html = await (await fetch(address + "/")).text();
    expect(html).not.toContain("/static/telemetry.js");
    expect((await collect("arbitrary")).status).toBe(404);
    for (const table of [
      "telemetry_tokens",
      "telemetry_events",
      "telemetry_receipts",
      "delivery_state",
    ])
      expect((await sql(`SELECT COUNT(*) n FROM ${table}`)).results[0].n).toBe(
        0,
      );
    expect(outbound).toHaveLength(0);
  });
  it("collects once under concurrency, strips unauthorised fields and excludes URL query secrets", async () => {
    await configure({});
    const token = await collectionToken();
    const responses = await Promise.all(
        Array.from({ length: 6 }, () => collect(token)),
      ),
      payloads = (await Promise.all(responses.map((r) => r.json()))) as any[];
    expect(responses.every((r) => r.status === 202)).toBe(true);
    expect(payloads.filter((p) => !p.duplicate)).toHaveLength(1);
    const event = (await sql("SELECT * FROM telemetry_events")).results[0];
    expect(event.path).toBe("/demo/oauth");
    expect(event.referrer_origin).toBe("https://site.example.org");
    expect(event.signals).not.toContain("unapproved");
    expect(event.signals).not.toContain("secret");
    expect(event.token_id).toBe(hash(token));
    const view = await new Admin().json("/api/management/telemetry");
    expect(view.statistics.summary.total).toBe(1);
    expect(view.charts.operatingSystems).toEqual([
      { label: "macos", count: 1 },
    ]);
  });
  it("rejects expired and stale-policy tokens without recording data", async () => {
    await configure({});
    const token = await collectionToken();
    await sql("UPDATE telemetry_tokens SET expires_at=0");
    expect((await collect(token)).status).toBe(410);
    const next = await collectionToken();
    await sql(
      "UPDATE app_settings SET setting_value=json_set(setting_value,'$.revision','changed') WHERE setting_key='telemetry_config'",
    );
    expect((await collect(next)).status).toBe(409);
    expect((await sql("SELECT * FROM telemetry_events")).results).toHaveLength(
      0,
    );
  });
  it("counts only the last 24 hours in the overview while preserving complete history after collection is switched off", async () => {
    await configure({});
    const token = await collectionToken();
    expect((await collect(token)).status).toBe(202);
    await sql(
      "INSERT INTO telemetry_events(token_id,policy_key,path,payload_bytes,created_at) VALUES(?,?,?,?,?)",
      [
        "historical-token",
        "historical-policy",
        "/older-visit",
        1,
        Math.floor(Date.now() / 1000) - 86460,
      ],
    );
    const admin = new Admin("bob");
    expect(
      (await admin.json("/api/management/overview")).summary.telemetry24h.value,
    ).toBe(1);
    await admin.json("/api/management/settings/telemetry", "PATCH", {
      enabled: false,
      anonymousEnabled: false,
      defaultFeatures: ["screen"],
    });
    const page = await (await fetch(address + "/")).text();
    expect(page).not.toContain("/static/telemetry.js");
    expect((await collect(token)).status).toBe(404);
    expect(
      (await admin.json("/api/management/overview")).summary.telemetry24h.value,
    ).toBe(1);
    const history = await admin.json("/api/management/telemetry");
    expect(history.statistics.summary).toMatchObject({ total: 2, last24h: 1 });
    expect(history.statistics.recent).toHaveLength(2);
    expect(history.charts.features).toEqual([{ label: "screen", count: 1 }]);
    expect(
      await (
        await admin.request("/api/management/export/telemetry.csv")
      ).text(),
    ).toContain("/demo/oauth");
    await admin.json("/api/management/telemetry/events/clear", "POST", {});
    const audit = (
      await sql("SELECT details FROM audit_logs WHERE action='telemetry.clear'")
    ).results[0];
    expect(JSON.parse(audit.details).deleted).toBe(2);
    expect(
      (await admin.json("/api/management/overview")).summary.telemetry24h.value,
    ).toBe(0);
  });
  it("checks a policy revocation inside the token-consumption transaction", async () => {
    await configure({});
    const token = await collectionToken();
    const r = await fetch(address + "/api/telemetry/collect", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-test-before-batch-sql":
          "UPDATE app_settings SET setting_value=json_set(setting_value,'$.enabled',0) WHERE setting_key='telemetry_config'",
      },
      body: JSON.stringify(sample(token)),
    });
    expect(r.status).toBe(409);
    expect((await sql("SELECT * FROM telemetry_events")).results).toHaveLength(
      0,
    );
  });
  it("masks secrets and rejects private authentication in browser-direct mode", async () => {
    await configure({
      backend: "custom",
      customUrl: "https://telemetry.example.com/events",
      customAuthMode: "bearer",
      customSecret: "private-server-secret",
      customHeaders: { "X-Api-Key": "other-private-secret" },
    });
    const a = new Admin();
    const text = JSON.stringify(await a.json("/api/management/telemetry"));
    expect(text).not.toContain("private-server-secret");
    expect(text).not.toContain("other-private-secret");
    a.token = (
      await sql("SELECT action_token_hash FROM sessions WHERE user_id=1")
    ).results[0].action_token_hash;
    // Invalid configurations are tested with a fresh admin token to isolate validation.
    const b = new Admin("bob");
    const r = await b.request("/api/management/settings/telemetry", "PATCH", {
      enabled: true,
      anonymousEnabled: true,
      defaultFeatures: ["screen"],
      backend: "custom",
      deliveryMode: "direct",
      customUrl: "https://telemetry.example.com/events",
      customAuthMode: "bearer",
      customSecret: "secret",
    });
    expect(r.status).toBe(400);
  });
  it("relays asynchronously, preserves external payload shape, and keeps private keys out of the response", async () => {
    await configure({
      backend: "custom",
      customUrl: "https://telemetry.example.com/events",
      customAuthMode: "bearer",
      customSecret: "server-only-key",
    });
    const token = await collectionToken(),
      r = await collect(token);
    expect(r.status).toBe(202);
    expect(await r.json()).toMatchObject({ queued: true, duplicate: false });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(outbound).toHaveLength(1);
    expect(outbound[0].headers.authorization).toBe("Bearer server-only-key");
    expect(outbound[0].body).toMatchObject({
      event: "passkey_auth.browser_telemetry",
      schema_version: 1,
      subject: { anonymous: true, user_id: null },
      telemetry: { client: { os_family: "macos" } },
    });
    const status = await new Admin().json("/api/management/telemetry");
    expect(status.settings.delivery.sent).toBe(1);
    expect(status.statistics.summary.total).toBe(0);
    expect((await sql("SELECT * FROM telemetry_events")).results).toHaveLength(
      0,
    );
  });
  it("pairs Jason using two HMAC proofs without exposing the negotiated API key", async () => {
    const a = new Admin();
    const r = await a.json(
      "/api/management/telemetry/backend/pair-jason",
      "POST",
      {
        baseUrl: "https://telemetry.example.com",
        pairingCode: "one-time-code",
        deliveryMode: "direct",
      },
    );
    expect(r).toMatchObject({ apiKeyConfigured: true, serverVersion: "13" });
    expect(JSON.stringify(r)).not.toContain("paired-private-key");
    expect(outbound).toHaveLength(2);
    expect(outbound[0].body).toHaveProperty("proof");
    expect(JSON.stringify(outbound)).not.toContain("one-time-code");
    expect(
      (await a.json("/api/management/telemetry")).settings.jason
        .apiKeyConfigured,
    ).toBe(true);
  });
  it("reserves a management capability before external pairing so concurrent replay makes only one outbound handshake", async () => {
    backendDelay = 30;
    const a = new Admin();
    const responses = await Promise.all(
      Array.from({ length: 5 }, () =>
        a.request("/api/management/telemetry/backend/pair-jason", "POST", {
          baseUrl: "https://telemetry.example.com",
          pairingCode: "one-time-code",
        }),
      ),
    );
    expect(responses.map((r) => r.status).sort()).toEqual([
      200, 409, 409, 409, 409,
    ]);
    expect(outbound).toHaveLength(2);
  });
  it("restores the previous management capability after a failed external operation", async () => {
    failBackend = true;
    const a = new Admin();
    expect(
      (
        await a.request(
          "/api/management/telemetry/backend/pair-jason",
          "POST",
          {
            baseUrl: "https://telemetry.example.com",
            pairingCode: "one-time-code",
          },
        )
      ).status,
    ).toBe(502);
    expect(
      (await sql("SELECT action_token_hash FROM sessions WHERE user_id=1"))
        .results[0].action_token_hash,
    ).toBe(hash(a.token));
    failBackend = false;
    await a.json("/api/management/settings/registration", "PATCH", {
      mode: "open",
    });
  });
  it("does not start an external handshake if actor permission is revoked before the reservation commits", async () => {
    const r = await new Admin().request(
      "/api/management/telemetry/backend/pair-jason",
      "POST",
      {
        baseUrl: "https://telemetry.example.com",
        pairingCode: "one-time-code",
      },
      { "x-test-before-batch-sql": "UPDATE users SET admin=0 WHERE id=1" },
    );
    expect(r.status).toBe(409);
    expect(outbound).toHaveLength(0);
  });
  it("returns one short-lived Jason direct target and rejects token reuse", async () => {
    await configure({
      backend: "jason",
      deliveryMode: "direct",
      jasonBaseUrl: "https://telemetry.example.com",
      jasonApiKey: "private-jason-key",
    });
    const token = await collectionToken(),
      request = () =>
        fetch(address + "/api/telemetry/direct-target", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ token }),
        });
    const r = await request(),
      p = (await r.json()) as any;
    expect(r.status, JSON.stringify(p)).toBe(200);
    expect(p.target.url).toBe(
      "https://telemetry.example.com/v12/browser/short-lived-public-token/device-info-submit",
    );
    expect(JSON.stringify(p)).not.toContain("private-jason-key");
    expect((await request()).status).toBe(409);
    expect(outbound).toHaveLength(1);
  });
  it("never reuses a direct collection token after an ambiguous external failure", async () => {
    await configure({
      backend: "jason",
      deliveryMode: "direct",
      jasonBaseUrl: "https://telemetry.example.com",
      jasonApiKey: "private-jason-key",
    });
    const token = await collectionToken();
    failBackend = true;
    const request = () =>
      fetch(address + "/api/telemetry/direct-target", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token }),
      });
    expect((await request()).status).toBe(503);
    failBackend = false;
    expect((await request()).status).toBe(409);
    expect(outbound).toHaveLength(1);
  });
  it("enforces the external queue bound atomically and ignores expired jobs from terminated Workers", async () => {
    await configure({
      backend: "custom",
      customUrl: "https://telemetry.example.com/events",
    });
    const tokens = await Promise.all([collectionToken(), collectionToken()]);
    const time = Math.floor(Date.now() / 1000);
    await sql(
      "INSERT INTO telemetry_receipts(token_id,expires_at,state) SELECT value,?,'queued' FROM json_each(?)",
      [
        time + 60,
        JSON.stringify(Array.from({ length: 127 }, (_, i) => `queue-${i}`)),
      ],
    );
    backendDelay = 150;
    const responses = await Promise.all(tokens.map(collect)),
      payloads = (await Promise.all(responses.map((r) => r.json()))) as any[];
    expect(payloads.filter((p) => p.queued)).toHaveLength(1);
    expect(payloads.filter((p) => p.dropped)).toHaveLength(1);
    await new Promise((resolve) => setTimeout(resolve, 180));
    backendDelay = 0;
    await sql("UPDATE telemetry_receipts SET expires_at=0");
    const next = await collectionToken(),
      r = await collect(next);
    expect(await r.json()).toMatchObject({ queued: true, dropped: false });
    await new Promise((resolve) => setTimeout(resolve, 30));
  });
  it("rejects local, IP, credential-bearing and non-HTTPS integration URLs before making any outbound request", async () => {
    const a = new Admin();
    for (const url of [
      "http://public.example.com",
      "https://127.0.0.1",
      "https://[::1]",
      "https://2130706433",
      "https://metadata.google.internal",
      "https://private.local",
      "https://user:secret@public.example.com",
    ]) {
      expect(
        (
          await a.request(
            "/api/management/telemetry/backend/pair-jason",
            "POST",
            { baseUrl: url, pairingCode: "code" },
          )
        ).status,
      ).toBe(400);
    }
    expect(outbound).toHaveLength(0);
  });
});
