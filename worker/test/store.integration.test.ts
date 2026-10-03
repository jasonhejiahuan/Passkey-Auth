import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

// Execute the real Store inside workerd, against Miniflare's D1 binding.
// This privileged fixture is bundled only for tests; it is never an app route.
type Statement = { sql: string; bindings?: unknown[] };
type Result = {
  results: Record<string, unknown>[];
  meta: { changes: number; rows_read: number; rows_written: number };
};
let runtime: Miniflare;
let address: string;
const now = 1_800_000_000;

async function request(path: string, data: unknown) {
  return fetch(`${address}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(data),
  });
}
async function sql(
  statement: string,
  bindings: unknown[] = [],
): Promise<Result> {
  const response = await request("/sql", { sql: statement, bindings });
  if (!response.ok) throw new Error(await response.text());
  return response.json() as Promise<Result>;
}
async function guard(
  condition: string,
  bindings: unknown[],
  statements: Statement[],
) {
  return request("/guard", { condition, bindings, statements });
}
async function count(table: string) {
  return Number((await sql(`SELECT COUNT(*) AS n FROM ${table}`)).results[0].n);
}

const adminCondition = `EXISTS (
  SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id
  WHERE s.token_hash=? AND s.action_token_hash=? AND s.expires_at>?
    AND s.reauthenticated_at>=? AND s.user_version=u.session_version
    AND u.admin=1 AND u.login=1 AND u.disabled_at IS NULL
)`;
function managementWrite(
  session: string,
  writes: Statement[],
  token = "current",
) {
  return guard(
    adminCondition,
    [session, token, now, now - 300],
    [
      {
        sql: "UPDATE sessions SET action_token_hash=? WHERE token_hash=?",
        bindings: ["next", session],
      },
      ...writes,
    ],
  );
}

beforeAll(async () => {
  const bundle = await build({
    stdin: {
      contents: `import {Store,StoreConflict} from './src/store.ts';
      export default {async fetch(request,env){
        const store=new Store(env.DB), path=new URL(request.url).pathname;
        try {
          if(path==='/migration')return Response.json(await env.DB.batch((await request.text())
            .replace(/^--.*$/gm,'').split(';').map(sql=>sql.trim()).filter(Boolean).map(sql=>env.DB.prepare(sql))));
          const body=await request.json();
          if(path==='/sql')return Response.json(await env.DB.prepare(body.sql).bind(...(body.bindings??[])).all());
          if(path==='/guard')return Response.json(await store.guardBatch(body.condition,body.bindings,
            body.statements.map(s=>env.DB.prepare(s.sql).bind(...(s.bindings??[])))));
          if(path==='/methods')return Response.json({
            one:await store.one('SELECT username FROM users WHERE id=?',1),
            all:await store.all('SELECT username FROM users ORDER BY id'),
            missing:await store.one('SELECT username FROM users WHERE id=?',999),
            empty:await store.batch([]),
          });
          return new Response('Unknown fixture route',{status:404});
        } catch(error) {
          return Response.json({name:error.name,error:String(error)}, {status:error instanceof StoreConflict?409:500});
        }
      }};`,
      resolveDir: process.cwd(),
      sourcefile: "store-fixture.ts",
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
      script: bundle.outputFiles[0].text,
      d1Databases: ["DB"],
    }),
  );
  address = String(await runtime.ready).replace(/\/$/, "");
  const response = await fetch(`${address}/migration`, {
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
  expect(await count("operation_guards")).toBe(0);
  await sql("DELETE FROM users");
  await sql("DELETE FROM oauth_clients");
  await sql("DELETE FROM admin_recovery_tokens");
  await sql("DELETE FROM app_settings");
  await sql("DELETE FROM audit_logs");
  for (const [id, name, admin] of [
    [1, "alice", 1],
    [2, "bob", 1],
    [3, "learner", 0],
  ] as const) {
    await sql(
      "INSERT INTO users(id,username,username_key,user_handle,admin,created_at) VALUES (?,?,?,?,?,?)",
      [id, name, name, `stable-handle-${name}`, admin, now],
    );
    await sql(
      "INSERT INTO sessions(token_hash,csrf_token,user_id,user_version,reauthenticated_at,action_token_hash,created_at,expires_at) VALUES (?,?,?,1,?,?,?,?)",
      [`session-${name}`, `csrf-${name}`, id, now, "current", now, now + 3600],
    );
  }
});

describe("Store running in workerd with actual D1", () => {
  it("returns rows and missing values without an implicit SQLite connection", async () => {
    const response = await request("/methods", {});
    expect(await response.json()).toEqual({
      one: { username: "alice" },
      all: [
        { username: "alice" },
        { username: "bob" },
        { username: "learner" },
      ],
      missing: null,
      empty: [],
    });
  });

  it("evaluates rejected authorization inside the transaction and discards every write", async () => {
    const response = await guard(
      "0",
      [],
      [
        {
          sql: "INSERT INTO app_settings(setting_key,setting_value,updated_at) VALUES ('protected','changed',?)",
          bindings: [now],
        },
      ],
    );
    expect(response.status, await response.clone().text()).toBe(409);
    expect(await response.json()).toMatchObject({ name: "StoreConflict" });
    expect(await count("app_settings")).toBe(0);
    expect(await count("operation_guards")).toBe(0);
  });

  it("returns only business results and removes the temporary authorization receipt", async () => {
    const response = await guard(
      "EXISTS(SELECT 1 FROM users WHERE id=?)",
      [1],
      [
        {
          sql: "UPDATE users SET username=? WHERE id=? RETURNING user_handle",
          bindings: ["Alice renamed", 1],
        },
        { sql: "SELECT username FROM users WHERE id=?", bindings: [1] },
      ],
    );
    expect(response.status, await response.clone().text()).toBe(200);
    const results = (await response.json()) as Result[];
    expect(results).toHaveLength(2);
    expect(results[0].results).toEqual([
      { user_handle: "stable-handle-alice" },
    ]);
    expect(results[1].results).toEqual([{ username: "Alice renamed" }]);
    expect(await count("operation_guards")).toBe(0);
  });

  it("rolls back token rotation and earlier writes when a later constraint fails", async () => {
    const response = await managementWrite("session-alice", [
      {
        sql: "UPDATE users SET username=? WHERE id=?",
        bindings: ["Uncommitted name", 3],
      },
      {
        sql: "INSERT INTO users(username,username_key,user_handle,created_at) VALUES (?,?,?,?)",
        bindings: ["duplicate", "duplicate", "stable-handle-alice", now],
      },
    ]);
    expect(response.status).toBe(500);
    expect(
      (await sql("SELECT username FROM users WHERE id=3")).results[0].username,
    ).toBe("learner");
    expect(
      (
        await sql(
          "SELECT action_token_hash FROM sessions WHERE token_hash='session-alice'",
        )
      ).results[0].action_token_hash,
    ).toBe("current");
    expect(await count("operation_guards")).toBe(0);
    const retry = await managementWrite("session-alice", [
      {
        sql: "UPDATE users SET username=? WHERE id=?",
        bindings: ["Committed name", 3],
      },
    ]);
    expect(retry.status, await retry.text()).toBe(200);
  });

  it("allows only one simultaneous use of an action token", async () => {
    const responses = await Promise.all(
      Array.from({ length: 12 }, () =>
        managementWrite("session-alice", [
          {
            sql: "INSERT INTO audit_logs(actor_user_id,action,created_at) VALUES (1,'one protected change',?)",
            bindings: [now],
          },
        ]),
      ),
    );
    expect(
      responses.filter((response) => response.status === 200),
    ).toHaveLength(1);
    expect(
      responses.filter((response) => response.status === 409),
    ).toHaveLength(11);
    expect(await count("audit_logs")).toBe(1);
    expect(await count("operation_guards")).toBe(0);
  });

  it("denies a prepared request after its actor is revoked, disabled, or reauth expires", async () => {
    for (const mutation of [
      "UPDATE users SET session_version=session_version+1 WHERE id=1",
      "UPDATE users SET admin=0 WHERE id=1",
      "UPDATE users SET login=0 WHERE id=1",
      "UPDATE users SET disabled_at=1 WHERE id=1",
      `UPDATE sessions SET reauthenticated_at=${now - 301} WHERE user_id=1`,
      `UPDATE sessions SET expires_at=${now} WHERE user_id=1`,
    ]) {
      await sql(mutation);
      const response = await managementWrite("session-alice", [
        {
          sql: "UPDATE users SET username=? WHERE id=3",
          bindings: ["Must not change"],
        },
      ]);
      expect(response.status).toBe(409);
      await sql(
        "UPDATE users SET session_version=1,admin=1,login=1,disabled_at=NULL WHERE id=1",
      );
      await sql(
        "UPDATE sessions SET reauthenticated_at=?,expires_at=? WHERE user_id=1",
        [now, now + 3600],
      );
    }
    expect(
      (await sql("SELECT username FROM users WHERE id=3")).results[0].username,
    ).toBe("learner");
  });

  it("serializes two administrators trying to revoke one another", async () => {
    const remove = (actor: string, target: number) =>
      managementWrite(`session-${actor}`, [
        {
          sql: "UPDATE users SET admin=0,session_version=session_version+1 WHERE id=?",
          bindings: [target],
        },
      ]);
    const responses = await Promise.all([remove("alice", 2), remove("bob", 1)]);
    expect(responses.map((response) => response.status).sort()).toEqual([
      200, 409,
    ]);
    expect(
      (
        await sql(
          "SELECT COUNT(*) n FROM users WHERE admin=1 AND login=1 AND disabled_at IS NULL",
        )
      ).results[0].n,
    ).toBe(1);
  });

  it("atomically claims a channel nonce/counter with the protected write", async () => {
    await sql(
      "INSERT INTO management_channels(id,user_id,session_hash,public_key_jwk,server_nonce,created_at,expires_at,last_seen_at) VALUES (?,?,?,?,?,?,?,?)",
      [
        "channel",
        1,
        "session-alice",
        "{}",
        "server-nonce",
        now,
        now + 1800,
        now,
      ],
    );
    const condition = `${adminCondition} AND EXISTS(SELECT 1 FROM management_channels WHERE id=? AND session_hash=? AND user_id=1 AND server_nonce=? AND last_counter<? AND expires_at>? AND last_seen_at>=?)`;
    const parameters = [
      "session-alice",
      "current",
      now,
      now - 300,
      "channel",
      "session-alice",
      "server-nonce",
      1,
      now,
      now - 300,
    ];
    const statements = [
      {
        sql: "UPDATE management_channels SET last_counter=1 WHERE id='channel'",
      },
      {
        sql: "UPDATE sessions SET action_token_hash='next' WHERE token_hash='session-alice'",
      },
      {
        sql: "INSERT INTO audit_logs(action,created_at) VALUES ('channel write',?)",
        bindings: [now],
      },
    ];
    const responses = await Promise.all(
      Array.from({ length: 6 }, () => guard(condition, parameters, statements)),
    );
    expect(
      responses.filter((response) => response.status === 200),
    ).toHaveLength(1);
    expect(
      responses.filter((response) => response.status === 409),
    ).toHaveLength(5);
    expect(await count("audit_logs")).toBe(1);
    expect(
      (
        await sql(
          "SELECT last_counter FROM management_channels WHERE id='channel'",
        )
      ).results[0].last_counter,
    ).toBe(1);
  });

  it("rolls back registration, consumed ceremony and operator grant together", async () => {
    await sql(
      "INSERT INTO ceremonies(id,session_hash,purpose,challenge,username,username_key,user_handle,expires_at) VALUES (?,?,?,?,?,?,?,?)",
      [
        "ceremony",
        "session-learner",
        "recovery",
        "challenge",
        "operator",
        "operator",
        "new-handle",
        now + 300,
      ],
    );
    await sql(
      "INSERT INTO registration_reservations(username_key,ceremony_id,expires_at) VALUES (?,?,?)",
      ["operator", "ceremony", now + 300],
    );
    await sql(
      "INSERT INTO admin_recovery_tokens(token_hash,created_at,expires_at) VALUES (?,?,?)",
      ["operator-issued-hash", now, now + 300],
    );
    await sql(
      "INSERT INTO credentials(user_id,credential_id,public_key,created_at,updated_at) VALUES (?,?,?,?,?)",
      [1, "existing-credential", "public-key", now, now],
    );
    const condition = `EXISTS(SELECT 1 FROM ceremonies WHERE id=? AND session_hash=? AND purpose='recovery' AND consumed_at IS NULL AND expires_at>?)
      AND EXISTS(SELECT 1 FROM registration_reservations WHERE username_key='operator' AND ceremony_id=? AND expires_at>?)
      AND EXISTS(SELECT 1 FROM admin_recovery_tokens WHERE token_hash=? AND consumed_at IS NULL AND expires_at>?)`;
    const bindings = [
      "ceremony",
      "session-learner",
      now,
      "ceremony",
      now,
      "operator-issued-hash",
      now,
    ];
    const writes = (credential: string): Statement[] => [
      {
        sql: "UPDATE ceremonies SET consumed_at=? WHERE id='ceremony'",
        bindings: [now],
      },
      {
        sql: "UPDATE admin_recovery_tokens SET consumed_at=? WHERE token_hash='operator-issued-hash'",
        bindings: [now],
      },
      {
        sql: "INSERT INTO users(username,username_key,user_handle,admin,created_at) VALUES ('operator','operator','new-handle',1,?)",
        bindings: [now],
      },
      {
        sql: "INSERT INTO credentials(user_id,credential_id,public_key,created_at,updated_at) SELECT id,?,'new-public-key',?,? FROM users WHERE username_key='operator'",
        bindings: [credential, now, now],
      },
      {
        sql: "DELETE FROM registration_reservations WHERE username_key='operator'",
      },
    ];
    const failed = await guard(
      condition,
      bindings,
      writes("existing-credential"),
    );
    expect(failed.status).toBe(500);
    expect(
      (await sql("SELECT consumed_at FROM ceremonies WHERE id='ceremony'"))
        .results[0].consumed_at,
    ).toBeNull();
    expect(
      (await sql("SELECT consumed_at FROM admin_recovery_tokens")).results[0]
        .consumed_at,
    ).toBeNull();
    expect(
      (await sql("SELECT id FROM users WHERE username_key='operator'")).results,
    ).toHaveLength(0);
    expect(await count("registration_reservations")).toBe(1);
    const responses = await Promise.all(
      Array.from({ length: 6 }, () =>
        guard(condition, bindings, writes("new-credential")),
      ),
    );
    expect(
      responses.filter((response) => response.status === 200),
    ).toHaveLength(1);
    expect(
      responses.filter((response) => response.status === 409),
    ).toHaveLength(5);
    expect(await count("registration_reservations")).toBe(0);
    expect(await count("operation_guards")).toBe(0);
  });
});
