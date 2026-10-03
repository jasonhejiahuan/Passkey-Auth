import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type { Context, UserRow, SessionRow } from "./types";
import {
  now,
  random,
  hash,
  b64,
  unb64,
  body,
  json,
  redirect,
  HTTPError,
  sameOrigin,
  username,
  usernameKey,
  safeReturn,
  saveData,
  ensureSession,
  cookie,
} from "./security";
import { renderPage, registerClientJavaScript } from "./pages";

export function page(
  c: Context,
  name: string,
  vars: Record<string, unknown> = {},
  status = 200,
) {
  return new Response(renderPage(name, vars), {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}
export async function settings(c: Context) {
  const rows = await c.store.all<{
    setting_key: string;
    setting_value: string;
  }>(
    "SELECT setting_key,setting_value FROM app_settings WHERE setting_key LIKE ? OR setting_key IN (?,?,?)",
    "passkey_%",
    "registration_mode",
    "registration_enabled_until",
    "default_demo_allowed",
  );
  return Object.fromEntries(rows.map((r) => [r.setting_key, r.setting_value]));
}
export const registrationOpen = (s: Record<string, string>) =>
  s.registration_mode === "open" ||
  (s.registration_mode === "temporary" &&
    Number(s.registration_enabled_until) > now());
export const registrationGuard =
  "(EXISTS(SELECT 1 FROM app_settings WHERE setting_key='registration_mode' AND setting_value='open') OR (EXISTS(SELECT 1 FROM app_settings WHERE setting_key='registration_mode' AND setting_value='temporary') AND EXISTS(SELECT 1 FROM app_settings WHERE setting_key='registration_enabled_until' AND CAST(setting_value AS INTEGER)>unixepoch())))";
export async function newFlow(c: Context) {
  c.data.auth_flow_token = random();
  await saveData(c);
  return c.data.auth_flow_token as string;
}
function checkFlow(c: Context, data: any) {
  if (!data.authFlowToken || data.authFlowToken !== c.data.auth_flow_token)
    throw new HTTPError(403, "Passkey 验证页面已过期，请重新打开");
}
export function loginRecord(
  c: Context,
  u: UserRow,
  flow: string,
  result: string,
  client: string | null = null,
  hint: string | null = null,
) {
  return c.env.DB.prepare(
    "INSERT INTO login_history(user_id,username,sub_snapshot,client_id,flow,result,credential_hint,ip_address,user_agent,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
  ).bind(
    u.id,
    u.username,
    u.user_handle,
    client,
    flow,
    result,
    hint,
    c.request.headers.get("cf-connecting-ip") || "",
    c.request.headers.get("user-agent")?.slice(0, 512) || "",
    now(),
  );
}
async function ceremony(c: Context, purpose: string): Promise<any> {
  const id = c.data[`${purpose}_ceremony`];
  if (!id) throw new HTTPError(400, "验证会话已过期，请重新开始");
  const row = await c.store.one<any>(
    "SELECT * FROM ceremonies WHERE id=? AND session_hash=? AND purpose=? AND consumed_at IS NULL AND expires_at>?",
    id,
    c.session.token_hash,
    purpose,
    now(),
  );
  if (!row) throw new HTTPError(400, "验证会话已过期，请重新开始");
  return row;
}
async function rotate(
  c: Context,
  u: UserRow,
  action: string,
  guard: string,
  bindings: any[],
  statements: D1PreparedStatement[],
  reauth = false,
  userVerified = false,
) {
  const time = now(),
    old = c.session.token_hash,
    token = random(),
    next = reauth ? old : await hash(token),
    csrf = reauth ? c.session.csrf_token : random(),
    actionHash = await hash(action);
  const reauthenticatedAt = userVerified ? time : null;
  delete c.data.auth_flow_token;
  delete c.data.authentication_ceremony;
  delete c.data.registration_ceremony;
  if (!reauth) delete c.data.management_channel_id;
  const state = JSON.stringify(c.data);
  if (reauth)
    statements.push(
      c.env.DB.prepare(
        "UPDATE sessions SET reauthenticated_at=?,action_token_hash=?,data_json=json_remove(data_json,'$.auth_flow_token','$.authentication_ceremony','$.registration_ceremony') WHERE token_hash=?",
      ).bind(reauthenticatedAt, actionHash, old),
    );
  else {
    statements.push(
      c.env.DB.prepare(
        "INSERT INTO sessions(token_hash,csrf_token,user_id,user_version,reauthenticated_at,action_token_hash,data_json,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
      ).bind(
        next,
        csrf,
        u.id,
        u.session_version,
        reauthenticatedAt,
        actionHash,
        state,
        time,
        time + 43200,
      ),
    );
    statements.push(
      c.env.DB.prepare(
        "UPDATE oauth_requests SET session_hash=? WHERE session_hash=?",
      ).bind(next, old),
    );
    statements.push(
      c.env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(old),
    );
  }
  await c.store.guardBatch(
    `(${guard}) AND EXISTS(SELECT 1 FROM users WHERE id=? AND session_version=? AND login=1 AND disabled_at IS NULL) AND EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND expires_at>?)`,
    [...bindings, u.id, u.session_version, old, time],
    statements,
  );
  c.user = u;
  c.session = {
    ...c.session,
    token_hash: next,
    csrf_token: csrf,
    user_id: u.id,
    user_version: u.session_version,
    reauthenticated_at: reauthenticatedAt,
    action_token_hash: actionHash,
    data_json: state,
  };
  if (!reauth) cookie(c, token);
}
async function registerOptions(c: Context, data: any, recovery: string | null) {
  const s = await settings(c),
    name = username(data.username),
    key = usernameKey(name),
    time = now();
  if (
    !recovery &&
    (!registrationOpen(s) ||
      Number(c.data.registration_unlock_expires_at || 0) <= time)
  )
    throw new HTTPError(403, "注册入口未解锁或已过期");
  const recoveryHash = recovery ? await hash(recovery) : null;
  if (
    recoveryHash &&
    !(await c.store.one(
      "SELECT token_hash FROM admin_recovery_tokens WHERE token_hash=? AND consumed_at IS NULL AND expires_at>?",
      recoveryHash,
      time,
    ))
  )
    throw new HTTPError(404, "恢复入口不存在或已使用");
  let oauth: any = null;
  if (data.oauth) {
    oauth = await c.store.one<any>(
      "SELECT * FROM oauth_requests WHERE id=? AND session_hash=? AND expires_at>? AND consumed_at IS NULL",
      c.data.oauth_request_id || "",
      c.session.token_hash,
      time,
    );
    if (!oauth || oauth.screen_hint !== "signup" || oauth.username !== name)
      throw new HTTPError(400, "OAuth 注册用户名或会话无效");
  }
  if (await c.store.one("SELECT id FROM users WHERE username_key=?", key))
    throw new HTTPError(409, "用户名已注册");
  const id = random(),
    handle = random(),
    uv = recovery ? "required" : s.passkey_user_verification || "preferred";
  const options = await generateRegistrationOptions({
    rpName: c.env.PASSKEY_RP_NAME || "JSTU Passkey",
    rpID: c.env.PASSKEY_RP_ID,
    userName: name,
    userID: unb64(handle),
    timeout: 60000,
    attestationType: (s.passkey_attestation || "none") as any,
    supportedAlgorithmIDs: JSON.parse(s.passkey_algorithms || "[-7,-8,-257]"),
    authenticatorSelection: {
      residentKey: (s.passkey_resident_key || "required") as any,
      userVerification: uv as any,
      ...(s.passkey_authenticator_attachment &&
      s.passkey_authenticator_attachment !== "any"
        ? { authenticatorAttachment: s.passkey_authenticator_attachment as any }
        : {}),
    },
  });
  options.hints = JSON.parse(
    s.passkey_hints || '["client-device","security-key","hybrid"]',
  );
  const context = JSON.stringify({
    recoveryHash,
    oauthId: oauth?.id || null,
    requireUV: uv === "required",
    algorithms: JSON.parse(s.passkey_algorithms || "[-7,-8,-257]"),
  });
  await ensureSession(c);
  try {
    await c.store.batch([
      c.env.DB.prepare(
        "DELETE FROM registration_reservations WHERE expires_at<=? OR ceremony_id IN(SELECT id FROM ceremonies WHERE session_hash=? AND purpose=?)",
      ).bind(time, c.session.token_hash, "registration"),
      c.env.DB.prepare(
        "DELETE FROM ceremonies WHERE session_hash=? AND purpose=?",
      ).bind(c.session.token_hash, "registration"),
      c.env.DB.prepare(
        "INSERT INTO ceremonies(id,session_hash,purpose,challenge,user_handle,username,username_key,context_json,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
      ).bind(
        id,
        c.session.token_hash,
        "registration",
        options.challenge,
        handle,
        name,
        key,
        context,
        time + 300,
      ),
      c.env.DB.prepare(
        "INSERT INTO registration_reservations(username_key,ceremony_id,expires_at) VALUES(?,?,?)",
      ).bind(key, id, time + 300),
    ]);
  } catch (e) {
    if (String(e).includes("UNIQUE"))
      throw new HTTPError(409, "用户名已注册或正在注册");
    throw e;
  }
  c.data.registration_ceremony = id;
  await saveData(c);
  return json({ publicKey: options });
}
async function registerVerify(c: Context, data: any, recovery: string | null) {
  const r = await ceremony(c, "registration"),
    ctx = JSON.parse(r.context_json),
    s = await settings(c),
    time = now();
  if (
    recovery ? ctx.recoveryHash !== (await hash(recovery)) : !!ctx.recoveryHash
  )
    throw new HTTPError(400, "管理员注册会话已过期");
  if (!recovery && !registrationOpen(s))
    throw new HTTPError(403, "注册功能未启用");
  let result;
  try {
    result = await verifyRegistrationResponse({
      response: data.credential,
      expectedChallenge: r.challenge,
      expectedOrigin: c.env.PASSKEY_ORIGIN,
      expectedRPID: c.env.PASSKEY_RP_ID,
      requireUserVerification: ctx.requireUV,
      supportedAlgorithmIDs: ctx.algorithms,
    });
  } catch {
    throw new HTTPError(400, "Passkey 注册验证失败");
  }
  if (!result.verified || !result.registrationInfo)
    throw new HTTPError(400, "Passkey 注册验证失败");
  const info = result.registrationInfo,
    cred = info.credential,
    action = random(),
    sessionToken = random(),
    sessionHash = await hash(sessionToken),
    csrf = random();
  delete c.data.registration_ceremony;
  delete c.data.auth_flow_token;
  delete c.data.registration_unlock_expires_at;
  delete c.data.management_channel_id;
  const dataJSON = JSON.stringify(c.data);
  const guard = `EXISTS(SELECT 1 FROM ceremonies WHERE id=? AND session_hash=? AND consumed_at IS NULL AND expires_at>?) AND EXISTS(SELECT 1 FROM registration_reservations WHERE username_key=? AND ceremony_id=? AND expires_at>?) AND ${recovery ? "EXISTS(SELECT 1 FROM admin_recovery_tokens WHERE token_hash=? AND consumed_at IS NULL AND expires_at>?)" : registrationGuard}`;
  const binds: any[] = [
    r.id,
    c.session.token_hash,
    time,
    r.username_key,
    r.id,
    time,
  ];
  if (recovery) binds.push(ctx.recoveryHash, time);
  const stmts = [
    c.env.DB.prepare(
      "INSERT INTO users(username,username_key,user_handle,admin,demo,created_at) VALUES(?,?,?,?,?,?)",
    ).bind(
      r.username,
      r.username_key,
      r.user_handle,
      recovery ? 1 : 0,
      recovery ? 1 : s.default_demo_allowed === "false" ? 0 : 1,
      time,
    ),
    c.env.DB.prepare(
      "INSERT INTO credentials(user_id,credential_id,public_key,sign_count,transports,aaguid,credential_type,device_type,backed_up,created_at,updated_at) SELECT id,?,?,?,?,?,?,?,?,?,? FROM users WHERE user_handle=?",
    ).bind(
      cred.id,
      b64(cred.publicKey),
      cred.counter,
      JSON.stringify(cred.transports || []),
      info.aaguid,
      "public-key",
      info.credentialDeviceType,
      info.credentialBackedUp ? 1 : 0,
      time,
      time,
      r.user_handle,
    ),
    c.env.DB.prepare(
      "INSERT INTO sessions(token_hash,csrf_token,user_id,user_version,reauthenticated_at,action_token_hash,data_json,created_at,expires_at) SELECT ?,?,id,session_version,?,?,?,?,? FROM users WHERE user_handle=?",
    ).bind(
      sessionHash,
      csrf,
      info.userVerified ? time : null,
      await hash(action),
      dataJSON,
      time,
      time + 43200,
      r.user_handle,
    ),
    c.env.DB.prepare(
      "UPDATE oauth_requests SET session_hash=?,authenticated_user_id=CASE WHEN id=? THEN (SELECT id FROM users WHERE user_handle=?) ELSE authenticated_user_id END,authenticated_user_version=CASE WHEN id=? THEN 1 ELSE authenticated_user_version END WHERE session_hash=?",
    ).bind(
      sessionHash,
      ctx.oauthId || "",
      r.user_handle,
      ctx.oauthId || "",
      c.session.token_hash,
    ),
    c.env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(
      c.session.token_hash,
    ),
  ];
  if (recovery)
    stmts.push(
      c.env.DB.prepare(
        "UPDATE admin_recovery_tokens SET consumed_at=? WHERE token_hash=?",
      ).bind(time, ctx.recoveryHash),
    );
  stmts.push(
    c.env.DB.prepare(
      "INSERT INTO audit_logs(actor_user_id,actor_username,action,target_type,target_id,created_at) SELECT id,username,?,'user',CAST(id AS TEXT),? FROM users WHERE user_handle=?",
    ).bind(recovery ? "admin.recovery" : "user.register", time, r.user_handle),
  );
  try {
    await c.store.guardBatch(guard, binds, stmts);
  } catch (e) {
    if (String(e).includes("UNIQUE") || (e as Error).name === "StoreConflict")
      throw new HTTPError(409, "用户名已注册或注册会话已过期");
    throw e;
  }
  c.user = await c.store.one<UserRow>(
    "SELECT * FROM users WHERE user_handle=?",
    r.user_handle,
  );
  c.session = (await c.store.one<SessionRow>(
    "SELECT * FROM sessions WHERE token_hash=?",
    sessionHash,
  ))!;
  cookie(c, sessionToken);
  return json({
    ok: true,
    ...(recovery ? { redirectUrl: "/management" } : {}),
    action_token: action,
  });
}
async function loginOptions(c: Context, data: any) {
  checkFlow(c, data);
  const mode = data.mode || "login";
  if (!["login", "reauth", "code", "challenge"].includes(mode))
    throw new HTTPError(400, "无效的 Passkey 验证模式");
  let expected: UserRow | null = mode === "reauth" ? c.user : null,
    oauth: any = null;
  if (mode === "reauth" && !expected)
    throw new HTTPError(401, "登录会话已过期");
  if (mode === "code") {
    oauth = await c.store.one<any>(
      "SELECT * FROM oauth_requests WHERE id=? AND session_hash=? AND expires_at>? AND consumed_at IS NULL",
      c.data.oauth_request_id || "",
      c.session.token_hash,
      now(),
    );
    if (!oauth || (oauth.username && oauth.username !== data.username))
      throw new HTTPError(400, "OAuth 登录用户名不匹配");
  }
  if (!expected && data.username)
    expected = await c.store.one<UserRow>(
      "SELECT * FROM users WHERE username_key=?",
      usernameKey(username(data.username)),
    );
  if (data.username && !expected)
    throw new HTTPError(404, "没有找到这个用户名，请先注册 Passkey");
  if (expected && (expected.disabled_at !== null || !expected.login))
    throw new HTTPError(403, "此账户当前不允许登录");
  const creds = expected
    ? await c.store.all<any>(
        "SELECT credential_id,transports FROM credentials WHERE user_id=?",
        expected.id,
      )
    : null;
  if (creds && !creds.length)
    throw new HTTPError(404, "这个用户还没有注册 Passkey");
  const s = await settings(c),
    uv =
      mode === "reauth"
        ? "required"
        : s.passkey_user_verification || "preferred";
  const options = await generateAuthenticationOptions({
    rpID: c.env.PASSKEY_RP_ID,
    timeout: 60000,
    userVerification: uv as any,
    ...(creds
      ? {
          allowCredentials: creds.map((r) => ({
            id: r.credential_id,
            transports: JSON.parse(r.transports),
          })),
        }
      : {}),
  });
  options.hints = JSON.parse(
    s.passkey_hints || '["client-device","security-key","hybrid"]',
  );
  const id = random(),
    time = now();
  await c.store.batch([
    c.env.DB.prepare(
      "DELETE FROM ceremonies WHERE session_hash=? AND purpose=?",
    ).bind(c.session.token_hash, "authentication"),
    c.env.DB.prepare(
      "INSERT INTO ceremonies(id,session_hash,purpose,challenge,user_id,context_json,expires_at) VALUES(?,?,?,?,?,?,?)",
    ).bind(
      id,
      c.session.token_hash,
      "authentication",
      options.challenge,
      expected?.id || null,
      JSON.stringify({
        mode,
        oauthId: oauth?.id || null,
        requireUV: uv === "required",
        challengeId: c.data.link_challenge_id || null,
      }),
      time + 300,
    ),
  ]);
  c.data.authentication_ceremony = id;
  await saveData(c);
  return json({ publicKey: options });
}
async function loginVerify(c: Context, data: any) {
  checkFlow(c, data);
  const r = await ceremony(c, "authentication"),
    ctx = JSON.parse(r.context_json),
    response = data.credential || {};
  const cred = await c.store.one<any>(
    "SELECT * FROM credentials WHERE credential_id=?",
    response.id || response.rawId || "",
  );
  if (!cred) throw new HTTPError(404, "没有找到对应的 Passkey");
  const u = await c.store.one<UserRow>(
    "SELECT * FROM users WHERE id=?",
    cred.user_id,
  );
  if (
    !u ||
    u.disabled_at !== null ||
    !u.login ||
    (r.user_id && r.user_id !== u.id) ||
    (response.response?.userHandle &&
      response.response.userHandle !== u.user_handle)
  )
    throw new HTTPError(403, "Passkey 的用户句柄和凭据归属不一致");
  let result;
  try {
    result = await verifyAuthenticationResponse({
      response,
      expectedChallenge: r.challenge,
      expectedOrigin: c.env.PASSKEY_ORIGIN,
      expectedRPID: c.env.PASSKEY_RP_ID,
      requireUserVerification: ctx.requireUV,
      credential: {
        id: cred.credential_id,
        publicKey: unb64(cred.public_key),
        counter: cred.sign_count,
        transports: JSON.parse(cred.transports),
      },
    });
  } catch {
    await c.store.batch([
      c.env.DB.prepare(
        "UPDATE ceremonies SET consumed_at=? WHERE id=? AND consumed_at IS NULL",
      ).bind(now(), r.id),
      loginRecord(
        c,
        u,
        "passkey",
        "failure",
        null,
        cred.credential_id.slice(0, 16),
      ),
    ]);
    throw new HTTPError(400, "Passkey 验证失败");
  }
  if (!result.verified) throw new HTTPError(400, "Passkey 验证失败");
  const action = random(),
    time = now();
  const stmts = [
    c.env.DB.prepare("UPDATE ceremonies SET consumed_at=? WHERE id=?").bind(
      time,
      r.id,
    ),
    c.env.DB.prepare(
      "UPDATE credentials SET sign_count=?,backed_up=?,updated_at=? WHERE id=?",
    ).bind(
      result.authenticationInfo.newCounter,
      result.authenticationInfo.credentialBackedUp ? 1 : 0,
      time,
      cred.id,
    ),
    loginRecord(
      c,
      u,
      "passkey",
      "success",
      null,
      cred.credential_id.slice(0, 16),
    ),
  ];
  if (ctx.oauthId)
    stmts.push(
      c.env.DB.prepare(
        "UPDATE oauth_requests SET authenticated_user_id=?,authenticated_user_version=? WHERE id=? AND session_hash=? AND expires_at>?",
      ).bind(u.id, u.session_version, ctx.oauthId, c.session.token_hash, time),
    );
  if (ctx.mode === "challenge") c.data.link_authenticated_id = ctx.challengeId;
  await rotate(
    c,
    u,
    action,
    "EXISTS(SELECT 1 FROM ceremonies WHERE id=? AND session_hash=? AND consumed_at IS NULL AND expires_at>?) AND EXISTS(SELECT 1 FROM credentials WHERE id=? AND sign_count=?)",
    [r.id, c.session.token_hash, time, cred.id, cred.sign_count],
    stmts,
    ctx.mode === "reauth",
    result.authenticationInfo.userVerified,
  );
  return json({ ok: true, mode: ctx.mode || "login", action_token: action });
}
export async function auth(c: Context): Promise<Response | null> {
  const path = c.url.pathname,
    method = c.request.method;
  if (method === "GET" && path === "/")
    return page(c, "index.html", {
      home_auth_enabled: c.env.PASSKEY_HOME_AUTH_ENABLED !== "false",
    });
  if (method === "GET" && path === "/api/me")
    return json(
      c.user
        ? { authenticated: true, user: { username: c.user.username } }
        : { authenticated: false },
    );
  if (method === "GET" && path === "/auth/passkey") {
    const mode =
      c.url.searchParams.get("mode") === "reauth" && c.user
        ? "reauth"
        : "login";
    return page(c, "oauth_authorize.html", {
      ok: true,
      mode,
      client_name: "",
      client_id: "",
      redirect_uri: "",
      state: "",
      challenge_id: "",
      username: "",
      return_to: safeReturn(c.url.searchParams.get("return_to")),
      auth_flow_token: await newFlow(c),
    });
  }
  if (method === "POST" && path === "/auth/passkey/flow") {
    sameOrigin(c);
    return json({ ok: true, authFlowToken: await newFlow(c) });
  }
  if (method === "POST" && path === "/api/ui/intent") {
    sameOrigin(c);
    const d = await body(c);
    if (d.intent !== "register") throw new HTTPError(400, "未知操作");
    if (!registrationOpen(await settings(c)))
      throw new HTTPError(403, "注册功能未启用");
    c.data.registration_unlock_expires_at = now() + 120;
    await saveData(c);
    return json({
      ok: true,
      register: {
        usernameMaxLength: 64,
        usernamePlaceholder: "用户名",
        buttonText: "注册",
        clientPath: "/api/ui/register-client.js",
      },
    });
  }
  if (method === "GET" && path === "/api/ui/register-client.js") {
    if (
      !registrationOpen(await settings(c)) ||
      Number(c.data.registration_unlock_expires_at || 0) <= now()
    )
      return new Response("throw new Error('注册入口未解锁或已过期');", {
        status: 403,
        headers: {
          "Content-Type": "application/javascript",
          "Cache-Control": "no-store",
        },
      });
    return new Response(registerClientJavaScript, {
      headers: {
        "Content-Type": "application/javascript",
        "Cache-Control": "no-store",
      },
    });
  }
  if (
    method === "POST" &&
    [
      "/api/register/options",
      "/api/register/verify",
      "/auth/passkey/options",
      "/auth/passkey/verify",
    ].includes(path)
  ) {
    sameOrigin(c);
    const d = await body(c);
    if (path === "/api/register/options") return registerOptions(c, d, null);
    if (path === "/api/register/verify") return registerVerify(c, d, null);
    if (path === "/auth/passkey/options") return loginOptions(c, d);
    return loginVerify(c, d);
  }
  if (method === "POST" && path === "/api/logout") {
    sameOrigin(c);
    await c.store.run(
      "DELETE FROM sessions WHERE token_hash=?",
      c.session.token_hash,
    );
    c.cookies.push(
      `session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${c.url.protocol === "https:" ? "; Secure" : ""}`,
    );
    return json({ ok: true });
  }
  const match = path.match(
    /^\/([A-Za-z0-9_-]{32,128})(?:\/(options|verify))?$/,
  );
  if (match) {
    const token = match[1];
    if (method === "GET" && !match[2]) {
      if (
        !(await c.store.one(
          "SELECT token_hash FROM admin_recovery_tokens WHERE token_hash=? AND expires_at>? AND consumed_at IS NULL",
          await hash(token),
          now(),
        ))
      )
        throw new HTTPError(404, "Not found");
      return page(c, "admin_recovery.html", { recovery_token: token });
    }
    if (method === "POST" && match[2]) {
      sameOrigin(c);
      const d = await body(c);
      return match[2] === "options"
        ? registerOptions(c, d, token)
        : registerVerify(c, d, token);
    }
  }
  return null;
}
