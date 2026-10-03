import type { Context, UserRow, ClientRow } from "./types";
import {
  body,
  json,
  redirect,
  HTTPError,
  sameOrigin,
  now,
  random,
  hash,
  equal,
  username,
  usernameKey,
  saveData,
  ensureSession,
} from "./security";
import { page, newFlow, registrationOpen, settings, loginRecord } from "./auth";

// Evaluated inside every code/token/challenge transaction, including after permission changes.
export const policySQL = `u.disabled_at IS NULL AND u.login=1 AND cl.enabled=1 AND (COALESCE((SELECT mode FROM user_platform_policies WHERE user_id=u.id),'allow_all')='allow_all' OR (COALESCE((SELECT mode FROM user_platform_policies WHERE user_id=u.id),'allow_all')='allow_only' AND EXISTS(SELECT 1 FROM user_platform_policy_entries WHERE user_id=u.id AND client_id=cl.client_id)) OR (COALESCE((SELECT mode FROM user_platform_policies WHERE user_id=u.id),'allow_all')='deny_only' AND NOT EXISTS(SELECT 1 FROM user_platform_policy_entries WHERE user_id=u.id AND client_id=cl.client_id)))`;
const payload = (u: UserRow) => ({
  sub: u.user_handle,
  id: u.id,
  username: u.username,
  createdAt: u.created_at,
});
export function withParams(uri: string, values: Record<string, string>) {
  const u = new URL(uri);
  for (const [k, v] of Object.entries(values)) if (v) u.searchParams.set(k, v);
  return u.toString();
}
const demoURI = (uri: string) => new URL(uri).pathname.startsWith("/demo/");
export async function client(c: Context, id: string) {
  return c.store.one<ClientRow>(
    "SELECT * FROM oauth_clients WHERE client_id=? AND enabled=1",
    id,
  );
}
const allowedRedirect = (cl: ClientRow | null, uri: string) =>
  !!cl && JSON.parse(cl.redirect_uris).includes(uri);
const oauthError = (error: string, description: string, status = 400) =>
  json({ ok: false, error, error_description: description }, status);
export async function accessUser(c: Context, token: string) {
  if (!token) return null;
  return c.store.one<UserRow>(
    `SELECT u.* FROM access_tokens a JOIN users u ON u.id=a.user_id JOIN oauth_clients cl ON cl.client_id=a.client_id WHERE a.token_hash=? AND a.expires_at>? AND a.user_version=u.session_version AND (a.demo_required=0 OR u.demo=1) AND ${policySQL}`,
    await hash(token),
    now(),
  );
}
async function exchange(
  c: Context,
  d: any,
  trustedDemo = false,
): Promise<Response> {
  const cl = await client(c, d.client_id || "");
  if (
    !cl ||
    (!trustedDemo &&
      !(await equal(cl.secret_hash, await hash(String(d.client_secret || "")))))
  )
    return oauthError("invalid_client", "OAuth client 校验失败", 401);
  if (!allowedRedirect(cl, d.redirect_uri))
    return oauthError("invalid_grant", "redirect_uri 不匹配");
  const codeHash = await hash(String(d.code || ""));
  const code = await c.store.one<any>(
    "SELECT * FROM oauth_codes WHERE code_hash=? AND client_id=? AND redirect_uri=? AND consumed_at IS NULL AND expires_at>?",
    codeHash,
    cl.client_id,
    d.redirect_uri,
    now(),
  );
  if (!code)
    return oauthError(
      "invalid_grant",
      "authorization code 无效、已使用或已过期",
    );
  if (
    code.pkce_challenge &&
    (!/^[A-Za-z0-9._~-]{43,128}$/.test(d.code_verifier || "") ||
      (await hash(d.code_verifier)) !== code.pkce_challenge)
  )
    return oauthError("invalid_grant", "PKCE 验证失败");
  const u = await c.store.one<UserRow>(
    "SELECT * FROM users WHERE id=?",
    code.user_id,
  );
  if (!u)
    return oauthError(
      "invalid_grant",
      "authorization code 对应用户不存在或无权访问",
    );
  const token = random(),
    time = now(),
    demo = demoURI(d.redirect_uri) ? 1 : 0;
  try {
    await c.store.guardBatch(
      `EXISTS(SELECT 1 FROM oauth_codes oc JOIN users u ON u.id=oc.user_id JOIN oauth_clients cl ON cl.client_id=oc.client_id WHERE oc.code_hash=? AND oc.client_id=? AND oc.redirect_uri=? AND oc.pkce_challenge=? AND oc.consumed_at IS NULL AND oc.expires_at>? AND oc.user_version=u.session_version AND cl.secret_hash=? AND cl.redirect_uris=? AND (?=0 OR u.demo=1) AND ${policySQL})`,
      [
        codeHash,
        cl.client_id,
        d.redirect_uri,
        code.pkce_challenge,
        time,
        cl.secret_hash,
        cl.redirect_uris,
        demo,
      ],
      [
        c.env.DB.prepare(
          "UPDATE oauth_codes SET consumed_at=? WHERE code_hash=?",
        ).bind(time, codeHash),
        c.env.DB.prepare(
          "INSERT INTO access_tokens(token_hash,user_id,user_version,client_id,demo_required,created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
        ).bind(
          await hash(token),
          u.id,
          code.user_version,
          cl.client_id,
          demo,
          time,
          time + 3600,
        ),
      ],
    );
  } catch (e) {
    if ((e as Error).name === "StoreConflict")
      return oauthError(
        "invalid_grant",
        "authorization code 无效、已使用或已过期",
      );
    throw e;
  }
  return json({
    ok: true,
    access_token: token,
    token_type: "Bearer",
    expires_in: 3600,
    authenticated: true,
    user: payload(u),
  });
}
async function authorize(c: Context) {
  const q = c.url.searchParams,
    id = q.get("client_id") || "",
    uri = q.get("redirect_uri") || "",
    state = q.get("state") || "",
    pkce = q.get("code_challenge") || "",
    method = q.get("code_challenge_method") || "",
    hint = q.get("screen_hint") || "";
  const cl = await client(c, id);
  if (!allowedRedirect(cl, uri))
    return page(
      c,
      "oauth_authorize.html",
      {
        ok: false,
        error: "invalid_client",
        error_description: "OAuth client 或 redirect_uri 无效",
      },
      400,
    );
  const err = (e: string, d: string) =>
    redirect(withParams(uri, { error: e, error_description: d, state }));
  if (q.get("response_type") !== "code")
    return err("unsupported_response_type", "仅支持 authorization code flow");
  if (!state || state.length > 512)
    return err("invalid_request", "state 必填且不能超过 512 字符");
  if (
    (pkce || method) &&
    (!/^[A-Za-z0-9_-]{43}$/.test(pkce) || method !== "S256")
  )
    return err("invalid_request", "仅支持有效的 S256 PKCE");
  if (hint && hint !== "signup")
    return err("invalid_request", "未知的 screen_hint");
  let name = "";
  try {
    if (q.get("login_hint") || hint === "signup")
      name = username(q.get("login_hint"));
  } catch (e) {
    return err("invalid_request", (e as Error).message);
  }
  const create =
    hint === "signup" &&
    !(await c.store.one(
      "SELECT id FROM users WHERE username_key=?",
      usernameKey(name),
    ));
  if (create && !registrationOpen(await settings(c)))
    return err("registration_not_allowed", "注册功能未启用");
  const requestId = random(),
    time = now();
  await ensureSession(c);
  await c.store.run(
    "INSERT INTO oauth_requests(id,session_hash,client_id,redirect_uri,state,pkce_challenge,username,screen_hint,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
    requestId,
    c.session.token_hash,
    id,
    uri,
    state,
    pkce,
    name,
    create ? "signup" : "",
    time + 300,
  );
  c.data.oauth_request_id = requestId;
  if (create) c.data.registration_unlock_expires_at = time + 120;
  const flow = await newFlow(c),
    errorURI = new URL(uri);
  if (!pkce && !hint && errorURI.pathname === "/api/auth/callback") {
    errorURI.pathname = "/api/auth/error";
    errorURI.search = "";
    errorURI.hash = "";
  }
  return page(c, "oauth_authorize.html", {
    ok: true,
    mode: "code",
    client_name: cl!.name,
    client_id: id,
    redirect_uri: uri,
    state,
    challenge_id: "",
    username: name,
    screen_hint: create ? "signup" : "",
    auth_flow_token: flow,
    error_redirect_uri:
      pkce || hint
        ? uri
        : new URL(uri).pathname === "/api/auth/callback"
          ? errorURI.toString()
          : "",
  });
}
async function complete(c: Context, d: any) {
  const time = now(),
    r = await c.store.one<any>(
      "SELECT * FROM oauth_requests WHERE id=? AND session_hash=? AND expires_at>? AND consumed_at IS NULL",
      c.data.oauth_request_id || "",
      c.session.token_hash,
      time,
    );
  if (!r || ["client_id", "redirect_uri", "state"].some((k) => r[k] !== d[k]))
    throw new HTTPError(400, "OAuth 授权会话无效或已过期");
  if (
    !c.user ||
    r.authenticated_user_id !== c.user.id ||
    r.authenticated_user_version !== c.user.session_version
  )
    throw new HTTPError(401, "请先完成 Passkey 登录");
  const cl = await client(c, r.client_id);
  if (!allowedRedirect(cl, r.redirect_uri))
    throw new HTTPError(400, "OAuth client 或 redirect_uri 无效");
  const code = random(),
    demo = demoURI(r.redirect_uri) ? 1 : 0;
  try {
    await c.store.guardBatch(
      `EXISTS(SELECT 1 FROM oauth_requests r JOIN sessions s ON s.token_hash=r.session_hash JOIN users u ON u.id=s.user_id JOIN oauth_clients cl ON cl.client_id=r.client_id WHERE r.id=? AND r.session_hash=? AND r.consumed_at IS NULL AND r.expires_at>? AND s.expires_at>? AND s.user_version=u.session_version AND r.authenticated_user_id=u.id AND r.authenticated_user_version=u.session_version AND cl.redirect_uris=? AND (?=0 OR u.demo=1) AND ${policySQL})`,
      [r.id, c.session.token_hash, time, time, cl!.redirect_uris, demo],
      [
        c.env.DB.prepare(
          "UPDATE oauth_requests SET consumed_at=? WHERE id=?",
        ).bind(time, r.id),
        c.env.DB.prepare(
          "INSERT INTO oauth_codes(code_hash,client_id,redirect_uri,user_id,user_version,pkce_challenge,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)",
        ).bind(
          await hash(code),
          cl!.client_id,
          r.redirect_uri,
          c.user.id,
          c.user.session_version,
          r.pkce_challenge,
          time,
          time + 300,
        ),
        loginRecord(c, c.user, "oauth", "success", cl!.client_id),
      ],
    );
  } catch (e) {
    if ((e as Error).name === "StoreConflict")
      throw new HTTPError(403, "此账户无权登录该平台或授权已使用");
    throw e;
  }
  return json({
    ok: true,
    redirectUrl: withParams(r.redirect_uri, { code, state: r.state }),
  });
}
async function serverClient(c: Context, d: any): Promise<ClientRow | null> {
  let id = typeof d.client_id === "string" ? d.client_id : "",
    secret = typeof d.client_secret === "string" ? d.client_secret : "";
  const authorization = c.request.headers.get("authorization") || "";
  if (authorization) {
    if (!authorization.startsWith("Basic ")) return null;
    try {
      const decoded = atob(authorization.slice(6)),
        separator = decoded.indexOf(":");
      if (separator < 0) return null;
      id = decodeURIComponent(decoded.slice(0, separator).replace(/\+/g, " "));
      secret = decodeURIComponent(
        decoded.slice(separator + 1).replace(/\+/g, " "),
      );
    } catch {
      return null;
    }
  }
  const cl = await client(c, id);
  return cl && secret && (await equal(cl.secret_hash, await hash(secret)))
    ? cl
    : null;
}
async function serverChallenge(
  c: Context,
  consume: boolean,
): Promise<Response> {
  const d = await body(c),
    cl = await serverClient(c, d);
  if (!cl) return oauthError("invalid_client", "OAuth client 校验失败", 401);
  if (typeof d.return_uri !== "string" || !allowedRedirect(cl, d.return_uri))
    return oauthError("invalid_request", "return_uri 不匹配");
  if (typeof d.state !== "string" || !d.state || d.state.length > 512)
    return oauthError("invalid_request", "state 必填且不能超过 512 字符");
  const time = now();
  if (!consume) {
    const name = username(d.username),
      id = random();
    try {
      await c.store.guardBatch(
        "EXISTS(SELECT 1 FROM oauth_clients WHERE client_id=? AND enabled=1 AND secret_hash=? AND redirect_uris=?)",
        [cl.client_id, cl.secret_hash, cl.redirect_uris],
        [
          c.env.DB.prepare(
            "INSERT INTO oauth_challenges(challenge_id,client_id,return_uri,username,username_key,state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)",
          ).bind(
            id,
            cl.client_id,
            d.return_uri,
            name,
            usernameKey(name),
            d.state,
            time,
            time + 300,
          ),
        ],
      );
    } catch (e) {
      if ((e as Error).name === "StoreConflict")
        return oauthError("invalid_client", "OAuth client 校验失败", 401);
      throw e;
    }
    return json({
      ok: true,
      challenge: id,
      authorizationUrl: c.env.PASSKEY_ORIGIN + "/oauth/challenge/" + id,
      expires_in: 300,
    });
  }
  if (
    typeof d.challenge !== "string" ||
    !d.challenge ||
    typeof d.challenge_result !== "string" ||
    !d.challenge_result
  )
    return oauthError("invalid_grant", "challenge result 无效");
  try {
    const rows = await c.store.guardBatch(
      `EXISTS(SELECT 1 FROM oauth_challenges r JOIN users u ON u.id=r.user_id JOIN oauth_clients cl ON cl.client_id=r.client_id WHERE r.challenge_id=? AND r.result_hash=? AND r.client_id=? AND r.return_uri=? AND r.state=? AND r.completed_at IS NOT NULL AND r.consumed_at IS NULL AND r.expires_at>? AND r.user_version=u.session_version AND cl.secret_hash=? AND cl.redirect_uris=? AND (?=0 OR u.demo=1) AND ${policySQL})`,
      [
        d.challenge,
        await hash(d.challenge_result),
        cl.client_id,
        d.return_uri,
        d.state,
        time,
        cl.secret_hash,
        cl.redirect_uris,
        demoURI(d.return_uri) ? 1 : 0,
      ],
      [
        c.env.DB.prepare(
          "UPDATE oauth_challenges SET consumed_at=? WHERE challenge_id=?",
        ).bind(time, d.challenge),
        c.env.DB.prepare(
          "SELECT u.* FROM users u JOIN oauth_challenges r ON r.user_id=u.id WHERE r.challenge_id=?",
        ).bind(d.challenge),
      ],
    );
    return json({
      ok: true,
      authenticated: true,
      user: payload(rows[1].results[0] as unknown as UserRow),
    });
  } catch (e) {
    if ((e as Error).name === "StoreConflict")
      return oauthError(
        "invalid_grant",
        "challenge result 无效、已使用或已过期",
      );
    throw e;
  }
}
export async function oauth(c: Context): Promise<Response | null> {
  const p = c.url.pathname,
    m = c.request.method;
  if (
    m === "POST" &&
    (p === "/api/server/challenges" || p === "/api/server/challenges/consume")
  )
    return serverChallenge(c, p.endsWith("/consume"));
  if (m === "GET" && p === "/.well-known/oauth-authorization-server") {
    const base = c.env.PASSKEY_ORIGIN;
    return json({
      issuer: base,
      authorization_endpoint: base + "/oauth/authorize",
      token_endpoint: base + "/oauth/token",
      userinfo_endpoint: base + "/oauth/userinfo",
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      token_endpoint_auth_methods_supported: [
        "client_secret_post",
        "client_secret_basic",
      ],
      code_challenge_methods_supported: ["S256"],
      registration_screen_hint_supported: true,
    });
  }
  if (m === "GET" && p === "/oauth/authorize") return authorize(c);
  if (m === "POST" && p === "/oauth/authorize/complete") {
    sameOrigin(c);
    return complete(c, await body(c));
  }
  if (m === "POST" && p === "/oauth/token") {
    const d = await body(c);
    if ((d.grant_type || "authorization_code") !== "authorization_code")
      return json({ error: "unsupported_grant_type" }, 400);
    const a = c.request.headers.get("authorization") || "";
    if (a.startsWith("Basic ")) {
      try {
        const basic = atob(a.slice(6)),
          i = basic.indexOf(":");
        if (i < 0) throw Error();
        d.client_id = decodeURIComponent(basic.slice(0, i).replace(/\+/g, " "));
        d.client_secret = decodeURIComponent(
          basic.slice(i + 1).replace(/\+/g, " "),
        );
      } catch {
        return oauthError("invalid_client", "OAuth client 校验失败", 401);
      }
    }
    return exchange(c, d);
  }
  if (m === "GET" && p === "/oauth/userinfo") {
    const u = await accessUser(
      c,
      (c.request.headers.get("authorization") || "").replace(/^Bearer /, ""),
    );
    if (!u) throw new HTTPError(401, "access token 无效或已过期");
    return json(payload(u));
  }
  if (m === "POST" && p === "/api/server/session/verify") {
    const expected = c.env.PASSKEY_SERVER_API_TOKEN,
      a = c.request.headers.get("authorization") || "";
    if (!expected || !(await equal(a, "Bearer " + expected)))
      throw new HTTPError(401, "服务端验证 API 未启用或令牌无效");
    const d = await body(c);
    let raw = String(d.sessionCookie || d.session_cookie || "").trim();
    let u = c.user;
    if (raw) {
      if (raw.includes("="))
        raw = raw.match(/(?:^|;\s*)session=([^;]+)/)?.[1] || "";
      u = await c.store.one<UserRow>(
        "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.user_version=u.session_version AND u.disabled_at IS NULL AND u.login=1",
        await hash(raw),
        now(),
      );
      if (!u)
        return json({
          ok: true,
          authenticated: false,
          error: "无效的 session cookie",
        });
    }
    return json(
      u
        ? { ok: true, authenticated: true, user: payload(u) }
        : { ok: true, authenticated: false },
    );
  }
  const match = p.match(/^\/oauth\/challenge\/([\w-]+)(\/complete)?$/);
  if (match) {
    const r = await c.store.one<any>(
      "SELECT * FROM oauth_challenges WHERE challenge_id=? AND expires_at>? AND completed_at IS NULL AND consumed_at IS NULL",
      match[1],
      now(),
    );
    const cl = r ? await client(c, r.client_id) : null;
    if (!r || !allowedRedirect(cl, r.return_uri)) {
      if (m === "GET")
        return page(
          c,
          "oauth_authorize.html",
          {
            ok: false,
            error: "invalid_challenge",
            error_description: "challenge 不存在或已过期",
          },
          400,
        );
      throw new HTTPError(400, "challenge 不存在或已过期");
    }
    if (m === "GET" && !match[2]) {
      c.data.link_challenge_id = r.challenge_id;
      return page(c, "oauth_authorize.html", {
        ok: true,
        mode: "challenge",
        client_name: cl!.name,
        client_id: r.client_id,
        redirect_uri: r.return_uri,
        state: r.state,
        challenge_id: r.challenge_id,
        username: r.username,
        auth_flow_token: await newFlow(c),
      });
    }
    if (m === "POST" && match[2]) {
      sameOrigin(c);
      const u = c.user;
      if (!u || c.data.link_authenticated_id !== r.challenge_id)
        throw new HTTPError(401, "请先完成 Passkey 登录");
      if (u.username_key !== r.username_key)
        throw new HTTPError(403, "Passkey 用户和原网站用户名不匹配");
      const result = random(),
        time = now();
      await c.store.guardBatch(
        `EXISTS(SELECT 1 FROM oauth_challenges q JOIN oauth_clients cl ON cl.client_id=q.client_id JOIN users u ON u.id=? JOIN sessions s ON s.user_id=u.id WHERE q.challenge_id=? AND q.completed_at IS NULL AND q.consumed_at IS NULL AND q.expires_at>? AND s.token_hash=? AND s.expires_at>? AND s.user_version=u.session_version AND u.username_key=q.username_key AND cl.redirect_uris=? AND (?=0 OR u.demo=1) AND ${policySQL})`,
        [
          u.id,
          r.challenge_id,
          time,
          c.session.token_hash,
          time,
          cl!.redirect_uris,
          demoURI(r.return_uri) ? 1 : 0,
        ],
        [
          c.env.DB.prepare(
            "UPDATE oauth_challenges SET user_id=?,user_version=?,result_hash=?,completed_at=? WHERE challenge_id=?",
          ).bind(
            u.id,
            u.session_version,
            await hash(result),
            time,
            r.challenge_id,
          ),
          loginRecord(c, u, "link_challenge", "success", r.client_id),
        ],
      );
      return json({
        ok: true,
        redirectUrl: withParams(r.return_uri, {
          challenge: r.challenge_id,
          challenge_result: result,
          state: r.state,
          status: "success",
        }),
      });
    }
  }
  if (p.startsWith("/demo/")) return demos(c);
  return null;
}
async function demos(c: Context): Promise<Response | null> {
  const p = c.url.pathname,
    m = c.request.method,
    q = c.url.searchParams;
  const cl = await c.store.one<ClientRow>(
    "SELECT * FROM oauth_clients WHERE is_demo=1 AND enabled=1 ORDER BY id LIMIT 1",
  );
  if (!cl)
    return page(
      c,
      "oauth_authorize.html",
      {
        ok: false,
        error: "invalid_client",
        error_description: "Demo client 未配置",
      },
      503,
    );
  const base = c.env.PASSKEY_ORIGIN;
  if (m === "GET" && ["/demo/oauth", "/demo/third-party"].includes(p)) {
    const state = random(),
      verifier = random(),
      kind = p.endsWith("third-party") ? "third_party" : "demo";
    c.data[kind + "_oauth_state"] = state;
    c.data[kind + "_verifier"] = verifier;
    await saveData(c);
    const uri = base + p + "/callback";
    return page(
      c,
      kind === "demo" ? "oauth_demo.html" : "third_party_demo.html",
      {
        authorize_url: withParams(base + "/oauth/authorize", {
          response_type: "code",
          client_id: cl.client_id,
          redirect_uri: uri,
          state,
          code_challenge: await hash(verifier),
          code_challenge_method: "S256",
        }),
        client_id: cl.client_id,
        redirect_uri: uri,
      },
    );
  }
  if (m === "GET" && p === "/demo/link-login") {
    await ensureSession(c);
    return page(c, "link_login_demo.html", {
      client_id: cl.client_id,
      return_uri: base + p + "/callback",
      auth_base_url: base + "/oauth/challenge/",
      csrf_token: c.session.csrf_token,
    });
  }
  if (m === "POST" && p === "/demo/link-login/start") {
    const d = await body(c),
      requestOrigin = c.request.headers.get("origin");
    if (requestOrigin !== base) {
      // A no-referrer document can submit a native form with an opaque Origin.
      // This exception requires both browser same-origin navigation metadata and
      // a secret CSRF value bound to the existing session; JSON writes stay strict.
      const nativeSameOrigin =
        (!requestOrigin || requestOrigin === "null") &&
        c.request.headers.get("sec-fetch-site") === "same-origin" &&
        c.request.headers.get("sec-fetch-mode") === "navigate" &&
        (c.request.headers.get("content-type") || "").startsWith(
          "application/x-www-form-urlencoded",
        );
      if (
        !nativeSameOrigin ||
        typeof d.csrf_token !== "string" ||
        !(await equal(d.csrf_token, c.session.csrf_token))
      )
        throw new HTTPError(403, "Invalid request origin or CSRF token.");
    }
    const name = username(d.username),
      state = random(),
      id = random(),
      time = now();
    c.data.link_login_state = state;
    await saveData(c);
    await c.store.run(
      "INSERT INTO oauth_challenges(challenge_id,client_id,return_uri,username,username_key,state,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?)",
      id,
      cl.client_id,
      base + "/demo/link-login/callback",
      name,
      usernameKey(name),
      state,
      time,
      time + 300,
    );
    return redirect(base + "/oauth/challenge/" + id);
  }
  if (
    m === "GET" &&
    [
      "/demo/oauth/callback",
      "/demo/third-party/callback",
      "/demo/link-login/callback",
    ].includes(p)
  ) {
    const link = p.includes("link-login"),
      third = p.includes("third-party"),
      kind = link ? "link_login" : third ? "third_party_oauth" : "demo_oauth",
      expected = c.data[kind + "_state"],
      state = q.get("state") || "";
    delete c.data[kind + "_state"];
    const verifier = c.data[(third ? "third_party" : "demo") + "_verifier"];
    delete c.data[(third ? "third_party" : "demo") + "_verifier"];
    await saveData(c);
    const template = link
        ? "link_login_result.html"
        : third
          ? "third_party_result.html"
          : "oauth_result.html",
      vars: any = {
        ok: false,
        error: "",
        error_description: "",
        callback_params: Object.fromEntries(q),
        token_response: null,
        userinfo_response: null,
        user: null,
      };
    if (!state || state !== expected) {
      vars.error = "invalid_state";
      vars.error_description = "OAuth state 校验失败";
      return page(c, template, vars);
    }
    if (q.has("error")) {
      vars.error = q.get("error");
      vars.error_description = q.get("error_description");
      return page(c, template, vars);
    }
    if (link) {
      const condition = `EXISTS(SELECT 1 FROM oauth_challenges r JOIN users u ON u.id=r.user_id JOIN oauth_clients cl ON cl.client_id=r.client_id WHERE r.challenge_id=? AND r.result_hash=? AND r.client_id=? AND r.return_uri=? AND r.state=? AND r.completed_at IS NOT NULL AND r.consumed_at IS NULL AND r.expires_at>? AND r.user_version=u.session_version AND u.demo=1 AND ${policySQL})`;
      const id = q.get("challenge") || "",
        time = now();
      try {
        const rows = await c.store.guardBatch(
          condition,
          [
            id,
            await hash(q.get("challenge_result") || ""),
            cl.client_id,
            base + p,
            state,
            time,
          ],
          [
            c.env.DB.prepare(
              "UPDATE oauth_challenges SET consumed_at=? WHERE challenge_id=?",
            ).bind(time, id),
            c.env.DB.prepare(
              "SELECT u.* FROM users u JOIN oauth_challenges r ON r.user_id=u.id WHERE r.challenge_id=?",
            ).bind(id),
          ],
        );
        vars.ok = true;
        vars.user = payload(rows[1].results[0] as unknown as UserRow);
      } catch (e) {
        if ((e as Error).name !== "StoreConflict") throw e;
        vars.error = "invalid_challenge_result";
      }
    } else {
      const response = await exchange(
        c,
        {
          client_id: cl.client_id,
          redirect_uri: base + p,
          code: q.get("code") || "",
          code_verifier: verifier,
        },
        true,
      );
      const value: any = await response.json();
      vars.ok = response.ok;
      vars.error = value.error || "";
      vars.error_description = value.error_description || "";
      vars.token_response = value;
      if (third && response.ok)
        vars.userinfo_response = payload(
          (await accessUser(c, value.access_token))!,
        );
    }
    return page(c, template, vars);
  }
  return null;
}
