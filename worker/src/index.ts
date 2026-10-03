import { Store, StoreConflict } from "./store";
import type { Env, Context, SessionRow, UserRow } from "./types";
import { auth, page } from "./auth";
import { oauth } from "./oauth";
import { management } from "./management";
import {
  telemetry,
  telemetryHTML,
  telemetryConnectOrigin,
  telemetryEnabled,
} from "./telemetry";
import { now, random, hash, json, HTTPError } from "./security";

function statusLabel(status: number) {
  return (
    (
      {
        400: "Bad Request",
        401: "Unauthorized",
        403: "Forbidden",
        404: "Not Found",
        409: "Conflict",
        429: "Too Many Requests",
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
      } as Record<number, string>
    )[status] || "Error"
  );
}

async function context(
  request: Request,
  env: Env,
  executionCtx: ExecutionContext,
): Promise<Context> {
  const store = new Store(env.DB),
    url = new URL(request.url),
    time = now();
  const raw =
    request.headers.get("cookie")?.match(/(?:^|;\s*)session=([^;]+)/)?.[1] ||
    "";
  let session = raw
    ? await store.one<SessionRow>(
        "SELECT * FROM sessions WHERE token_hash=? AND expires_at>?",
        await hash(raw),
        time,
      )
    : null;
  let user = session?.user_id
    ? await store.one<UserRow>(
        "SELECT * FROM users WHERE id=? AND session_version=? AND disabled_at IS NULL AND login=1",
        session.user_id,
        session.user_version,
      )
    : null;
  const cookies: string[] = [];
  let pendingSessionToken: string | undefined;
  if (!session) {
    pendingSessionToken = random();
    session = {
      token_hash: await hash(pendingSessionToken),
      csrf_token: random(),
      user_id: null,
      user_version: null,
      reauthenticated_at: null,
      action_token_hash: null,
      data_json: "{}",
      created_at: time,
      expires_at: time + 43200,
    };
  }

  return {
    request,
    url,
    env,
    executionCtx,
    store,
    session,
    user,
    data: JSON.parse(session.data_json),
    cookies,
    pendingSessionToken,
  };
}
function secure(response: Response, c?: Context, connectOrigin = ""): Response {
  const headers = new Headers(response.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self), publickey-credentials-create=(self)",
  );
  if (c?.url.protocol === "https:")
    headers.set("Strict-Transport-Security", "max-age=31536000");
  headers.set(
    "Content-Security-Policy",
    `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'${connectOrigin ? " " + connectOrigin : ""}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'`,
  );
  if (!headers.has("Cache-Control")) headers.set("Cache-Control", "no-store");
  for (const value of c?.cookies || []) headers.append("Set-Cookie", value);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
async function fetchHandler(
  request: Request,
  env: Env,
  executionCtx: ExecutionContext,
): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname.startsWith("/static/")) return env.ASSETS.fetch(request);
  let c: Context | undefined;
  try {
    // Configuration is the RP authority, not a caller-controlled Host header.
    if (url.origin !== env.PASSKEY_ORIGIN)
      return secure(new Response("Not found", { status: 404 }));
    c = await context(request, env, executionCtx);
    let response =
      (await auth(c)) ||
      (await oauth(c)) ||
      (await management(c)) ||
      (await telemetry(c));
    if (!response) {
      const status = url.pathname.match(
        /^\/_error\/(400|401|403|404|429|500|502|503|504)$/,
      )?.[1];
      response = page(
        c,
        "error.html",
        {
          status_code: Number(status || 404),
          status_label: statusLabel(Number(status || 404)),
          home_auth_enabled: env.PASSKEY_HOME_AUTH_ENABLED !== "false",
        },
        Number(status || 404),
      );
    }
    let connectOrigin = "";
    if (
      response.headers.get("content-type")?.includes("text/html") &&
      (await telemetryEnabled(c))
    ) {
      response = new Response(
        await telemetryHTML(c, await response.text()),
        response,
      );
      connectOrigin = await telemetryConnectOrigin(c);
    }
    return secure(response, c, connectOrigin);
  } catch (error) {
    const status =
      error instanceof HTTPError
        ? error.status
        : error instanceof StoreConflict
          ? 409
          : 500;
    const message =
      error instanceof HTTPError
        ? error.message
        : error instanceof StoreConflict
          ? "操作已过期或权限已变更，请重试"
          : "服务暂时不可用";
    // Deliberately do not log request URLs/bodies/cookies or exception data containing bindings.
    const response =
      request.method === "GET" &&
      !url.pathname.startsWith("/api/") &&
      !url.pathname.startsWith("/oauth/userinfo") &&
      c
        ? page(
            c,
            "error.html",
            {
              status_code: status,
              status_label: statusLabel(status),
              error_message: message,
              home_auth_enabled: env.PASSKEY_HOME_AUTH_ENABLED !== "false",
            },
            status,
          )
        : json(
            {
              ok: false,
              error: message,
              ...(error instanceof HTTPError ? error.extra : {}),
            },
            status,
          );
    return secure(response, c);
  }
}
export default {
  fetch: fetchHandler,
  async scheduled(
    _event: ScheduledController,
    env: Env,
    ctx: ExecutionContext,
  ) {
    const db = env.DB,
      time = now();
    ctx.waitUntil(
      db.batch([
        db.prepare("DELETE FROM sessions WHERE expires_at<=?").bind(time),
        db.prepare("DELETE FROM ceremonies WHERE expires_at<=?").bind(time),
        db.prepare("DELETE FROM oauth_requests WHERE expires_at<=?").bind(time),
        db.prepare("DELETE FROM oauth_codes WHERE expires_at<=?").bind(time),
        db.prepare("DELETE FROM access_tokens WHERE expires_at<=?").bind(time),
        db
          .prepare("DELETE FROM oauth_challenges WHERE expires_at<=?")
          .bind(time),
        db
          .prepare("DELETE FROM admin_recovery_tokens WHERE expires_at<=?")
          .bind(time),
        db
          .prepare("DELETE FROM management_channels WHERE expires_at<=?")
          .bind(time),
        db
          .prepare("DELETE FROM telemetry_receipts WHERE expires_at<=?")
          .bind(time),
        db
          .prepare(
            "UPDATE delivery_state SET queued=(SELECT COUNT(*) FROM telemetry_receipts WHERE state='queued' AND expires_at>?) WHERE id=1",
          )
          .bind(time),
        db
          .prepare("DELETE FROM telemetry_tokens WHERE expires_at<=?")
          .bind(time),
        db
          .prepare(
            "DELETE FROM telemetry_events WHERE created_at < ? - 86400 * MAX(1,MIN(365,COALESCE((SELECT CAST(json_extract(setting_value,'$.retentionDays') AS INTEGER) FROM app_settings WHERE setting_key='telemetry_config'),30)))",
          )
          .bind(time),
      ]),
    );
  },
} satisfies ExportedHandler<Env>;
