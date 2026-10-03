import type { Context, UserRow, ClientRow } from "./types";
import {
  body,
  b64,
  unb64,
  hash,
  random,
  now,
  json,
  sameOrigin,
  username,
  usernameKey,
  HTTPError,
} from "./security";
import { StoreConflict } from "./store";
import { renderPage } from "./pages";
import {
  telemetryManagement,
  telemetrySettingsPayload,
  telemetryLast24hCount,
} from "./telemetry";

export interface Mutation {
  statements: D1PreparedStatement[];
  action: string;
  targetType?: string;
  targetId?: string;
  details?: Record<string, unknown>;
  auditChangedRows?: boolean;
  condition?: string;
  bindings?: unknown[];
  response?:
    | Record<string, unknown>
    | ((results: D1Result[]) => Record<string, unknown>);
  /** External work runs only after the current action capability is reserved. */
  prepare?: () => Promise<Partial<Mutation>>;
}
export type ManagementWriter = (mutation: Mutation) => Promise<Response>;
interface Channel {
  id: string;
  user_id: number;
  session_hash: string;
  public_key_jwk: string;
  server_nonce: string;
  last_counter: number;
  created_at: number;
  expires_at: number;
  last_seen_at: number;
  ack_after_ms: number;
}
interface Proof {
  channel: Channel;
  counter: number;
}

function admin(c: Context): UserRow {
  if (!c.user) throw new HTTPError(401, "请先完成 Passkey 登录");
  if (!c.user.admin || !c.user.login || c.user.disabled_at !== null)
    throw new HTTPError(403, "没有管理权限");
  return c.user;
}
function csrf(c: Context) {
  sameOrigin(c);
  if (
    !c.session.csrf_token ||
    c.request.headers.get("X-CSRF-Token") !== c.session.csrf_token
  )
    throw new HTTPError(403, "CSRF 校验失败");
}
function recent(c: Context) {
  if ((c.session.reauthenticated_at || 0) < now() - 300)
    throw new HTTPError(428, "请重新完成 Passkey 登录后再执行此操作", {
      reauth_required: true,
    });
}
function channelError(reason: string): never {
  throw new HTTPError(409, "管理通道已失效，请重新完成 Passkey 验证", {
    reauth_required: true,
    reason,
  });
}
function tokenError(reason = "action_token_mismatch"): never {
  throw new HTTPError(409, "操作令牌无效，请重新完成 Passkey 验证", {
    reauth_required: true,
    reason,
  });
}
export function actorCondition(
  c: Context,
  fresh = false,
): { sql: string; bindings: unknown[] } {
  return {
    sql: `EXISTS (SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id
      WHERE s.token_hash=? AND s.expires_at>? AND u.id=? AND u.admin=1 AND u.login=1
      AND u.disabled_at IS NULL AND s.user_version=u.session_version AND s.user_version=?
      ${fresh ? "AND s.reauthenticated_at>=? AND s.csrf_token=?" : ""})`,
    bindings: [
      c.session.token_hash,
      now(),
      c.user!.id,
      c.session.user_version,
      ...(fresh ? [now() - 300, c.session.csrf_token] : []),
    ],
  };
}
function channelPayload(ch: Channel) {
  return {
    channel_id: ch.id,
    server_nonce: ch.server_nonce,
    ack_after_ms: ch.ack_after_ms,
    min_ack_after_ms: 30000,
    max_ack_after_ms: 300000,
    expires_at: ch.expires_at,
    last_seen_at: ch.last_seen_at,
  };
}
export function adaptiveAck(data: Record<string, unknown>): number {
  if (data.visibility !== "visible" || data.saveData) return 180000;
  if (["slow-2g", "2g"].includes(String(data.effectiveType))) return 120000;
  return data.effectiveType === "3g" || Number(data.rttMs) > 1500
    ? 90000
    : 45000;
}
export function channelMessage(
  ch: Channel,
  purpose: string,
  method: string,
  path: string,
  p: Record<string, any>,
): string {
  return [
    "passkey-management-channel-v1",
    purpose,
    ch.id,
    String(p.counter),
    ch.server_nonce,
    p.clientNonce,
    method.toUpperCase(),
    path,
    p.visibility || "unknown",
    p.effectiveType || "unknown",
    p.saveData ? "1" : "0",
    p.rttMs === null || p.rttMs === undefined || p.rttMs === ""
      ? ""
      : String(Math.trunc(Number(p.rttMs))),
  ].join("\n");
}
async function getChannel(c: Context, id?: string): Promise<Channel> {
  const expected = String(c.data.management_channel_id || "");
  if (!expected || (id && id !== expected)) channelError("channel_missing");
  const ch = await c.store.one<Channel>(
    "SELECT * FROM management_channels WHERE id=? AND session_hash=? AND user_id=? AND expires_at>?",
    expected,
    c.session.token_hash,
    c.user!.id,
    now(),
  );
  if (!ch) channelError("channel_missing");
  return ch;
}
async function verifyProof(
  ch: Channel,
  purpose: string,
  method: string,
  path: string,
  p: Record<string, any>,
): Promise<Proof> {
  const counter = Number(p.counter);
  if (!Number.isSafeInteger(counter) || counter <= 0)
    channelError("channel_counter_invalid");
  if (counter <= ch.last_counter) channelError("channel_replay");
  if (
    typeof p.clientNonce !== "string" ||
    !/^[A-Za-z0-9_-]{16,128}$/.test(p.clientNonce) ||
    typeof p.signature !== "string" ||
    p.signature.length > 256
  )
    channelError("channel_proof_missing");
  if (
    p.rttMs != null &&
    (!Number.isFinite(Number(p.rttMs)) || Number(p.rttMs) < 0)
  )
    channelError("channel_signature_invalid");
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      JSON.parse(ch.public_key_jwk),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    const verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      unb64(p.signature),
      new TextEncoder().encode(
        channelMessage(ch, purpose, method, path, { ...p, counter }),
      ),
    );
    if (!verified) channelError("channel_signature_invalid");
  } catch {
    channelError("channel_signature_invalid");
  }
  return { channel: ch, counter };
}
function proofCondition(proof: Proof): { sql: string; bindings: unknown[] } {
  const ch = proof.channel;
  return {
    sql: "EXISTS(SELECT 1 FROM management_channels WHERE id=? AND session_hash=? AND user_id=? AND server_nonce=? AND last_counter=? AND expires_at>? AND last_seen_at>=?)",
    bindings: [
      ch.id,
      ch.session_hash,
      ch.user_id,
      ch.server_nonce,
      ch.last_counter,
      now(),
      now() - 300,
    ],
  };
}
async function writer(c: Context): Promise<ManagementWriter> {
  admin(c);
  csrf(c);
  recent(c);
  const current = c.request.headers.get("X-Action-Token") || "";
  if (!current || current.length > 256 || !c.session.action_token_hash)
    tokenError("action_token_missing");
  const currentHash = await hash(current);
  if (currentHash !== c.session.action_token_hash) tokenError();
  let proof: Proof | null = null;
  const channelId = String(c.data.management_channel_id || "");
  if (channelId) {
    const ch = await getChannel(c);
    if (ch.last_seen_at < now() - 300) channelError("channel_stale");
    const h = c.request.headers;
    if (h.get("X-Management-Channel-Id") !== ch.id)
      channelError("channel_proof_missing");
    proof = await verifyProof(ch, "write", c.request.method, c.url.pathname, {
      counter: h.get("X-Management-Channel-Counter"),
      clientNonce: h.get("X-Management-Channel-Client-Nonce"),
      signature: h.get("X-Management-Channel-Signature"),
      visibility: h.get("X-Management-Channel-Visibility") || "unknown",
      effectiveType: h.get("X-Management-Channel-Effective-Type") || "unknown",
      saveData: h.get("X-Management-Channel-Save-Data") === "1",
      rttMs: null,
    });
  }
  return async (initial) => {
    let m = initial;
    const next = random(),
      nextHash = await hash(next),
      auth = actorCondition(c, true);
    let condition = `${auth.sql} AND EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND action_token_hash=? AND COALESCE(json_extract(data_json,'$.management_channel_id'),'')=?)`;
    const bindings = [
      ...auth.bindings,
      c.session.token_hash,
      currentHash,
      channelId,
    ];
    const statements: D1PreparedStatement[] = [];
    if (proof) {
      const pc = proofCondition(proof);
      condition += ` AND ${pc.sql}`;
      bindings.push(...pc.bindings);
      statements.push(
        c.env.DB.prepare(
          "UPDATE management_channels SET last_counter=?,last_seen_at=? WHERE id=?",
        ).bind(proof.counter, now(), proof.channel.id),
      );
    }
    if (m.condition) {
      condition += ` AND (${m.condition})`;
      bindings.push(...(m.bindings || []));
    }
    let reservationHash: string | null = null;
    if (m.prepare) {
      reservationHash = await hash(random());
      try {
        await c.store.guardBatch(condition, bindings, [
          ...statements,
          c.env.DB.prepare(
            "UPDATE sessions SET action_token_hash=? WHERE token_hash=?",
          ).bind(reservationHash, c.session.token_hash),
        ]);
        // The capability is now exclusively reserved. Network work cannot be
        // rolled into a D1 transaction; final authority is checked again below.
        m = { ...m, ...(await m.prepare()) };
      } catch (error) {
        await c.store.run(
          "UPDATE sessions SET action_token_hash=? WHERE token_hash=? AND action_token_hash=?",
          currentHash,
          c.session.token_hash,
          reservationHash,
        );
        if (error instanceof StoreConflict) tokenError("authorization_changed");
        throw error;
      }
      const fresh = actorCondition(c, true);
      condition = `${fresh.sql} AND EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND action_token_hash=? AND COALESCE(json_extract(data_json,'$.management_channel_id'),'')=?)`;
      bindings.splice(
        0,
        bindings.length,
        ...fresh.bindings,
        c.session.token_hash,
        reservationHash,
        channelId,
      );
      if (proof) {
        condition +=
          " AND EXISTS(SELECT 1 FROM management_channels WHERE id=? AND session_hash=? AND last_counter>=? AND expires_at>?)";
        bindings.push(
          proof.channel.id,
          c.session.token_hash,
          proof.counter,
          now(),
        );
      }
      if (m.condition) {
        condition += ` AND (${m.condition})`;
        bindings.push(...(m.bindings || []));
      }
      statements.length = 0;
    }
    statements.push(
      c.env.DB.prepare(
        "UPDATE sessions SET action_token_hash=? WHERE token_hash=?",
      ).bind(nextHash, c.session.token_hash),
    );
    const prefix = statements.length;
    statements.push(...m.statements);
    if (m.action)
      statements.push(
        c.env.DB.prepare(
          `INSERT INTO audit_logs(actor_user_id,actor_username,action,target_type,target_id,details,ip_address,user_agent,created_at) VALUES(?,?,?,?,?,${m.auditChangedRows ? "json_set(?,'$.deleted',changes())" : "?"},?,?,?)`,
        ).bind(
          c.user!.id,
          c.user!.username,
          m.action,
          m.targetType || "",
          m.targetId || "",
          JSON.stringify(m.details || {}),
          c.request.headers.get("CF-Connecting-IP") || "",
          (c.request.headers.get("User-Agent") || "").slice(0, 1000),
          now(),
        ),
      );
    try {
      const result = await c.store.guardBatch(condition, bindings, statements);
      c.session.action_token_hash = nextHash;
      const payload =
        typeof m.response === "function"
          ? m.response(result.slice(prefix, prefix + m.statements.length))
          : m.response || { ok: true };
      return json({ ...payload, next_action_token: next });
    } catch (error) {
      if (reservationHash)
        await c.store.run(
          "UPDATE sessions SET action_token_hash=? WHERE token_hash=? AND action_token_hash=?",
          currentHash,
          c.session.token_hash,
          reservationHash,
        );
      if (error instanceof StoreConflict) tokenError("authorization_changed");
      if (
        error instanceof Error &&
        /UNIQUE constraint|CHECK constraint|FOREIGN KEY constraint/.test(
          error.message,
        )
      )
        throw new HTTPError(409, "数据已更改或配置冲突，请刷新后重试");
      throw error;
    }
  };
}

export function setting(
  c: Context,
  key: string,
  value: string,
): D1PreparedStatement {
  return c.env.DB.prepare(
    "INSERT INTO app_settings(setting_key,setting_value,updated_at) VALUES(?,?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=excluded.updated_at",
  ).bind(key, value, now());
}
export function parseJSON<T>(text: string | null | undefined, fallback: T): T {
  try {
    return JSON.parse(text || "") as T;
  } catch {
    return fallback;
  }
}
function permissions(u: UserRow) {
  return { admin: !!u.admin, login: !!u.login, demo: !!u.demo };
}
function clientPayload(client: ClientRow) {
  return {
    id: client.id,
    clientId: client.client_id,
    name: client.name,
    redirectUris: parseJSON(client.redirect_uris, []),
    enabled: !!client.enabled,
    isDemo: !!client.is_demo,
    createdAt: client.created_at,
    updatedAt: client.updated_at,
  };
}
export function redirectURIs(value: unknown): string[] {
  const values = Array.isArray(value)
    ? value
    : String(value || "").split(/[\n,]/);
  if (values.length > 50) throw new HTTPError(400, "回调地址过多");
  const uris = [
    ...new Set(values.map((v) => String(v).trim()).filter(Boolean)),
  ].sort();
  for (const uri of uris) {
    let u: URL;
    try {
      u = new URL(uri);
    } catch {
      throw new HTTPError(400, "回调地址必须是完整的 HTTP 或 HTTPS URL");
    }
    if (
      !["http:", "https:"].includes(u.protocol) ||
      u.username ||
      u.password ||
      u.hash ||
      uri.length > 2048
    )
      throw new HTTPError(400, "回调地址无效");
  }
  return uris;
}
function requiredText(v: unknown, length: number, label: string) {
  const s = String(v || "").trim();
  if (!s || s.length > length || /[\u0000-\u001f]/.test(s))
    throw new HTTPError(400, `${label}无效`);
  return s;
}
function beforeValue(v: unknown): number | null {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < 0) throw new HTTPError(400, "时间无效");
  return n;
}
export function csvValue(v: unknown): string {
  let s =
    v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
  if (/^[\s]*[=+@-]/.test(s) || /^[\t\r\n]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}
export function csvResponse(
  fields: string[],
  rows: Record<string, unknown>[],
  name: string,
) {
  return new Response(
    "\ufeff" +
      [
        fields.join(","),
        ...rows.map((row) => fields.map((f) => csvValue(row[f])).join(",")),
      ].join("\r\n") +
      "\r\n",
    {
      headers: {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": `attachment; filename="passkey-auth-${name}.csv"`,
        "Cache-Control": "no-store",
      },
    },
  );
}
const iso = (value: unknown) =>
  value ? new Date(Number(value) * 1000).toISOString() : "";
function countItems(
  rows: Record<string, any>[],
  key: string,
  labels: Record<string, string> = {},
  limit = Infinity,
) {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const v = String(row[key] || "unknown");
    counts.set(v, (counts.get(v) || 0) + 1);
  }
  return [...counts]
    .map(([key, count]) => ({ key, label: labels[key] || key, count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
    .slice(0, limit);
}
async function listUsers(c: Context): Promise<any[]> {
  const [users, credentials, policies, entries] = await Promise.all([
    c.store.all<UserRow & { last_login_at: number | null }>(
      "SELECT u.*,(SELECT MAX(created_at) FROM login_history l WHERE l.user_id=u.id AND result='success') last_login_at FROM users u ORDER BY id",
    ),
    c.store.all<any>(
      "SELECT id,user_id,created_at,updated_at,device_type,backed_up,transports,aaguid FROM credentials ORDER BY id",
    ),
    c.store.all<any>("SELECT user_id,mode FROM user_platform_policies"),
    c.store.all<any>(
      "SELECT user_id,client_id FROM user_platform_policy_entries ORDER BY client_id",
    ),
  ]);
  const cm = new Map<number, any[]>(),
    pm = new Map(policies.map((p) => [p.user_id, p.mode])),
    em = new Map<number, string[]>();
  for (const cr of credentials) {
    const rows = cm.get(cr.user_id) || [];
    rows.push({
      id: cr.id,
      createdAt: cr.created_at,
      updatedAt: cr.updated_at,
      deviceType: cr.device_type,
      backedUp: !!cr.backed_up,
      transports: parseJSON(cr.transports, []),
      aaguid: cr.aaguid,
    });
    cm.set(cr.user_id, rows);
  }
  for (const e of entries) {
    const rows = em.get(e.user_id) || [];
    rows.push(e.client_id);
    em.set(e.user_id, rows);
  }
  return users.map((u) => ({
    id: u.id,
    username: u.username,
    sub: u.user_handle,
    createdAt: u.created_at,
    disabledAt: u.disabled_at,
    sessionVersion: u.session_version,
    credentialCount: (cm.get(u.id) || []).length,
    lastLoginAt: u.last_login_at,
    permissions: permissions(u),
    platformPolicy: {
      mode: pm.get(u.id) || "allow_all",
      client_ids: em.get(u.id) || [],
    },
    credentials: cm.get(u.id) || [],
  }));
}
async function overview(c: Context) {
  const [
    users,
    clients,
    loginHistory,
    auditLogs,
    settingsRows,
    telemetrySettings,
    telemetryCount,
  ] = await Promise.all([
    listUsers(c),
    c.store.all<ClientRow>("SELECT * FROM oauth_clients ORDER BY id"),
    c.store.all<any>(
      "SELECT *,username AS username_snapshot FROM login_history ORDER BY created_at DESC,id DESC LIMIT 500",
    ),
    c.store.all<any>(
      "SELECT * FROM audit_logs ORDER BY created_at DESC,id DESC LIMIT 500",
    ),
    c.store.all<{ setting_key: string; setting_value: string }>(
      "SELECT setting_key,setting_value FROM app_settings WHERE setting_key!='telemetry_config'",
    ),
    telemetrySettingsPayload(c),
    telemetryLast24hCount(c),
  ]);
  const settings = Object.fromEntries(
    settingsRows.map((r) => [r.setting_key, r.setting_value]),
  );
  const platforms = clients.map(clientPayload),
    enabled = platforms.filter((p) => p.enabled),
    recent = loginHistory.filter((l) => l.created_at >= now() - 86400);
  const telemetryValue =
    telemetrySettings.backend === "builtin"
      ? telemetryCount
      : telemetrySettings.deliveryMode === "direct"
        ? "直连"
        : telemetrySettings.delivery.queued;
  return json({
    ok: true,
    currentUserId: c.user!.id,
    users,
    platforms,
    loginHistory,
    auditLogs,
    summary: {
      users: {
        value: users.length,
        detail: `${users.filter((u) => u.disabledAt === null).length} 个启用账户`,
      },
      platforms: {
        value: enabled.length,
        detail: `共 ${platforms.length} 个平台`,
      },
      loginSuccessRate24h: {
        value: recent.length
          ? Math.round(
              (recent.filter((l) => l.result === "success").length /
                recent.length) *
                100,
            )
          : null,
        detail: `${recent.length} 次登录尝试`,
      },
      telemetry24h: {
        value: telemetryValue,
        detail:
          telemetrySettings.backend === "builtin"
            ? "24 小时内本地样本"
            : telemetrySettings.deliveryMode === "direct"
              ? "浏览器直接发送"
              : "外部队列等待发送",
        backend: telemetrySettings.backend,
      },
    },
    charts: {
      loginResults: countItems(recent, "result", {
        success: "成功",
        failure: "失败",
      }),
      platformStatus: [
        { key: "enabled", label: "已启用", count: enabled.length },
        {
          key: "disabled",
          label: "已停用",
          count: platforms.length - enabled.length,
        },
      ],
      passkeyCoverage: [
        {
          key: "with-passkey",
          label: "已有 Passkey",
          count: users.filter((u) => u.credentialCount > 0).length,
        },
        {
          key: "without-passkey",
          label: "尚无 Passkey",
          count: users.filter((u) => !u.credentialCount).length,
        },
      ],
      auditActivity: countItems(auditLogs.slice(0, 120), "action", {}, 6),
    },
    registration: {
      mode: settings.registration_mode || "closed",
      enabledUntil: Number(settings.registration_enabled_until) || null,
      defaultDemoAllowed: settings.default_demo_allowed !== "false",
    },
    passkeySettings: {
      algorithms: parseJSON(settings.passkey_algorithms, [-7, -8, -257]),
      authenticatorAttachment:
        settings.passkey_authenticator_attachment || "any",
      residentKey: settings.passkey_resident_key || "required",
      userVerification: settings.passkey_user_verification || "preferred",
      attestation: settings.passkey_attestation || "none",
      excludeCredentials: settings.passkey_exclude_credentials !== "false",
      hints: parseJSON(settings.passkey_hints, [
        "client-device",
        "security-key",
        "hybrid",
      ]),
    },
  });
}

async function channels(c: Context): Promise<Response> {
  const path = c.url.pathname;
  if (path.endsWith("/start") && c.request.method === "POST") {
    csrf(c);
    recent(c);
    const data = await body(c, 4096),
      jwk = data.publicKeyJwk;
    if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256" || jwk.d)
      throw new HTTPError(400, "通道公钥必须使用 P-256 ECDSA");
    let canonical: JsonWebKey;
    try {
      const key = await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"],
      );
      canonical = await crypto.subtle.exportKey("jwk", key);
    } catch {
      throw new HTTPError(400, "通道公钥无效");
    }
    if (!c.session.action_token_hash) tokenError("action_token_missing");
    const ch: Channel = {
      id: random(24),
      user_id: c.user!.id,
      session_hash: c.session.token_hash,
      public_key_jwk: JSON.stringify(canonical),
      server_nonce: random(24),
      last_counter: 0,
      created_at: now(),
      expires_at: now() + 1800,
      last_seen_at: now(),
      ack_after_ms: 45000,
    };
    const auth = actorCondition(c, true);
    try {
      await c.store.guardBatch(
        auth.sql +
          " AND EXISTS(SELECT 1 FROM sessions WHERE token_hash=? AND action_token_hash IS NOT NULL)",
        [...auth.bindings, c.session.token_hash],
        [
          c.env.DB.prepare(
            "DELETE FROM management_channels WHERE session_hash=?",
          ).bind(c.session.token_hash),
          c.env.DB.prepare(
            "INSERT INTO management_channels(id,user_id,session_hash,public_key_jwk,server_nonce,last_counter,created_at,expires_at,last_seen_at,ack_after_ms) VALUES(?,?,?,?,?,?,?,?,?,?)",
          ).bind(...Object.values(ch)),
          c.env.DB.prepare(
            "UPDATE sessions SET data_json=json_set(data_json,'$.management_channel_id',?) WHERE token_hash=?",
          ).bind(ch.id, c.session.token_hash),
        ],
      );
    } catch (e) {
      if (e instanceof StoreConflict) channelError("authorization_changed");
      throw e;
    }
    c.data.management_channel_id = ch.id;
    return json({ ok: true, ...channelPayload(ch) });
  }
  if (path.endsWith("/events") && c.request.method === "GET") {
    const ch = await getChannel(c);
    const nonce = random(24),
      auth = actorCondition(c);
    try {
      await c.store.guardBatch(
        auth.sql +
          " AND EXISTS(SELECT 1 FROM management_channels WHERE id=? AND session_hash=? AND expires_at>?)",
        [...auth.bindings, ch.id, c.session.token_hash, now()],
        [
          c.env.DB.prepare(
            "UPDATE management_channels SET server_nonce=? WHERE id=?",
          ).bind(nonce, ch.id),
        ],
      );
    } catch (e) {
      if (e instanceof StoreConflict)
        return new Response(
          "event: reauth\ndata: " +
            JSON.stringify({
              ok: false,
              reason: "channel_expired",
              reauth_required: true,
            }) +
            "\n\n",
          {
            headers: {
              "Content-Type": "text/event-stream",
              "Cache-Control": "no-store",
            },
          },
        );
      throw e;
    }
    ch.server_nonce = nonce;
    // A bounded SSE response preserves EventSource's native reconnect contract
    // while avoiding a 30-minute invocation accumulating CPU and D1 queries.
    return new Response(
      `retry: ${ch.ack_after_ms}\nevent: challenge\ndata: ${JSON.stringify(channelPayload(ch))}\n\n`,
      {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-store, no-transform",
          "X-Accel-Buffering": "no",
        },
      },
    );
  }
  if (path.endsWith("/ack") && c.request.method === "POST") {
    csrf(c);
    const data = await body(c, 4096),
      ch = await getChannel(c, String(data.channelId || ""));
    const proof = await verifyProof(ch, "ack", "POST", path, data),
      pc = proofCondition(proof),
      auth = actorCondition(c),
      interval = adaptiveAck(data);
    try {
      await c.store.guardBatch(
        `${auth.sql} AND ${pc.sql}`,
        [...auth.bindings, ...pc.bindings],
        [
          c.env.DB.prepare(
            "UPDATE management_channels SET last_counter=?,last_seen_at=?,ack_after_ms=? WHERE id=?",
          ).bind(proof.counter, now(), interval, ch.id),
        ],
      );
    } catch (e) {
      if (e instanceof StoreConflict) channelError("channel_replay");
      throw e;
    }
    ch.last_seen_at = now();
    ch.ack_after_ms = interval;
    return json({ ok: true, ...channelPayload(ch) });
  }
  throw new HTTPError(404, "接口不存在");
}

export async function management(c: Context): Promise<Response | null> {
  const path = c.url.pathname,
    method = c.request.method;
  if (path !== "/management" && !path.startsWith("/api/management/"))
    return null;
  admin(c);
  if (path === "/management" && method === "GET")
    return new Response(
      renderPage("management.html", { csrf_token: c.session.csrf_token }),
      {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
        },
      },
    );
  if (path.startsWith("/api/management/channel/")) return channels(c);
  if (path === "/api/management/overview" && method === "GET")
    return overview(c);
  const write =
    method === "GET"
      ? async (_m: Mutation): Promise<Response> => {
          throw new HTTPError(405, "不支持的操作");
        }
      : await writer(c);
  const telemetryResponse = await telemetryManagement(c, write);
  if (telemetryResponse) return telemetryResponse;
  const userMatch = path.match(
    /^\/api\/management\/users\/(\d+)(?:\/(revoke-sessions|credentials\/\d+))?$/,
  );
  if (userMatch) {
    const id = Number(userMatch[1]),
      operation = userMatch[2],
      target = await c.store.one<UserRow>("SELECT * FROM users WHERE id=?", id);
    if (!target) throw new HTTPError(404, "用户不存在");
    const targetGuard =
        "EXISTS(SELECT 1 FROM users WHERE id=? AND session_version=?)",
      targetBindings = [id, target.session_version];
    if (!operation && method === "PATCH") {
      const data = await body(c),
        p = data.permissions || {},
        next = {
          admin: p.admin === undefined ? target.admin : Number(!!p.admin),
          login: p.login === undefined ? target.login : Number(!!p.login),
          demo: p.demo === undefined ? target.demo : Number(!!p.demo),
        },
        disabled =
          data.disabled === undefined
            ? target.disabled_at !== null
            : !!data.disabled;
      const name = username(
        data.username === undefined ? target.username : data.username,
      );
      const removing = disabled || !next.admin || !next.login;
      if (c.user!.id === id && removing)
        throw new HTTPError(409, "不能停用、降权或关闭自己的登录权限");
      let condition = targetGuard;
      if (target.admin && removing)
        condition +=
          " AND EXISTS(SELECT 1 FROM users WHERE id!=? AND admin=1 AND login=1 AND disabled_at IS NULL)";
      const bindings = [
        ...targetBindings,
        ...(target.admin && removing ? [id] : []),
      ];
      const statements = [
        c.env.DB.prepare(
          "UPDATE users SET username=?,username_key=?,admin=?,login=?,demo=?,disabled_at=?,session_version=session_version+1 WHERE id=?",
        ).bind(
          name,
          usernameKey(name),
          next.admin,
          next.login,
          next.demo,
          disabled ? target.disabled_at || now() : null,
          id,
        ),
      ];
      if (data.platformPolicy !== undefined) {
        const policy = data.platformPolicy;
        if (
          !policy ||
          !["allow_all", "allow_only", "deny_only"].includes(policy.mode) ||
          !Array.isArray(policy.clientIds) ||
          policy.clientIds.length > 500
        )
          throw new HTTPError(400, "平台策略无效");
        const ids = [
          ...new Set(
            policy.clientIds.map((v: unknown) =>
              requiredText(v, 128, "平台 ID"),
            ),
          ),
        ];
        statements.push(
          c.env.DB.prepare(
            "INSERT INTO user_platform_policies(user_id,mode,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET mode=excluded.mode,updated_at=excluded.updated_at",
          ).bind(id, policy.mode, now()),
          c.env.DB.prepare(
            "DELETE FROM user_platform_policy_entries WHERE user_id=?",
          ).bind(id),
          c.env.DB.prepare(
            "INSERT INTO user_platform_policy_entries(user_id,client_id) SELECT ?,value FROM json_each(?)",
          ).bind(id, JSON.stringify(ids)),
        );
      }
      if (c.user!.id === id)
        statements.push(
          c.env.DB.prepare(
            "UPDATE sessions SET user_version=? WHERE token_hash=?",
          ).bind(target.session_version + 1, c.session.token_hash),
        );
      const response = await write({
        statements,
        action: "user.update",
        targetType: "user",
        targetId: String(id),
        details: { username: name },
        condition,
        bindings,
      });
      if (c.user!.id === id) {
        c.user = {
          ...target,
          username: name,
          session_version: target.session_version + 1,
          ...next,
        };
        c.session.user_version = target.session_version + 1;
      }
      return response;
    }
    if (c.user!.id === id)
      throw new HTTPError(
        409,
        method === "DELETE"
          ? "不能在当前控制台删除自己的账户或 Passkey"
          : "不能在当前控制台撤销自己的全部会话",
      );
    if (!operation && method === "DELETE")
      return write({
        statements: [c.env.DB.prepare("DELETE FROM users WHERE id=?").bind(id)],
        action: "user.delete",
        targetType: "user",
        targetId: String(id),
        details: { username: target.username },
        condition:
          targetGuard +
          (target.admin
            ? " AND EXISTS(SELECT 1 FROM users WHERE id!=? AND admin=1 AND login=1 AND disabled_at IS NULL)"
            : ""),
        bindings: [...targetBindings, ...(target.admin ? [id] : [])],
      });
    if (operation === "revoke-sessions" && method === "POST")
      return write({
        statements: [
          c.env.DB.prepare(
            "UPDATE users SET session_version=session_version+1 WHERE id=?",
          ).bind(id),
        ],
        action: "user.revoke_sessions",
        targetType: "user",
        targetId: String(id),
        condition: targetGuard,
        bindings: targetBindings,
      });
    if (operation?.startsWith("credentials/") && method === "DELETE") {
      const credentialId = Number(operation.split("/")[1]);
      if (
        !(await c.store.one(
          "SELECT id FROM credentials WHERE id=? AND user_id=?",
          credentialId,
          id,
        ))
      )
        throw new HTTPError(404, "Passkey 不存在");
      return write({
        statements: [
          c.env.DB.prepare(
            "DELETE FROM credentials WHERE id=? AND user_id=?",
          ).bind(credentialId, id),
          c.env.DB.prepare(
            "UPDATE users SET session_version=session_version+1 WHERE id=?",
          ).bind(id),
        ],
        action: "credential.delete",
        targetType: "user",
        targetId: String(id),
        details: { credentialId },
        condition:
          targetGuard +
          " AND EXISTS(SELECT 1 FROM credentials WHERE id=? AND user_id=?)",
        bindings: [...targetBindings, credentialId, id],
      });
    }
  }
  if (path === "/api/management/platforms" && method === "POST") {
    const data = await body(c),
      id = requiredText(data.clientId, 128, "client_id"),
      name = requiredText(data.name, 160, "平台名称"),
      uris = redirectURIs(data.redirectUris);
    if (!uris.length) throw new HTTPError(400, "回调地址不能为空");
    const secret = random();
    return write({
      statements: [
        c.env.DB.prepare(
          "INSERT INTO oauth_clients(client_id,name,secret_hash,redirect_uris,enabled,is_demo,created_at,updated_at) VALUES(?,?,?,?,1,0,?,?)",
        ).bind(
          id,
          name,
          await hash(secret),
          JSON.stringify(uris),
          now(),
          now(),
        ),
      ],
      action: "platform.create",
      targetType: "platform",
      targetId: id,
      details: { name },
      response: { ok: true, clientSecret: secret },
    });
  }
  const platformMatch = path.match(
    /^\/api\/management\/platforms\/([^/]+)(\/rotate-secret)?$/,
  );
  if (platformMatch) {
    const id = decodeURIComponent(platformMatch[1]),
      target = await c.store.one<ClientRow>(
        "SELECT * FROM oauth_clients WHERE client_id=?",
        id,
      );
    if (!target) throw new HTTPError(404, "平台不存在");
    if (platformMatch[2] && method === "POST") {
      const secret = random();
      return write({
        statements: [
          c.env.DB.prepare(
            "UPDATE oauth_clients SET secret_hash=?,updated_at=? WHERE client_id=?",
          ).bind(await hash(secret), now(), id),
        ],
        action: "platform.rotate_secret",
        targetType: "platform",
        targetId: id,
        response: { ok: true, clientSecret: secret },
        condition: "EXISTS(SELECT 1 FROM oauth_clients WHERE client_id=?)",
        bindings: [id],
      });
    }
    if (!platformMatch[2] && method === "PATCH") {
      const data = await body(c),
        name = requiredText(data.name || id, 160, "平台名称"),
        uris = redirectURIs(data.redirectUris);
      if (!uris.length) throw new HTTPError(400, "回调地址不能为空");
      return write({
        statements: [
          c.env.DB.prepare(
            "UPDATE oauth_clients SET name=?,redirect_uris=?,enabled=?,updated_at=? WHERE client_id=?",
          ).bind(
            name,
            JSON.stringify(uris),
            data.enabled === false ? 0 : 1,
            now(),
            id,
          ),
        ],
        action: "platform.update",
        targetType: "platform",
        targetId: id,
        condition: "EXISTS(SELECT 1 FROM oauth_clients WHERE client_id=?)",
        bindings: [id],
      });
    }
    if (!platformMatch[2] && method === "DELETE") {
      if (target.is_demo)
        throw new HTTPError(409, "不能删除内置平台，可以将其停用");
      return write({
        statements: [
          c.env.DB.prepare("DELETE FROM oauth_clients WHERE client_id=?").bind(
            id,
          ),
          c.env.DB.prepare(
            "DELETE FROM user_platform_policy_entries WHERE client_id=?",
          ).bind(id),
        ],
        action: "platform.delete",
        targetType: "platform",
        targetId: id,
        condition:
          "EXISTS(SELECT 1 FROM oauth_clients WHERE client_id=? AND is_demo=0)",
        bindings: [id],
      });
    }
  }
  if (path === "/api/management/settings/registration" && method === "PATCH") {
    const data = await body(c),
      mode = String(data.mode || "closed"),
      until = mode === "temporary" ? beforeValue(data.enabledUntil) : null;
    if (!["closed", "open", "temporary"].includes(mode))
      throw new HTTPError(400, "无效的注册模式");
    if (mode === "temporary" && (!until || until <= now()))
      throw new HTTPError(400, "临时开放时间必须晚于当前时间");
    return write({
      statements: [
        setting(c, "registration_mode", mode),
        setting(c, "registration_enabled_until", until ? String(until) : ""),
        setting(
          c,
          "default_demo_allowed",
          data.defaultDemoAllowed === false ? "false" : "true",
        ),
      ],
      action: "registration.update",
      targetType: "settings",
      targetId: "registration",
      details: { mode },
    });
  }
  if (path === "/api/management/settings/passkey" && method === "PATCH") {
    const d = await body(c),
      algs = Array.isArray(d.algorithms)
        ? [...new Set<number>(d.algorithms)]
        : [],
      hints = Array.isArray(d.hints) ? [...new Set<string>(d.hints)] : [];
    if (
      !algs.length ||
      algs.some(
        (v) => ![-7, -8, -36, -37, -38, -39, -257, -258, -259].includes(v),
      )
    )
      throw new HTTPError(400, "至少选择一种受支持的公钥签名算法");
    const options: Record<string, [string, string[]]> = {
      authenticatorAttachment: ["any", ["any", "platform", "cross-platform"]],
      residentKey: ["required", ["discouraged", "preferred", "required"]],
      userVerification: ["preferred", ["discouraged", "preferred", "required"]],
      attestation: ["none", ["none", "indirect", "direct", "enterprise"]],
    };
    for (const [key, [fallback, allowed]] of Object.entries(options)) {
      d[key] = d[key] || fallback;
      if (!allowed.includes(d[key]))
        throw new HTTPError(400, "Passkey 设置无效");
    }
    if (
      hints.some(
        (v) => !["client-device", "security-key", "hybrid"].includes(v),
      )
    )
      throw new HTTPError(400, "无效的认证器提示");
    return write({
      statements: [
        setting(c, "passkey_algorithms", JSON.stringify(algs)),
        setting(
          c,
          "passkey_authenticator_attachment",
          d.authenticatorAttachment,
        ),
        setting(c, "passkey_resident_key", d.residentKey),
        setting(c, "passkey_user_verification", d.userVerification),
        setting(c, "passkey_attestation", d.attestation),
        setting(
          c,
          "passkey_exclude_credentials",
          d.excludeCredentials === false ? "false" : "true",
        ),
        setting(c, "passkey_hints", JSON.stringify(hints)),
      ],
      action: "passkey_settings.update",
      targetType: "settings",
      targetId: "passkey",
      details: {
        algorithms: algs,
        residentKey: d.residentKey,
        userVerification: d.userVerification,
      },
    });
  }
  const logsMatch = path.match(
    /^\/api\/management\/logs\/(login|audit)\/(count|clear)$/,
  );
  if (logsMatch) {
    const type = logsMatch[1],
      table = type === "login" ? "login_history" : "audit_logs",
      before = beforeValue(
        method === "GET"
          ? c.url.searchParams.get("before")
          : (await body(c)).before,
      ),
      where = before === null ? "" : " WHERE created_at<?",
      bindings = before === null ? [] : [before];
    if (logsMatch[2] === "count" && method === "GET") {
      const count = await c.store.one<{ count: number }>(
        `SELECT COUNT(*) count FROM ${table}${where}`,
        ...bindings,
      );
      return json({ ok: true, count: count!.count });
    }
    if (logsMatch[2] === "clear" && method === "POST")
      return write({
        statements: [
          c.env.DB.prepare(`DELETE FROM ${table}${where}`).bind(...bindings),
          c.env.DB.prepare(
            "INSERT INTO maintenance_events(actor_user_id,actor_username,log_type,deleted_count,created_at) VALUES(?,?,?,changes(),?)",
          ).bind(c.user!.id, c.user!.username, type, now()),
        ],
        action: "",
        response: (r) => ({ ok: true, deleted: r[0].meta.changes }),
      });
  }
  const exportMatch = path.match(
    /^\/api\/management\/export\/(users|platforms|login-history|audit-logs)\.csv$/,
  );
  if (exportMatch && method === "GET") {
    const type = exportMatch[1];
    let rows: Record<string, unknown>[], fields: string[];
    if (type === "users") {
      rows = (await listUsers(c)).map((u) => ({
        id: u.id,
        username: u.username,
        sub: u.sub,
        ...u.permissions,
        disabled_at: iso(u.disabledAt),
        created_at: iso(u.createdAt),
        credential_count: u.credentialCount,
        last_login_at: iso(u.lastLoginAt),
        platform_policy_mode: u.platformPolicy.mode,
        platform_client_ids: u.platformPolicy.client_ids.join(","),
      }));
      fields = [
        "id",
        "username",
        "sub",
        "admin",
        "login",
        "demo",
        "disabled_at",
        "created_at",
        "credential_count",
        "last_login_at",
        "platform_policy_mode",
        "platform_client_ids",
      ];
    } else if (type === "platforms") {
      rows = (
        await c.store.all<ClientRow>("SELECT * FROM oauth_clients ORDER BY id")
      ).map((p) => ({
        client_id: p.client_id,
        name: p.name,
        redirect_uris: parseJSON<string[]>(p.redirect_uris, []).join(","),
        enabled: !!p.enabled,
        is_demo: !!p.is_demo,
        created_at: iso(p.created_at),
        updated_at: iso(p.updated_at),
      }));
      fields = [
        "client_id",
        "name",
        "redirect_uris",
        "enabled",
        "is_demo",
        "created_at",
        "updated_at",
      ];
    } else {
      rows = await c.store.all<any>(
        type === "login-history"
          ? "SELECT *,username AS username_snapshot FROM login_history ORDER BY created_at DESC,id DESC LIMIT 100000"
          : "SELECT * FROM audit_logs ORDER BY created_at DESC,id DESC LIMIT 100000",
      );
      rows = rows.map((r) => ({ ...r, created_at: iso(r.created_at) }));
      fields =
        type === "login-history"
          ? [
              "id",
              "user_id",
              "username_snapshot",
              "sub_snapshot",
              "client_id",
              "flow",
              "result",
              "credential_hint",
              "ip_address",
              "user_agent",
              "created_at",
            ]
          : [
              "id",
              "actor_user_id",
              "actor_username",
              "action",
              "target_type",
              "target_id",
              "details",
              "ip_address",
              "user_agent",
              "created_at",
            ];
    }
    return csvResponse(fields, rows, type);
  }
  throw new HTTPError(404, "接口不存在");
}
