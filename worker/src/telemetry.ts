import type { Context } from "./types";
import { body, hash, random, now, json, HTTPError } from "./security";
import { StoreConflict } from "./store";
import type { ManagementWriter } from "./management";

export const TELEMETRY_FEATURES = [
  "screen",
  "hardware",
  "fonts",
  "battery",
  "network",
  "preferences",
] as const;
type Feature = (typeof TELEMETRY_FEATURES)[number];
interface Config {
  enabled: boolean;
  anonymousEnabled: boolean;
  defaultFeatures: Feature[];
  retentionDays: number;
  backend: "builtin" | "jason" | "custom";
  deliveryMode: "relay" | "direct";
  jasonBaseUrl: string;
  jasonApiKey: string;
  customUrl: string;
  customAuthMode: "none" | "bearer" | "header";
  customAuthHeader: string;
  customSecret: string;
  customHeaders: Record<string, string>;
  customDirectContentType: "text/plain" | "application/json";
  timeoutSeconds: number;
  revision: string;
}
interface Snapshot {
  config: Config;
  raw: string;
}
interface Policy {
  user_id: number;
  mode: "inherit" | "off" | "custom";
  features: string;
  revision: number;
  updated_at: number;
}
interface Decision {
  features: Feature[];
  policyKey: string;
  condition: string;
  bindings: unknown[];
}
interface TokenRow {
  token_hash: string;
  user_id: number | null;
  policy_key: string;
  features: string;
  created_at: number;
  expires_at: number;
  consumed_at: number | null;
}
const defaults: Config = {
  enabled: false,
  anonymousEnabled: false,
  defaultFeatures: ["screen", "hardware", "preferences"],
  retentionDays: 30,
  backend: "builtin",
  deliveryMode: "relay",
  jasonBaseUrl: "",
  jasonApiKey: "",
  customUrl: "",
  customAuthMode: "none",
  customAuthHeader: "X-Api-Key",
  customSecret: "",
  customHeaders: {},
  customDirectContentType: "text/plain",
  timeoutSeconds: 1,
  revision: "initial",
};
const configCache = new WeakMap<Context, Promise<Snapshot>>();
function object(value: unknown): value is Record<string, any> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
function parse<T>(value: string | undefined | null, fallback: T): T {
  try {
    return JSON.parse(value || "") as T;
  } catch {
    return fallback;
  }
}
function configSnapshot(c: Context): Promise<Snapshot> {
  let promise = configCache.get(c);
  if (!promise) {
    promise = c.store
      .one<{
        setting_value: string;
      }>(
        "SELECT setting_value FROM app_settings WHERE setting_key=?",
        "telemetry_config",
      )
      .then((row) => ({
        config: {
          ...defaults,
          ...parse<Partial<Config>>(row?.setting_value, {}),
        },
        raw: row?.setting_value || "",
      }));
    configCache.set(c, promise);
  }
  return promise;
}
export async function telemetryEnabled(c: Context): Promise<boolean> {
  return (await configSnapshot(c)).config.enabled;
}
function configCondition(snapshot: Snapshot) {
  return {
    condition:
      "COALESCE((SELECT setting_value FROM app_settings WHERE setting_key='telemetry_config'),'')=?",
    bindings: [snapshot.raw] as unknown[],
  };
}
function featureList(value: unknown): Feature[] {
  if (
    !Array.isArray(value) ||
    value.some((v) => !TELEMETRY_FEATURES.includes(v))
  )
    throw new HTTPError(400, "遥测能力必须是受支持的列表");
  return TELEMETRY_FEATURES.filter((f) => value.includes(f));
}
function sensitiveHeader(name: string) {
  return /authorization|cookie|token|secret|api[-_]?key|credential|pass(word|phrase)/i.test(
    name,
  );
}
function headerName(name: unknown): string {
  const s = String(name || "");
  if (
    !/^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}$/.test(s) ||
    /^(host|content-length|content-type|connection|transfer-encoding|set-cookie|proxy-.*|sec-.*)$/i.test(
      s,
    )
  )
    throw new HTTPError(400, "自定义 Header 名称无效");
  return s;
}
function secret(value: unknown): string {
  const s = String(value || "");
  if (s.length > 8192 || /[\r\n\u0000]/.test(s))
    throw new HTTPError(400, "密钥格式无效");
  return s;
}
/** Admin-configurable integrations cannot address local or metadata services. */
export function externalURL(value: unknown, required = true): string {
  const input = String(value || "").trim();
  if (!input && !required) return "";
  let u: URL;
  try {
    u = new URL(input);
  } catch {
    throw new HTTPError(400, "遥测地址必须是完整 HTTPS URL");
  }
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (
    u.protocol !== "https:" ||
    u.username ||
    u.password ||
    u.hash ||
    input.length > 2048 ||
    !host.includes(".") ||
    host.includes(":") ||
    /^\d+(?:\.\d+)*$/.test(host) ||
    /\.(localhost|local|internal|home|lan|invalid|test)$/.test(host) ||
    host === "localhost" ||
    host === "metadata.google.internal" ||
    host === "metadata.azure.internal"
  )
    throw new HTTPError(
      400,
      "遥测地址必须是公开 HTTPS 域名，不能使用本地或 IP 地址",
    );
  return u.toString();
}
export function validateTelemetryConfig(
  input: Record<string, any>,
  old: Config = defaults,
): Config {
  const c: Config = {
    ...old,
    enabled: !!input.enabled,
    anonymousEnabled: !!input.anonymousEnabled,
    defaultFeatures: featureList(input.defaultFeatures || []),
    retentionDays: Number(input.retentionDays || 30),
    revision: random(16),
  };
  for (const key of [
    "backend",
    "deliveryMode",
    "customAuthMode",
    "customDirectContentType",
  ] as const)
    if (input[key] !== undefined) (c as any)[key] = String(input[key]);
  if (
    !["builtin", "jason", "custom"].includes(c.backend) ||
    !["relay", "direct"].includes(c.deliveryMode) ||
    !["none", "bearer", "header"].includes(c.customAuthMode) ||
    !["text/plain", "application/json"].includes(c.customDirectContentType)
  )
    throw new HTTPError(400, "遥测后端设置无效");
  if (
    !Number.isInteger(c.retentionDays) ||
    c.retentionDays < 1 ||
    c.retentionDays > 365
  )
    throw new HTTPError(400, "保留天数必须介于 1 与 365");
  if (input.timeoutSeconds !== undefined)
    c.timeoutSeconds = Number(input.timeoutSeconds);
  if (
    !Number.isFinite(c.timeoutSeconds) ||
    c.timeoutSeconds < 0.2 ||
    c.timeoutSeconds > 5
  )
    throw new HTTPError(400, "请求超时必须介于 0.2 与 5 秒");
  if (input.jasonBaseUrl !== undefined)
    c.jasonBaseUrl = externalURL(input.jasonBaseUrl, false).replace(/\/$/, "");
  if (input.customUrl !== undefined)
    c.customUrl = externalURL(input.customUrl, false);
  if (input.customAuthHeader !== undefined)
    c.customAuthHeader = headerName(input.customAuthHeader || "X-Api-Key");
  for (const [key, clear] of [
    ["jasonApiKey", "clearJasonApiKey"],
    ["customSecret", "clearCustomSecret"],
  ] as const) {
    if (input[clear]) c[key] = "";
    else if (input[key]) c[key] = secret(input[key]);
  }
  if (input.customHeaders !== undefined) {
    if (
      !object(input.customHeaders) ||
      Object.keys(input.customHeaders).length > 20
    )
      throw new HTTPError(400, "自定义 Headers 必须是对象");
    c.customHeaders = {};
    for (const [name, value] of Object.entries(input.customHeaders)) {
      const n = headerName(name);
      c.customHeaders[n] =
        value === "[configured]" && old.customHeaders[n]
          ? old.customHeaders[n]
          : secret(value);
    }
  }
  if (c.enabled && !c.defaultFeatures.length)
    throw new HTTPError(400, "启用遥测时至少选择一种采集能力");
  if (c.backend === "builtin" && c.deliveryMode !== "relay")
    throw new HTTPError(400, "内置 Telemetry 只能由 Passkey-Auth 服务端接收");
  if (c.enabled && c.backend === "jason" && (!c.jasonBaseUrl || !c.jasonApiKey))
    throw new HTTPError(
      400,
      "启用 Jason Telemetry 时必须配置服务地址和 API Key",
    );
  if (c.enabled && c.backend === "custom" && !c.customUrl)
    throw new HTTPError(400, "启用自定义 Telemetry 时必须配置 POST 地址");
  if (
    c.enabled &&
    c.backend === "custom" &&
    c.customAuthMode !== "none" &&
    !c.customSecret
  )
    throw new HTTPError(400, "所选自定义认证方式需要配置密钥");
  if (
    c.backend === "custom" &&
    c.deliveryMode === "direct" &&
    (c.customAuthMode !== "none" ||
      Object.keys(c.customHeaders).some(sensitiveHeader))
  )
    throw new HTTPError(400, "浏览器直连不能包含私有密钥、令牌或 Cookie");
  return c;
}
async function decision(
  c: Context,
  snapshot: Snapshot,
  userId: number | null,
): Promise<Decision | null> {
  const cfg = snapshot.config;
  if (!cfg.enabled) return null;
  const guard = configCondition(snapshot);
  let features: Feature[] = cfg.defaultFeatures,
    revision = "anonymous";
  if (userId === null) {
    if (!cfg.anonymousEnabled) return null;
  } else {
    const [user, policy] = await Promise.all([
      c.store.one<{ id: number }>(
        "SELECT id FROM users WHERE id=? AND login=1 AND disabled_at IS NULL",
        userId,
      ),
      c.store.one<Policy>(
        "SELECT * FROM user_telemetry_policies WHERE user_id=?",
        userId,
      ),
    ]);
    if (!user || policy?.mode === "off") return null;
    guard.condition +=
      " AND EXISTS(SELECT 1 FROM users WHERE id=? AND login=1 AND disabled_at IS NULL)";
    guard.bindings.push(userId);
    if (policy) {
      if (policy.mode === "custom")
        features = parse<Feature[]>(policy.features, []);
      revision = String(policy.revision);
      guard.condition +=
        " AND EXISTS(SELECT 1 FROM user_telemetry_policies WHERE user_id=? AND revision=? AND mode=? AND features=?)";
      guard.bindings.push(
        userId,
        policy.revision,
        policy.mode,
        policy.features,
      );
    } else {
      revision = "inherit";
      guard.condition +=
        " AND NOT EXISTS(SELECT 1 FROM user_telemetry_policies WHERE user_id=?)";
      guard.bindings.push(userId);
    }
  }
  if (!features.length) return null;
  return {
    features,
    policyKey: (
      await hash(
        `${userId || 0}:${cfg.revision}:${revision}:${features.join(",")}`,
      )
    ).slice(0, 24),
    ...guard,
  };
}
export async function telemetryConnectOrigin(c: Context): Promise<string> {
  const cfg = (await configSnapshot(c)).config;
  if (
    !cfg.enabled ||
    cfg.deliveryMode !== "direct" ||
    cfg.backend === "builtin"
  )
    return "";
  return new URL(
    externalURL(cfg.backend === "jason" ? cfg.jasonBaseUrl : cfg.customUrl),
  ).origin;
}
export async function telemetryHTML(c: Context, html: string): Promise<string> {
  // Management and recovery are never collection surfaces.
  if (
    c.url.pathname === "/management" ||
    c.url.pathname.startsWith("/api/") ||
    !/^\/(?:$|auth\/passkey$|demo(?:\/|$)|oauth\/(?:authorize|challenge\/))/.test(
      c.url.pathname,
    )
  )
    return html;
  const snapshot = await configSnapshot(c);
  if (
    !snapshot.config.enabled ||
    !html.includes("</body>") ||
    html.includes("data-passkey-telemetry-token")
  )
    return html;
  const d = await decision(c, snapshot, c.user?.id ?? null);
  if (!d) return html;
  const token = random(),
    tokenHash = await hash(token),
    time = now();
  try {
    await c.store.guardBatch(d.condition, d.bindings, [
      c.env.DB.prepare(
        "INSERT INTO telemetry_tokens(token_hash,user_id,policy_key,features,created_at,expires_at) VALUES(?,?,?,?,?,?)",
      ).bind(
        tokenHash,
        c.user?.id ?? null,
        d.policyKey,
        JSON.stringify(d.features),
        time,
        time + 300,
      ),
    ]);
  } catch (e) {
    if (e instanceof StoreConflict) return html;
    throw e;
  }
  const endpoint =
    snapshot.config.deliveryMode === "direct"
      ? "/api/telemetry/direct-target"
      : "/api/telemetry/collect";
  const script = `<script defer src="/static/telemetry.js" data-passkey-telemetry-endpoint="${endpoint}" data-passkey-telemetry-delivery="${snapshot.config.deliveryMode}" data-passkey-telemetry-token="${token}" data-passkey-telemetry-policy="${d.policyKey}" data-passkey-telemetry-features="${d.features.join(",")}"></script>`;
  return html.replace("</body>", `${script}</body>`);
}
const signalKeys: Record<Feature, string[]> = {
  screen: [
    "width",
    "height",
    "availableWidth",
    "availableHeight",
    "pixelRatio",
    "colorDepth",
    "orientation",
  ],
  hardware: [
    "logicalProcessors",
    "deviceMemoryGb",
    "architecture",
    "bitness",
    "model",
  ],
  fonts: ["platform", "available"],
  battery: [
    "supported",
    "charging",
    "levelBucket",
    "chargingTimeBucket",
    "dischargingTimeBucket",
  ],
  network: [
    "supported",
    "effectiveType",
    "downlinkBucket",
    "rttBucket",
    "saveData",
  ],
  preferences: ["colorScheme", "reducedMotion", "contrast", "forcedColors"],
};
function text(value: unknown, max: number) {
  return String(value ?? "")
    .trim()
    .slice(0, max);
}
function browserFamily(ua: string) {
  const value = ua.toLowerCase();
  return /edg\//.test(value)
    ? "edge"
    : /firefox\/|fxios\//.test(value)
      ? "firefox"
      : /chrome\/|crios\//.test(value)
        ? "chrome"
        : /safari\//.test(value)
          ? "safari"
          : "other";
}
export function normalizeTelemetry(
  payload: Record<string, any>,
  features: Feature[],
  ua: string,
): Record<string, any> {
  if (
    !Array.isArray(payload.features) ||
    JSON.stringify(
      TELEMETRY_FEATURES.filter((f) => payload.features.includes(f)),
    ) !== JSON.stringify(features) ||
    !object(payload.signals)
  )
    throw new HTTPError(400, "telemetry_payload_invalid");
  const signals: Record<string, any> = {};
  for (const feature of features) {
    const value = payload.signals[feature];
    if (!object(value)) throw new HTTPError(400, "telemetry_payload_invalid");
    signals[feature] = {};
    for (const key of signalKeys[feature]) {
      const v = value[key];
      if (typeof v === "boolean") signals[feature][key] = v;
      else if (typeof v === "number" && Number.isFinite(v))
        signals[feature][key] = Math.round(v * 100) / 100;
      else if (typeof v === "string") signals[feature][key] = text(v, 80);
      else if (key === "available" && Array.isArray(v))
        signals[feature][key] = v
          .slice(0, 16)
          .map((f) => text(f, 80))
          .filter(Boolean);
    }
  }
  const client = object(payload.client) ? payload.client : {},
    os = String(client.osFamily || "other"),
    device = String(client.deviceClass || "desktop");
  let path = text(payload.path, 320).split(/[?#]/)[0];
  if (!path.startsWith("/") || path.startsWith("//")) path = "/";
  let referrer = "";
  try {
    const u = new URL(String(payload.referrerOrigin || ""));
    if (["https:", "http:"].includes(u.protocol))
      referrer = u.origin.slice(0, 240);
  } catch {}
  return {
    path,
    referrer_origin: referrer,
    os_family: [
      "windows",
      "macos",
      "ios",
      "android",
      "linux",
      "chromeos",
      "other",
    ].includes(os)
      ? os
      : "other",
    browser_family: browserFamily(ua),
    device_class: ["desktop", "tablet", "mobile"].includes(device)
      ? device
      : "desktop",
    features,
    signals,
  };
}
async function validatedToken(
  c: Context,
  snapshot: Snapshot,
  token: unknown,
): Promise<{ row: TokenRow; decision: Decision }> {
  if (typeof token !== "string" || !/^[A-Za-z0-9_-]{40,64}$/.test(token))
    throw new HTTPError(403, "telemetry_token_invalid");
  const row = await c.store.one<TokenRow>(
    "SELECT * FROM telemetry_tokens WHERE token_hash=?",
    await hash(token),
  );
  if (!row) throw new HTTPError(403, "telemetry_token_invalid");
  if (row.expires_at <= now())
    throw new HTTPError(410, "telemetry_token_expired");
  const d = await decision(c, snapshot, row.user_id);
  if (
    !d ||
    d.policyKey !== row.policy_key ||
    JSON.stringify(d.features) !== row.features
  )
    throw new HTTPError(409, "telemetry_policy_changed");
  return { row, decision: d };
}
async function takeToken(
  c: Context,
  row: TokenRow,
  d: Decision,
  statements: D1PreparedStatement[],
): Promise<boolean> {
  try {
    await c.store.guardBatch(
      `${d.condition} AND EXISTS(SELECT 1 FROM telemetry_tokens WHERE token_hash=? AND consumed_at IS NULL AND expires_at>?)`,
      [...d.bindings, row.token_hash, now()],
      [
        c.env.DB.prepare(
          "UPDATE telemetry_tokens SET consumed_at=? WHERE token_hash=?",
        ).bind(now(), row.token_hash),
        ...statements,
      ],
    );
    return true;
  } catch (e) {
    if (e instanceof StoreConflict) {
      const live = await c.store.one<TokenRow>(
        "SELECT * FROM telemetry_tokens WHERE token_hash=?",
        row.token_hash,
      );
      if (live?.consumed_at) return false;
      throw new HTTPError(409, "telemetry_policy_changed");
    }
    throw e;
  }
}
async function boundedBody(c: Context, limit: number) {
  try {
    const data = await body(c, limit);
    if (!object(data)) throw new HTTPError(400, "telemetry_payload_invalid");
    return data;
  } catch (e) {
    if (e instanceof HTTPError)
      throw new HTTPError(
        e.status,
        e.status === 413
          ? "telemetry_payload_too_large"
          : "telemetry_payload_invalid",
      );
    throw e;
  }
}
async function fetchBackend(
  url: string,
  method: string,
  payload: unknown,
  headers: Record<string, string>,
  timeout: number,
  expectJSON = true,
): Promise<Record<string, any>> {
  const target = externalURL(url);
  const response = await fetch(target, {
    method,
    headers: {
      Accept: "application/json",
      ...(payload !== undefined ? { "Content-Type": "application/json" } : {}),
      ...headers,
    },
    body: payload === undefined ? undefined : JSON.stringify(payload),
    redirect: "manual",
    signal: AbortSignal.timeout(Math.ceil(timeout * 1000)),
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`telemetry_http_${response.status}`);
  }
  const reader = response.body?.getReader();
  let size = 0,
    raw = "";
  const decoder = new TextDecoder();
  if (reader)
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 65536) {
        await reader.cancel();
        throw new Error("telemetry_invalid_response");
      }
      raw += decoder.decode(value, { stream: true });
    }
  raw += decoder.decode();
  if (!expectJSON || !raw) return {};
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    throw new Error("telemetry_invalid_response");
  }
  if (!object(data)) throw new Error("telemetry_invalid_response");
  return data;
}
function customHeaders(cfg: Config) {
  const headers = { ...cfg.customHeaders };
  if (cfg.customAuthMode === "bearer")
    headers.Authorization = `Bearer ${cfg.customSecret}`;
  if (cfg.customAuthMode === "header")
    headers[cfg.customAuthHeader] = cfg.customSecret;
  return headers;
}
function jasonURL(cfg: Config, suffix: string) {
  return `${cfg.jasonBaseUrl.replace(/\/$/, "")}/v12/${encodeURIComponent(cfg.jasonApiKey)}/${suffix}`;
}
function externalPayload(event: Record<string, any>) {
  return {
    event: "passkey_auth.browser_telemetry",
    timestamp: new Date().toISOString(),
    source: "passkey-auth",
    schema_version: 1,
    subject: { user_id: event.user_id, anonymous: event.user_id === null },
    telemetry: {
      path: event.path,
      referrer_origin: event.referrer_origin,
      client: {
        os_family: event.os_family,
        browser_family: event.browser_family,
        device_class: event.device_class,
      },
      features: event.features,
      signals: event.signals,
      payload_bytes: event.payload_bytes,
      policy_key: event.policy_key,
      ip_hash: event.ip_hash,
    },
  };
}
function safeBackendError(error: unknown) {
  return error instanceof Error && /^telemetry_[a-z0-9_]+$/.test(error.message)
    ? error.message
    : "telemetry_unavailable";
}
async function deliver(
  c: Context,
  cfg: Config,
  event: Record<string, any>,
  tokenHash: string,
) {
  let error = "";
  try {
    if (cfg.backend === "jason")
      await fetchBackend(
        jasonURL(cfg, "telemetry"),
        "POST",
        externalPayload(event),
        {},
        cfg.timeoutSeconds,
      );
    else
      await fetchBackend(
        cfg.customUrl,
        "POST",
        externalPayload(event),
        customHeaders(cfg),
        cfg.timeoutSeconds,
        false,
      );
  } catch (e) {
    error = safeBackendError(e);
  }
  const time = now();
  await c.store.batch([
    c.env.DB.prepare(
      "UPDATE telemetry_receipts SET state=? WHERE token_id=?",
    ).bind(error ? "failed" : "sent", tokenHash),
    c.env.DB.prepare(
      "UPDATE delivery_state SET queued=MAX(0,queued-1),delivered=delivered+?,failed=failed+?,last_status=?,last_success_at=CASE WHEN ?=1 THEN ? ELSE last_success_at END,updated_at=? WHERE id=1",
    ).bind(
      error ? 0 : 1,
      error ? 1 : 0,
      error || "sent",
      error ? 0 : 1,
      time,
      time,
    ),
  ]);
}
async function directTarget(
  cfg: Config,
  metadata: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (cfg.backend === "custom") {
    if (
      cfg.customAuthMode !== "none" ||
      Object.keys(cfg.customHeaders).some(sensitiveHeader)
    )
      throw new Error("telemetry_direct_private_auth");
    return {
      url: externalURL(cfg.customUrl),
      headers: cfg.customHeaders,
      contentType: cfg.customDirectContentType,
      opaque:
        cfg.customDirectContentType === "text/plain" &&
        Object.keys(cfg.customHeaders).length === 0,
    };
  }
  const response = await fetchBackend(
      jasonURL(cfg, "browser-collection-token"),
      "POST",
      metadata,
      {},
      cfg.timeoutSeconds,
    ),
    token = String(response.token || "");
  if (!token || token.length > 4096 || token === cfg.jasonApiKey)
    throw new Error("telemetry_invalid_token_response");
  return {
    url: `${cfg.jasonBaseUrl}/v12/browser/${encodeURIComponent(token)}/device-info-submit`,
    headers: {},
    contentType: "text/plain;charset=UTF-8",
    opaque: true,
  };
}
export async function telemetry(c: Context): Promise<Response | null> {
  if (!c.url.pathname.startsWith("/api/telemetry/")) return null;
  if (c.request.method !== "POST")
    throw new HTTPError(405, "Method not allowed.");
  const snapshot = await configSnapshot(c),
    cfg = snapshot.config;
  if (!cfg.enabled) throw new HTTPError(404, "telemetry_disabled");
  if (c.url.pathname === "/api/telemetry/browser-token") {
    const tokenURL = String(c.env.PASSKEY_TELEMETRY_TOKEN_URL || ""),
      key = String(c.env.PASSKEY_TELEMETRY_API_KEY || "");
    if (!tokenURL || !key) throw new HTTPError(404, "telemetry_not_configured");
    if (!(await decision(c, snapshot, c.user?.id ?? null)))
      throw new HTTPError(403, "telemetry_policy_changed");
    const payload = await boundedBody(c, 4096);
    try {
      const result = await fetchBackend(
        tokenURL,
        "POST",
        {
          event: "passkey_auth.browser_visit",
          source: "passkey-auth",
          path: text(payload.path, 320).split(/[?#]/)[0],
          referrer: text(payload.referrer, 240),
        },
        { "X-Api-Key": key },
        Math.min(
          5,
          Math.max(0.2, Number(c.env.PASSKEY_TELEMETRY_TIMEOUT_SECONDS) || 1),
        ),
      );
      const status = String(
        result.status_url || result.statusUrl || result.status_path || "",
      );
      if (!status) throw new HTTPError(502, "telemetry_missing_status_url");
      if (status.includes(key) || status.includes(encodeURIComponent(key)))
        throw new HTTPError(502, "telemetry_invalid_response");
      return json({
        ok: true,
        statusUrl: externalURL(new URL(status, tokenURL).toString()),
      });
    } catch (e) {
      if (e instanceof HTTPError && e.status === 502) throw e;
      throw new HTTPError(503, "telemetry_unavailable");
    }
  }
  if (c.url.pathname === "/api/telemetry/collect") {
    if (cfg.deliveryMode === "direct")
      throw new HTTPError(409, "telemetry_uses_direct_delivery");
    const payload = await boundedBody(c, 16384),
      { row, decision: d } = await validatedToken(c, snapshot, payload.token);
    if (row.consumed_at) return json({ ok: true, duplicate: true }, 202);
    const event: Record<string, any> = {
      ...normalizeTelemetry(
        payload,
        d.features,
        c.request.headers.get("User-Agent") || "",
      ),
      token_id: row.token_hash,
      user_id: row.user_id,
      policy_key: d.policyKey,
      payload_bytes: new TextEncoder().encode(JSON.stringify(payload)).length,
      ip_hash: (
        await hash(
          row.token_hash +
            ":" +
            (c.request.headers.get("CF-Connecting-IP") || ""),
        )
      ).slice(0, 24),
    };
    if (cfg.backend === "builtin") {
      const accepted = await takeToken(c, row, d, [
        c.env.DB.prepare(
          "INSERT INTO telemetry_events(token_id,user_id,policy_key,path,referrer_origin,os_family,browser_family,device_class,features,signals,payload_bytes,ip_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ).bind(
          event.token_id,
          event.user_id,
          event.policy_key,
          event.path,
          event.referrer_origin,
          event.os_family,
          event.browser_family,
          event.device_class,
          JSON.stringify(event.features),
          JSON.stringify(event.signals),
          event.payload_bytes,
          event.ip_hash,
          now(),
        ),
      ]);
      return json({ ok: true, duplicate: !accepted }, 202);
    }
    // A claim is counted only while its Worker can still be delivering it.
    // Expired jobs never block the bounded queue, including after isolate termination.
    const queueCondition =
      "(SELECT COUNT(*) FROM telemetry_receipts WHERE state='queued' AND expires_at>?)<128";
    let accepted: boolean;
    try {
      accepted = await takeToken(
        c,
        row,
        {
          ...d,
          condition: `${d.condition} AND ${queueCondition}`,
          bindings: [...d.bindings, now()],
        },
        [
          c.env.DB.prepare(
            "INSERT INTO telemetry_receipts(token_id,expires_at,state) VALUES(?,?,?)",
          ).bind(row.token_hash, now() + 30, "queued"),
          c.env.DB.prepare(
            "INSERT INTO delivery_state(id,attempted,queued,last_status,last_attempt_at,updated_at) VALUES(1,1,1,'queued',?,?) ON CONFLICT(id) DO UPDATE SET attempted=attempted+1,queued=queued+1,last_status='queued',last_attempt_at=excluded.last_attempt_at,updated_at=excluded.updated_at",
          ).bind(now(), now()),
        ],
      );
    } catch (e) {
      if (e instanceof HTTPError && e.status === 409) {
        const queued = await c.store.one<{ n: number }>(
          "SELECT COUNT(*) n FROM telemetry_receipts WHERE state='queued' AND expires_at>?",
          now(),
        );
        if ((queued?.n || 0) >= 128) {
          await c.store.run(
            "UPDATE delivery_state SET dropped=dropped+1 WHERE id=1",
          );
          return json(
            { ok: true, duplicate: false, queued: false, dropped: true },
            202,
          );
        }
      }
      throw e;
    }
    if (accepted)
      c.executionCtx.waitUntil(deliver(c, cfg, event, row.token_hash));
    return json(
      { ok: true, duplicate: !accepted, queued: accepted, dropped: false },
      202,
    );
  }
  if (c.url.pathname === "/api/telemetry/direct-target") {
    if (cfg.backend === "builtin" || cfg.deliveryMode !== "direct")
      throw new HTTPError(404, "telemetry_direct_unavailable");
    const payload = await boundedBody(c, 4096),
      { row, decision: d } = await validatedToken(c, snapshot, payload.token);
    if (row.consumed_at || !(await takeToken(c, row, d, [])))
      throw new HTTPError(409, "telemetry_token_used");
    try {
      return json({
        ok: true,
        target: await directTarget(cfg, {
          source: "passkey-auth",
          user_id: row.user_id,
          features: d.features,
          policy_key: d.policyKey,
        }),
      });
    } catch {
      // A timeout may follow successful issuance at the external server. Never
      // unconsume the token; a fresh page load issues a new collection capability.
      throw new HTTPError(503, "telemetry_backend_unavailable");
    }
  }
  throw new HTTPError(404, "接口不存在");
}

function emptyStats() {
  return {
    summary: {
      total: 0,
      last24h: 0,
      identifiedUsers: 0,
      anonymous: 0,
      averagePayloadBytes: 0,
      latestAt: null as number | null,
    },
    distributions: {
      operatingSystems: [] as any[],
      browsers: [] as any[],
      devices: [] as any[],
      features: [] as any[],
    },
    recent: [] as any[],
  };
}
function eventPayload(row: Record<string, any>) {
  return {
    id: row.id,
    userId: row.user_id,
    path: row.path,
    referrerOrigin: row.referrer_origin || "",
    osFamily: row.os_family,
    browserFamily: row.browser_family,
    deviceClass: row.device_class,
    features: parse(row.features, []),
    signals: parse(row.signals, {}),
    payloadBytes: row.payload_bytes,
    createdAt: row.created_at,
  };
}
export async function telemetryLast24hCount(c: Context): Promise<number> {
  const cfg = (await configSnapshot(c)).config;
  if (cfg.backend !== "builtin") return 0;
  // The overview needs only this indexed count. Historical events remain
  // visible to administrators even when collection is currently paused.
  const row = await c.store.one<{ count: number }>(
    "SELECT COUNT(*) count FROM telemetry_events WHERE created_at>=?",
    now() - 86400,
  );
  return row?.count || 0;
}

export async function telemetryStatistics(c: Context) {
  const cfg = (await configSnapshot(c)).config;
  // Only explicit administrator views call this function. Pausing collection
  // must not erase or disguise previously collected history in those views.
  if (cfg.backend !== "builtin") return emptyStats();
  const [s, rows, os, browsers, devices, features] = await Promise.all([
    c.store.one<any>(
      "SELECT COUNT(*) total,SUM(created_at>=?) last24h,COUNT(DISTINCT user_id) identifiedUsers,SUM(user_id IS NULL) anonymous,COALESCE(AVG(payload_bytes),0) averagePayloadBytes,MAX(created_at) latestAt FROM telemetry_events",
      now() - 86400,
    ),
    c.store.all<any>(
      "SELECT id,user_id,path,referrer_origin,os_family,browser_family,device_class,features,signals,payload_bytes,created_at FROM telemetry_events ORDER BY created_at DESC,id DESC LIMIT 60",
    ),
    c.store.all<any>(
      "SELECT os_family label,COUNT(*) count FROM telemetry_events GROUP BY os_family ORDER BY count DESC,label",
    ),
    c.store.all<any>(
      "SELECT browser_family label,COUNT(*) count FROM telemetry_events GROUP BY browser_family ORDER BY count DESC,label",
    ),
    c.store.all<any>(
      "SELECT device_class label,COUNT(*) count FROM telemetry_events GROUP BY device_class ORDER BY count DESC,label",
    ),
    c.store.all<any>(
      "SELECT j.value label,COUNT(*) count FROM telemetry_events e,json_each(e.features) j GROUP BY j.value ORDER BY count DESC,label",
    ),
  ]);
  return {
    summary: {
      total: s.total || 0,
      last24h: s.last24h || 0,
      identifiedUsers: s.identifiedUsers || 0,
      anonymous: s.anonymous || 0,
      averagePayloadBytes: Math.round(s.averagePayloadBytes || 0),
      latestAt: s.latestAt,
    },
    distributions: { operatingSystems: os, browsers, devices, features },
    recent: rows.map(eventPayload),
  };
}
export async function telemetrySettingsPayload(c: Context) {
  const cfg = (await configSnapshot(c)).config;
  const state =
    cfg.backend !== "builtin"
      ? await c.store.one<any>(
          "SELECT *, (SELECT COUNT(*) FROM telemetry_receipts WHERE state='queued' AND expires_at>?) active_queued FROM delivery_state WHERE id=1",
          now(),
        )
      : null;
  const publicHeaders = Object.fromEntries(
    Object.entries(cfg.customHeaders).map(([k, v]) => [
      k,
      sensitiveHeader(k) ? "[configured]" : v,
    ]),
  );
  return {
    enabled: cfg.enabled,
    anonymousEnabled: cfg.anonymousEnabled,
    defaultFeatures: cfg.defaultFeatures,
    retentionDays: cfg.retentionDays,
    backend: cfg.backend,
    deliveryMode: cfg.deliveryMode,
    availableBackends: ["builtin", "jason", "custom"],
    availableDeliveryModes: ["relay", "direct"],
    jason: { baseUrl: cfg.jasonBaseUrl, apiKeyConfigured: !!cfg.jasonApiKey },
    custom: {
      url: cfg.customUrl,
      authMode: cfg.customAuthMode,
      authHeader: cfg.customAuthHeader,
      secretConfigured: !!cfg.customSecret,
      headers: publicHeaders,
      directContentType: cfg.customDirectContentType,
    },
    timeoutSeconds: cfg.timeoutSeconds,
    localStorageActive: cfg.backend === "builtin",
    delivery: {
      state:
        cfg.backend === "builtin"
          ? "builtin"
          : !cfg.enabled
            ? "idle"
            : state?.active_queued
              ? "running"
              : "idle",
      queued: state?.active_queued || 0,
      sent: state?.delivered || 0,
      failed: state?.failed || 0,
      dropped: state?.dropped || 0,
      lastError: state?.last_status?.startsWith("telemetry_")
        ? state.last_status
        : "",
      lastAttemptAt: state?.last_attempt_at ?? null,
      lastSuccessAt: state?.last_success_at ?? null,
    },
    availableFeatures: [...TELEMETRY_FEATURES],
  };
}
function settingStatement(c: Context, cfg: Config) {
  return c.env.DB.prepare(
    "INSERT INTO app_settings(setting_key,setting_value,updated_at) VALUES(?,?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=excluded.updated_at",
  ).bind("telemetry_config", JSON.stringify(cfg), now());
}
function before(value: unknown) {
  if (value === null || value === undefined || value === "") return null;
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new HTTPError(400, "时间无效");
  return n;
}
function csvCell(v: unknown) {
  let s = v == null ? "" : String(v);
  if (/^[\s]*[=+@-]/.test(s) || /^[\t\r\n]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}
async function pairingProof(code: string, message: string) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(code),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return [
    ...new Uint8Array(
      await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)),
    ),
  ]
    .map((v) => v.toString(16).padStart(2, "0"))
    .join("");
}
export async function telemetryManagement(
  c: Context,
  write: ManagementWriter,
): Promise<Response | null> {
  const path = c.url.pathname,
    method = c.request.method;
  if (path === "/api/management/telemetry" && method === "GET") {
    const [settings, statistics, policies] = await Promise.all([
      telemetrySettingsPayload(c),
      telemetryStatistics(c),
      c.store.all<Policy>("SELECT * FROM user_telemetry_policies"),
    ]);
    return json({
      ok: true,
      settings,
      userPolicies: Object.fromEntries(
        policies.map((p) => [
          String(p.user_id),
          { mode: p.mode, features: parse(p.features, []) },
        ]),
      ),
      statistics,
      charts: statistics.distributions,
    });
  }
  if (path === "/api/management/settings/telemetry" && method === "PATCH") {
    const snapshot = await configSnapshot(c),
      data = await body(c),
      cfg = validateTelemetryConfig(data, snapshot.config),
      guard = configCondition(snapshot);
    const response = await write({
      statements: [settingStatement(c, cfg)],
      action: "telemetry_settings.update",
      targetType: "settings",
      targetId: "telemetry",
      details: {
        enabled: cfg.enabled,
        anonymousEnabled: cfg.anonymousEnabled,
        defaultFeatures: cfg.defaultFeatures,
        retentionDays: cfg.retentionDays,
        backend: cfg.backend,
        deliveryMode: cfg.deliveryMode,
      },
      ...guard,
    });
    configCache.delete(c);
    return response;
  }
  if (path === "/api/management/telemetry/backend/test" && method === "POST") {
    const snapshot = await configSnapshot(c),
      cfg = snapshot.config;
    return write({
      statements: [],
      action: "telemetry_backend.test",
      targetType: "settings",
      targetId: "telemetry",
      details: { backend: cfg.backend },
      ...configCondition(snapshot),
      prepare: async () => {
        const started = Date.now();
        try {
          if (cfg.backend === "jason")
            await fetchBackend(
              jasonURL(cfg, "status"),
              "GET",
              undefined,
              {},
              cfg.timeoutSeconds,
            );
          else if (cfg.backend === "custom")
            await fetchBackend(
              cfg.customUrl,
              "POST",
              {
                event: "passkey_auth.telemetry_test",
                timestamp: new Date().toISOString(),
                source: "passkey-auth",
                test: true,
              },
              customHeaders(cfg),
              cfg.timeoutSeconds,
              false,
            );
        } catch {
          throw new HTTPError(502, "遥测后端连接失败");
        }
        return {
          response:
            cfg.backend === "builtin"
              ? { ok: true, backend: "builtin", message: "内置事件库可用" }
              : {
                  ok: true,
                  backend: cfg.backend,
                  latencyMs: Date.now() - started,
                },
        };
      },
    });
  }
  if (
    path === "/api/management/telemetry/backend/pair-jason" &&
    method === "POST"
  ) {
    const snapshot = await configSnapshot(c),
      data = await body(c, 8192),
      url = externalURL(data.baseUrl).replace(/\/$/, ""),
      code = secret(data.pairingCode).trim(),
      timeout = Number(data.timeoutSeconds || 1),
      nonce = random(24);
    if (
      !code ||
      code.length > 1024 ||
      !Number.isFinite(timeout) ||
      timeout < 0.2 ||
      timeout > 5 ||
      !["relay", "direct"].includes(data.deliveryMode || "relay")
    )
      throw new HTTPError(400, "Jason Telemetry 地址、一次性配对码或超时无效");
    const response = await write({
      statements: [],
      action: "telemetry_backend.pair",
      targetType: "settings",
      targetId: "telemetry",
      ...configCondition(snapshot),
      prepare: async () => {
        let result: Record<string, any>;
        try {
          const challenge = await fetchBackend(
            url + "/v13/integrations/passkey-auth/pairing/challenge",
            "POST",
            {
              client_nonce: nonce,
              proof: await pairingProof(
                code,
                `passkey-auth-pairing-request-v1:${nonce}`,
              ),
            },
            {},
            timeout,
          );
          const id = String(challenge.challenge_id || ""),
            serverNonce = String(challenge.server_nonce || "");
          if (
            !id ||
            !serverNonce ||
            id.length > 1024 ||
            serverNonce.length > 1024
          )
            throw new Error("telemetry_invalid_pairing_challenge");
          result = await fetchBackend(
            url + "/v13/integrations/passkey-auth/pairing/complete",
            "POST",
            {
              challenge_id: id,
              client_nonce: nonce,
              proof: await pairingProof(
                code,
                `passkey-auth-pairing-complete-v1:${id}:${nonce}:${serverNonce}`,
              ),
              client: { name: "Passkey-Auth", integration_version: 1 },
            },
            {},
            timeout,
          );
        } catch {
          throw new HTTPError(502, "自动配对失败，请检查地址、配对码和 TLS");
        }
        if (!result.api_key)
          throw new HTTPError(502, "Jason Telemetry 未返回 API Key");
        const cfg = validateTelemetryConfig(
          {
            ...snapshot.config,
            backend: "jason",
            deliveryMode: data.deliveryMode || "relay",
            jasonBaseUrl: url,
            jasonApiKey: result.api_key,
            timeoutSeconds: timeout,
          },
          snapshot.config,
        );
        return {
          statements: [settingStatement(c, cfg)],
          details: {
            backend: "jason",
            serverVersion: text(result.server_version, 100),
          },
          response: {
            ok: true,
            backend: "jason",
            apiKeyConfigured: true,
            serverVersion: text(result.server_version, 100),
          },
        };
      },
    });
    configCache.delete(c);
    return response;
  }
  const policyMatch = path.match(
    /^\/api\/management\/users\/(\d+)\/telemetry$/,
  );
  if (policyMatch && method === "PATCH") {
    const id = Number(policyMatch[1]),
      data = await body(c, 4096),
      mode = String(data.mode || "inherit"),
      features = featureList(data.features || []);
    if (
      !["inherit", "off", "custom"].includes(mode) ||
      (mode === "custom" && !features.length)
    )
      throw new HTTPError(400, "用户遥测策略无效");
    if (!(await c.store.one("SELECT id FROM users WHERE id=?", id)))
      throw new HTTPError(400, "用户不存在");
    return write({
      statements: [
        c.env.DB.prepare(
          "INSERT INTO user_telemetry_policies(user_id,mode,features,revision,updated_at) VALUES(?,?,?,1,?) ON CONFLICT(user_id) DO UPDATE SET mode=excluded.mode,features=excluded.features,revision=revision+1,updated_at=excluded.updated_at",
        ).bind(id, mode, JSON.stringify(features), now()),
      ],
      action: "user.telemetry.update",
      targetType: "user",
      targetId: String(id),
      details: { mode, features },
      condition: "EXISTS(SELECT 1 FROM users WHERE id=?)",
      bindings: [id],
    });
  }
  if (
    path === "/api/management/telemetry/events/count" ||
    path === "/api/management/telemetry/events/clear" ||
    path === "/api/management/export/telemetry.csv"
  ) {
    const snapshot = await configSnapshot(c);
    if (snapshot.config.backend !== "builtin")
      throw new HTTPError(409, "当前遥测后端不使用内置事件库");
    if (path.endsWith("/count") && method === "GET") {
      const cutoff = before(c.url.searchParams.get("before")),
        row = await c.store.one<{ count: number }>(
          "SELECT COUNT(*) count FROM telemetry_events" +
            (cutoff === null ? "" : " WHERE created_at<?"),
          ...(cutoff === null ? [] : [cutoff]),
        );
      return json({ ok: true, count: row!.count });
    }
    if (path.endsWith("/clear") && method === "POST") {
      const cutoff = before((await body(c, 4096)).before);
      return write({
        statements: [
          c.env.DB.prepare(
            "DELETE FROM telemetry_events" +
              (cutoff === null ? "" : " WHERE created_at<?"),
          ).bind(...(cutoff === null ? [] : [cutoff])),
        ],
        action: "telemetry.clear",
        auditChangedRows: true,
        targetType: "telemetry",
        targetId: "events",
        details: { before: cutoff },
        response: (r) => ({ ok: true, deleted: r[0].meta.changes }),
        ...configCondition(snapshot),
      });
    }
    if (path.endsWith(".csv") && method === "GET") {
      const fields = [
          "id",
          "user_id",
          "path",
          "referrer_origin",
          "os_family",
          "browser_family",
          "device_class",
          "features",
          "signals",
          "payload_bytes",
          "created_at",
        ],
        rows = await c.store.all<any>(
          "SELECT id,user_id,path,referrer_origin,os_family,browser_family,device_class,features,signals,payload_bytes,created_at FROM telemetry_events ORDER BY created_at DESC,id DESC LIMIT 100000",
        );
      return new Response(
        "\ufeff" +
          fields.join(",") +
          "\r\n" +
          rows
            .map((r) => fields.map((k) => csvCell(r[k])).join(","))
            .join("\r\n"),
        {
          headers: {
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition":
              'attachment; filename="passkey-auth-telemetry.csv"',
            "Cache-Control": "no-store",
          },
        },
      );
    }
  }
  return null;
}

/** Called by the scheduled maintenance handler, never by an auth hot path. */
export async function pruneTelemetry(c: Context): Promise<void> {
  const cfg = (await configSnapshot(c)).config;
  if (!cfg.enabled) return;
  await c.store.batch([
    c.env.DB.prepare("DELETE FROM telemetry_tokens WHERE expires_at<?").bind(
      now(),
    ),
    c.env.DB.prepare("DELETE FROM telemetry_receipts WHERE expires_at<?").bind(
      now(),
    ),
    ...(cfg.backend === "builtin"
      ? [
          c.env.DB.prepare(
            "DELETE FROM telemetry_events WHERE created_at<?",
          ).bind(now() - cfg.retentionDays * 86400),
        ]
      : []),
    c.env.DB.prepare(
      "UPDATE delivery_state SET queued=(SELECT COUNT(*) FROM telemetry_receipts WHERE state='queued' AND expires_at>?) WHERE id=1",
    ).bind(now()),
  ]);
}
