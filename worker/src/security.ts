import type { Context } from "./types";
export const now = () => Math.floor(Date.now() / 1000);
export function b64(v: Uint8Array) {
  return btoa(String.fromCharCode(...v))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}
export function unb64(v: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(v.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
    c.charCodeAt(0),
  );
}
export function random(size = 32) {
  return b64(crypto.getRandomValues(new Uint8Array(size)));
}
export async function hash(v: string) {
  return b64(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)),
    ),
  );
}
export async function equal(a: string, b: string) {
  const x = await hash(a),
    y = await hash(b);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return d === 0;
}
export class HTTPError extends Error {
  constructor(
    public status: number,
    message: string,
    public extra: Record<string, unknown> = {},
  ) {
    super(message);
  }
}
export const json = (v: unknown, status = 200, headers: HeadersInit = {}) =>
  new Response(JSON.stringify(v), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers,
    },
  });
export const redirect = (url: string, status = 302) =>
  new Response(null, {
    status,
    headers: { Location: url, "Cache-Control": "no-store" },
  });
export async function body(c: Context, limit = 65536): Promise<any> {
  if (Number(c.request.headers.get("content-length") || 0) > limit)
    throw new HTTPError(413, "Request too large.");
  const reader = c.request.body?.getReader();
  if (!reader) return {};
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > limit) {
      await reader.cancel();
      throw new HTTPError(413, "Request too large.");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  const text = new TextDecoder().decode(bytes);
  if (
    c.request.headers
      .get("content-type")
      ?.includes("application/x-www-form-urlencoded")
  )
    return Object.fromEntries(new URLSearchParams(text));
  try {
    const value = JSON.parse(text || "{}");
    if (!value || typeof value !== "object" || Array.isArray(value))
      throw new Error();
    return value;
  } catch {
    throw new HTTPError(400, "Invalid JSON.");
  }
}
export function sameOrigin(c: Context) {
  if (c.request.headers.get("origin") !== c.env.PASSKEY_ORIGIN)
    throw new HTTPError(403, "Invalid request origin.");
}
export function username(value: unknown) {
  const raw = String(value ?? "");
  // Reject before trimming/normalizing, which could erase a control character
  // or turn a different whitespace character into an ordinary space.
  if (/[\u0000-\u001f\u007f-\u009f]|[^\S ]/u.test(raw))
    throw new HTTPError(400, "Invalid username.");
  const name = raw.trim().normalize("NFKC");
  if (!name || name.length > 64 || !/^[\p{L}\p{N}_.@+\- ]+$/u.test(name))
    throw new HTTPError(400, "Invalid username.");
  return name;
}
export const usernameKey = (v: string) => v.normalize("NFKC").toLowerCase();
export function safeReturn(value: unknown) {
  const v = String(value || "/");
  return v.startsWith("/") &&
    !v.startsWith("//") &&
    !/[\\\u0000-\u0020\u007f]/.test(v)
    ? v
    : "/";
}
export function cookie(c: Context, v: string) {
  c.cookies.push(
    `session=${v}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200${c.url.protocol === "https:" ? "; Secure" : ""}`,
  );
}
export async function ensureSession(c: Context) {
  if (!c.pendingSessionToken) return;
  const state = JSON.stringify(c.data),
    s = c.session;
  await c.store.run(
    "INSERT INTO sessions(token_hash,csrf_token,user_id,user_version,reauthenticated_at,action_token_hash,data_json,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
    s.token_hash,
    s.csrf_token,
    s.user_id,
    s.user_version,
    s.reauthenticated_at,
    s.action_token_hash,
    state,
    s.created_at,
    s.expires_at,
  );
  cookie(c, c.pendingSessionToken);
  c.session.data_json = state;
  delete c.pendingSessionToken;
}
export async function saveData(c: Context) {
  if (c.pendingSessionToken) {
    await ensureSession(c);
    return;
  }
  const state = JSON.stringify(c.data);
  const before = JSON.parse(c.session.data_json) as Record<string, unknown>,
    patch: Record<string, unknown> = {};
  for (const key of new Set([...Object.keys(before), ...Object.keys(c.data)])) {
    if (JSON.stringify(before[key]) !== JSON.stringify(c.data[key]))
      patch[key] = c.data[key] ?? null;
  }
  // Only merge this request's changes. A concurrent management channel update
  // must not disappear when an auth page saves its unrelated flow token.
  if (Object.keys(patch).length)
    await c.store.run(
      "UPDATE sessions SET data_json=json_patch(data_json,?) WHERE token_hash=? AND expires_at>?",
      JSON.stringify(patch),
      c.session.token_hash,
      now(),
    );
  c.session.data_json = state;
}
