import type { Store } from "./store";
export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  PASSKEY_RP_ID: string;
  PASSKEY_RP_NAME?: string;
  PASSKEY_ORIGIN: string;
  PASSKEY_SERVER_API_TOKEN?: string;
  PASSKEY_TELEMETRY_API_KEY?: string;
  PASSKEY_TELEMETRY_URL?: string;
  PASSKEY_TELEMETRY_PROJECT_ID?: string;
  [key: string]: unknown;
}
export interface UserRow {
  id: number;
  username: string;
  username_key: string;
  user_handle: string;
  session_version: number;
  disabled_at: number | null;
  admin: number;
  login: number;
  demo: number;
  created_at: number;
}
export interface SessionRow {
  token_hash: string;
  csrf_token: string;
  user_id: number | null;
  user_version: number | null;
  reauthenticated_at: number | null;
  action_token_hash: string | null;
  data_json: string;
  created_at: number;
  expires_at: number;
}
export interface Context {
  request: Request;
  url: URL;
  env: Env;
  executionCtx: ExecutionContext;
  store: Store;
  session: SessionRow;
  user: UserRow | null;
  data: Record<string, any>;
  cookies: string[];
  pendingSessionToken?: string;
}
export interface ClientRow {
  id: number;
  client_id: string;
  name: string;
  secret_hash: string;
  redirect_uris: string;
  enabled: number;
  is_demo: number;
  created_at: number;
  updated_at: number;
}
