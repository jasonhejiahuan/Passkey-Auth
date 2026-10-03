-- Fresh native Worker database. No user or administrator is implicitly created.
-- Timestamps are Unix seconds; opaque secrets are stored only as hashes.
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  username_key TEXT NOT NULL UNIQUE,
  user_handle TEXT NOT NULL UNIQUE,
  session_version INTEGER NOT NULL DEFAULT 1 CHECK (session_version >= 1),
  disabled_at INTEGER,
  admin INTEGER NOT NULL DEFAULT 0 CHECK (admin IN (0, 1)),
  login INTEGER NOT NULL DEFAULT 1 CHECK (login IN (0, 1)),
  demo INTEGER NOT NULL DEFAULT 1 CHECK (demo IN (0, 1)),
  created_at INTEGER NOT NULL
);
CREATE TABLE credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  transports TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(transports)),
  aaguid TEXT,
  credential_type TEXT NOT NULL DEFAULT 'public-key',
  device_type TEXT,
  backed_up INTEGER NOT NULL DEFAULT 0 CHECK (backed_up IN (0, 1)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX credentials_user ON credentials(user_id);
CREATE TABLE oauth_clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  secret_hash TEXT NOT NULL,
  redirect_uris TEXT NOT NULL CHECK (json_valid(redirect_uris)),
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  is_demo INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0, 1)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE user_platform_policies (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  mode TEXT NOT NULL DEFAULT 'allow_all' CHECK (mode IN ('allow_all', 'allow_only', 'deny_only')),
  updated_at INTEGER NOT NULL
);
CREATE TABLE user_platform_policy_entries (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL,
  PRIMARY KEY (user_id, client_id)
);
CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  csrf_token TEXT NOT NULL,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  user_version INTEGER,
  reauthenticated_at INTEGER,
  action_token_hash TEXT,
  data_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(data_json)),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_expiry ON sessions(expires_at);
CREATE TABLE ceremonies (
  id TEXT PRIMARY KEY,
  session_hash TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
  purpose TEXT NOT NULL,
  challenge TEXT NOT NULL,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  user_handle TEXT,
  username TEXT,
  username_key TEXT,
  context_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(context_json)),
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE INDEX ceremonies_session ON ceremonies(session_hash, purpose);
CREATE INDEX ceremonies_expiry ON ceremonies(expires_at);
CREATE TABLE registration_reservations (
  username_key TEXT PRIMARY KEY,
  ceremony_id TEXT NOT NULL UNIQUE REFERENCES ceremonies(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE TABLE oauth_requests (
  id TEXT PRIMARY KEY,
  session_hash TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  state TEXT NOT NULL,
  pkce_challenge TEXT NOT NULL DEFAULT '',
  username TEXT,
  screen_hint TEXT NOT NULL DEFAULT '',
  authenticated_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  authenticated_user_version INTEGER,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE INDEX oauth_requests_session ON oauth_requests(session_hash);
CREATE INDEX oauth_requests_expiry ON oauth_requests(expires_at);
CREATE TABLE oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_version INTEGER NOT NULL,
  pkce_challenge TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE INDEX oauth_codes_expiry ON oauth_codes(expires_at);
CREATE TABLE access_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_version INTEGER NOT NULL,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  demo_required INTEGER NOT NULL DEFAULT 0 CHECK (demo_required IN (0, 1)),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX access_tokens_expiry ON access_tokens(expires_at);
CREATE INDEX access_tokens_user ON access_tokens(user_id);
CREATE TABLE oauth_challenges (
  challenge_id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  return_uri TEXT NOT NULL,
  username TEXT NOT NULL,
  username_key TEXT NOT NULL,
  state TEXT NOT NULL,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  user_version INTEGER,
  result_hash TEXT,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  completed_at INTEGER,
  consumed_at INTEGER
);
CREATE INDEX oauth_challenges_expiry ON oauth_challenges(expires_at);
CREATE TABLE admin_recovery_tokens (
  token_hash TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE TABLE management_channels (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_hash TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
  public_key_jwk TEXT NOT NULL CHECK (json_valid(public_key_jwk)),
  server_nonce TEXT NOT NULL,
  last_counter INTEGER NOT NULL DEFAULT 0 CHECK (last_counter >= 0),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  ack_after_ms INTEGER NOT NULL DEFAULT 45000 CHECK (ack_after_ms BETWEEN 30000 AND 300000)
);
CREATE INDEX management_channels_session ON management_channels(session_hash);
CREATE TABLE app_settings (
  setting_key TEXT PRIMARY KEY,
  setting_value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE login_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  username TEXT,
  sub_snapshot TEXT,
  client_id TEXT,
  flow TEXT NOT NULL,
  result TEXT NOT NULL,
  credential_hint TEXT,
  ip_address TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX login_history_created ON login_history(created_at);
CREATE INDEX login_history_user ON login_history(user_id, created_at);
CREATE TABLE audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  actor_username TEXT,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  details TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(details)),
  ip_address TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX audit_logs_created ON audit_logs(created_at);
CREATE TABLE maintenance_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  actor_username TEXT,
  log_type TEXT NOT NULL,
  deleted_count INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE user_telemetry_policies (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  mode TEXT NOT NULL CHECK (mode IN ('inherit', 'off', 'custom')),
  features TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(features)),
  revision INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL
);
CREATE TABLE telemetry_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_id TEXT NOT NULL UNIQUE,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  policy_key TEXT NOT NULL,
  path TEXT NOT NULL,
  referrer_origin TEXT,
  os_family TEXT,
  browser_family TEXT,
  device_class TEXT,
  features TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(features)),
  signals TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(signals)),
  payload_bytes INTEGER NOT NULL,
  ip_hash TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX telemetry_events_created ON telemetry_events(created_at);
CREATE INDEX telemetry_events_user ON telemetry_events(user_id, created_at);
CREATE TABLE telemetry_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  policy_key TEXT NOT NULL,
  features TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(features)),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);
CREATE INDEX telemetry_tokens_expiry ON telemetry_tokens(expires_at);
CREATE TABLE telemetry_receipts (
  token_id TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL,
  state TEXT NOT NULL
);
CREATE INDEX telemetry_receipts_expiry ON telemetry_receipts(expires_at);
CREATE TABLE delivery_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  attempted INTEGER NOT NULL DEFAULT 0,
  delivered INTEGER NOT NULL DEFAULT 0,
  failed INTEGER NOT NULL DEFAULT 0,
  dropped INTEGER NOT NULL DEFAULT 0,
  queued INTEGER NOT NULL DEFAULT 0,
  last_status TEXT,
  last_attempt_at INTEGER,
  last_success_at INTEGER,
  updated_at INTEGER NOT NULL
);
-- A failed guard is a constraint error, so D1 rolls back the entire batch.
-- Successful transactions delete their receipt before they commit.
CREATE TABLE operation_guards (
  id TEXT PRIMARY KEY,
  allowed INTEGER NOT NULL CONSTRAINT operation_authorized CHECK (allowed = 1)
);
