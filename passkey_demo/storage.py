from __future__ import annotations

import json
import sqlite3
import time
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

_OAUTH_CODE_KDF_ALGORITHM = "pbkdf2_sha256"
_OAUTH_CODE_KDF_ITERATIONS = 120_000
_OAUTH_CODE_KDF_SALT = b"passkey-auth:oauth-authorization-code:v1"
_SECRET_KDF_ITERATIONS = 120_000
_SCHEMA_VERSION = 2


@dataclass(frozen=True)
class User:
    id: int
    username: str
    user_handle: bytes
    created_at: int
    session_version: int
    disabled_at: int | None


@dataclass(frozen=True)
class StoredCredential:
    id: int
    user_id: int
    credential_id: bytes
    public_key: bytes
    sign_count: int
    transports: list[str]
    aaguid: str | None
    credential_type: str | None
    device_type: str | None
    backed_up: bool
    created_at: int
    updated_at: int


@dataclass(frozen=True)
class OAuthAuthorizationCode:
    id: int
    client_id: str
    redirect_uri: str
    user_id: int
    created_at: int
    expires_at: int
    consumed_at: int | None


@dataclass(frozen=True)
class OAuthChallengeRequest:
    id: int
    challenge_id: str
    client_id: str
    return_uri: str
    username: str
    state: str
    created_at: int
    expires_at: int
    completed_at: int | None
    consumed_at: int | None
    user_id: int | None


@dataclass(frozen=True)
class OAuthClient:
    id: int
    client_id: str
    name: str
    redirect_uris: list[str]
    enabled: bool
    is_demo: bool
    created_at: int
    updated_at: int


@dataclass(frozen=True)
class RegistrationSettings:
    mode: str
    enabled_until: int | None
    default_demo_allowed: bool


@dataclass(frozen=True)
class PasskeySettings:
    algorithms: list[int]
    authenticator_attachment: str
    resident_key: str
    user_verification: str
    attestation: str
    exclude_credentials: bool
    hints: list[str]


class PasskeyStore:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self._memory_connection: sqlite3.Connection | None = None
        if self.database_path.parent:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.init()

    def connect(self) -> sqlite3.Connection:
        if str(self.database_path) == ":memory:" and self._memory_connection is not None:
            return self._memory_connection
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if str(self.database_path) == ":memory:":
            self._memory_connection = conn
        return conn

    def init(self) -> None:
        with self.connect() as conn:
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            existing = conn.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                LIMIT 1
                """
            ).fetchone()
            if existing and version != _SCHEMA_VERSION:
                raise RuntimeError(
                    "Unsupported Passkey-Auth database. Start with a new SQLite "
                    "database for the v2 management schema."
                )
            if existing and version == _SCHEMA_VERSION:
                return
            conn.executescript(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    user_handle BLOB NOT NULL UNIQUE,
                    session_version INTEGER NOT NULL DEFAULT 1,
                    disabled_at INTEGER,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    credential_id BLOB NOT NULL UNIQUE,
                    public_key BLOB NOT NULL,
                    sign_count INTEGER NOT NULL DEFAULT 0,
                    transports TEXT NOT NULL DEFAULT '[]',
                    aaguid TEXT,
                    credential_type TEXT,
                    device_type TEXT,
                    backed_up INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE oauth_clients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    secret_hash TEXT NOT NULL,
                    redirect_uris TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    is_demo INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE user_permissions (
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    permission_key TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    PRIMARY KEY (user_id, permission_key)
                );

                CREATE TABLE user_platform_policies (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    mode TEXT NOT NULL DEFAULT 'allow_all'
                        CHECK (mode IN ('allow_all', 'allow_only', 'deny_only')),
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE user_platform_policy_entries (
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    client_id TEXT NOT NULL,
                    PRIMARY KEY (user_id, client_id)
                );

                CREATE TABLE oauth_authorization_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code_hash TEXT NOT NULL UNIQUE,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER
                );

                CREATE TABLE oauth_challenge_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    challenge_id TEXT NOT NULL UNIQUE,
                    client_id TEXT NOT NULL,
                    return_uri TEXT NOT NULL,
                    username TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    completed_at INTEGER,
                    consumed_at INTEGER,
                    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
                );

                CREATE TABLE login_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    username_snapshot TEXT,
                    sub_snapshot TEXT,
                    client_id TEXT,
                    flow TEXT NOT NULL,
                    result TEXT NOT NULL,
                    credential_hint TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    actor_username TEXT,
                    action TEXT NOT NULL,
                    target_type TEXT,
                    target_id TEXT,
                    details TEXT NOT NULL DEFAULT '{}',
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE maintenance_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    actor_username TEXT,
                    log_type TEXT NOT NULL,
                    deleted_count INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE app_settings (
                    setting_key TEXT PRIMARY KEY,
                    setting_value TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE admin_recovery_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_hash TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL,
                    consumed_at INTEGER
                );

                CREATE TABLE registration_reservations (
                    username TEXT PRIMARY KEY COLLATE NOCASE,
                    reservation_token TEXT NOT NULL UNIQUE,
                    expires_at INTEGER NOT NULL
                );

                CREATE INDEX idx_login_history_created_at ON login_history(created_at);
                CREATE INDEX idx_login_history_user_id ON login_history(user_id);
                CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
                """
            )
            conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    def get_user_by_username(self, username: str) -> User | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, username, user_handle, session_version, disabled_at, created_at
                FROM users WHERE username = ?
                """,
                (username,),
            ).fetchone()
        return _user_from_row(row) if row else None

    def get_user_by_id(self, user_id: int) -> User | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, username, user_handle, session_version, disabled_at, created_at
                FROM users WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
        return _user_from_row(row) if row else None

    def get_user_by_handle(self, user_handle: bytes) -> User | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, username, user_handle, session_version, disabled_at, created_at
                FROM users WHERE user_handle = ?
                """,
                (user_handle,),
            ).fetchone()
        return _user_from_row(row) if row else None

    def create_user(self, username: str, user_handle: bytes) -> User:
        now = int(time.time())
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO users (username, user_handle, session_version, created_at)
                VALUES (?, ?, 1, ?)
                """,
                (username, user_handle, now),
            )
            user_id = int(cursor.lastrowid)
        return User(
            id=user_id,
            username=username,
            user_handle=user_handle,
            created_at=now,
            session_version=1,
            disabled_at=None,
        )

    def list_users(self) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT u.id, u.username, u.user_handle, u.session_version,
                       u.disabled_at, u.created_at,
                       COUNT(DISTINCT c.id) AS credential_count,
                       MAX(l.created_at) AS last_login_at
                FROM users u
                LEFT JOIN credentials c ON c.user_id = u.id
                LEFT JOIN login_history l
                  ON l.user_id = u.id AND l.result = 'success'
                GROUP BY u.id
                ORDER BY u.username COLLATE NOCASE
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def rename_user(self, user_id: int, username: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE users SET username = ? WHERE id = ?",
                (username, user_id),
            )

    def set_user_disabled(self, user_id: int, disabled: bool) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE users
                SET disabled_at = ?, session_version = session_version + 1
                WHERE id = ?
                """,
                (int(time.time()) if disabled else None, user_id),
            )

    def bump_session_version(self, user_id: int) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE users SET session_version = session_version + 1 WHERE id = ?",
                (user_id,),
            )

    def delete_user(self, user_id: int) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    def delete_credential(self, credential_row_id: int, user_id: int) -> bool:
        with self.connect() as conn:
            cursor = conn.execute(
                "DELETE FROM credentials WHERE id = ? AND user_id = ?",
                (credential_row_id, user_id),
            )
            if cursor.rowcount:
                conn.execute(
                    "UPDATE users SET session_version = session_version + 1 WHERE id = ?",
                    (user_id,),
                )
        return cursor.rowcount == 1

    def get_permissions(self, user_id: int) -> dict[str, bool]:
        permissions = {"admin": False, "login": True, "demo": True}
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT permission_key, allowed
                FROM user_permissions WHERE user_id = ?
                """,
                (user_id,),
            ).fetchall()
        permissions.update({str(row["permission_key"]): bool(row["allowed"]) for row in rows})
        return permissions

    def set_permissions(self, user_id: int, permissions: dict[str, bool]) -> None:
        now = int(time.time())
        with self.connect() as conn:
            for key, allowed in permissions.items():
                conn.execute(
                    """
                    INSERT INTO user_permissions (
                        user_id, permission_key, allowed, updated_at
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id, permission_key)
                    DO UPDATE SET allowed = excluded.allowed,
                                  updated_at = excluded.updated_at
                    """,
                    (user_id, key, int(bool(allowed)), now),
                )
            conn.execute(
                "UPDATE users SET session_version = session_version + 1 WHERE id = ?",
                (user_id,),
            )

    def count_enabled_admins(self) -> int:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM users u
                JOIN user_permissions p
                  ON p.user_id = u.id AND p.permission_key = 'admin'
                WHERE u.disabled_at IS NULL AND p.allowed = 1
                """
            ).fetchone()
        return int(row["count"])

    def get_platform_policy(self, user_id: int) -> dict:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT mode FROM user_platform_policies WHERE user_id = ?",
                (user_id,),
            ).fetchone()
            entries = conn.execute(
                """
                SELECT client_id FROM user_platform_policy_entries
                WHERE user_id = ? ORDER BY client_id
                """,
                (user_id,),
            ).fetchall()
        return {
            "mode": str(row["mode"]) if row else "allow_all",
            "client_ids": [str(entry["client_id"]) for entry in entries],
        }

    def set_platform_policy(
        self,
        user_id: int,
        mode: str,
        client_ids: Iterable[str],
    ) -> None:
        if mode not in {"allow_all", "allow_only", "deny_only"}:
            raise ValueError("无效的平台策略")
        now = int(time.time())
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO user_platform_policies (user_id, mode, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id)
                DO UPDATE SET mode = excluded.mode, updated_at = excluded.updated_at
                """,
                (user_id, mode, now),
            )
            conn.execute(
                "DELETE FROM user_platform_policy_entries WHERE user_id = ?",
                (user_id,),
            )
            conn.executemany(
                """
                INSERT INTO user_platform_policy_entries (user_id, client_id)
                VALUES (?, ?)
                """,
                [(user_id, client_id) for client_id in sorted(set(client_ids))],
            )
            conn.execute(
                "UPDATE users SET session_version = session_version + 1 WHERE id = ?",
                (user_id,),
            )

    def platform_allowed(self, user_id: int, client_id: str) -> bool:
        policy = self.get_platform_policy(user_id)
        entries = set(policy["client_ids"])
        if policy["mode"] == "allow_only":
            return client_id in entries
        if policy["mode"] == "deny_only":
            return client_id not in entries
        return True

    def bootstrap_oauth_client(
        self,
        *,
        client_id: str,
        name: str,
        client_secret: str,
        redirect_uris: Iterable[str],
    ) -> None:
        if self.get_oauth_client(client_id):
            return
        self.create_oauth_client(
            client_id=client_id,
            name=name,
            client_secret=client_secret,
            redirect_uris=redirect_uris,
            is_demo=True,
        )

    def create_oauth_client(
        self,
        *,
        client_id: str,
        name: str,
        client_secret: str,
        redirect_uris: Iterable[str],
        is_demo: bool = False,
    ) -> OAuthClient:
        now = int(time.time())
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO oauth_clients (
                    client_id, name, secret_hash, redirect_uris,
                    enabled, is_demo, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    client_id,
                    name,
                    _derive_secret_hash(client_secret),
                    json.dumps(sorted(set(redirect_uris))),
                    int(is_demo),
                    now,
                    now,
                ),
            )
            row_id = int(cursor.lastrowid)
        return OAuthClient(
            id=row_id,
            client_id=client_id,
            name=name,
            redirect_uris=sorted(set(redirect_uris)),
            enabled=True,
            is_demo=is_demo,
            created_at=now,
            updated_at=now,
        )

    def list_oauth_clients(self) -> list[OAuthClient]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, client_id, name, redirect_uris, enabled, is_demo,
                       created_at, updated_at
                FROM oauth_clients ORDER BY name COLLATE NOCASE
                """
            ).fetchall()
        return [_oauth_client_from_row(row) for row in rows]

    def get_oauth_client(self, client_id: str) -> OAuthClient | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, client_id, name, redirect_uris, enabled, is_demo,
                       created_at, updated_at
                FROM oauth_clients WHERE client_id = ?
                """,
                (client_id,),
            ).fetchone()
        return _oauth_client_from_row(row) if row else None

    def verify_oauth_client_secret(self, client_id: str, client_secret: str) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT secret_hash FROM oauth_clients WHERE client_id = ? AND enabled = 1",
                (client_id,),
            ).fetchone()
        return bool(row and _verify_secret_hash(client_secret, str(row["secret_hash"])))

    def update_oauth_client(
        self,
        client_id: str,
        *,
        name: str,
        redirect_uris: Iterable[str],
        enabled: bool,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE oauth_clients
                SET name = ?, redirect_uris = ?, enabled = ?, updated_at = ?
                WHERE client_id = ?
                """,
                (
                    name,
                    json.dumps(sorted(set(redirect_uris))),
                    int(enabled),
                    int(time.time()),
                    client_id,
                ),
            )

    def rotate_oauth_client_secret(self, client_id: str, client_secret: str) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE oauth_clients SET secret_hash = ?, updated_at = ?
                WHERE client_id = ?
                """,
                (_derive_secret_hash(client_secret), int(time.time()), client_id),
            )

    def delete_oauth_client(self, client_id: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM oauth_clients WHERE client_id = ?", (client_id,))
            conn.execute(
                "DELETE FROM user_platform_policy_entries WHERE client_id = ?",
                (client_id,),
            )

    def list_credentials_for_user(self, user_id: int) -> list[StoredCredential]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, user_id, credential_id, public_key, sign_count, transports,
                       aaguid, credential_type, device_type, backed_up, created_at, updated_at
                FROM credentials
                WHERE user_id = ?
                ORDER BY created_at DESC
                """,
                (user_id,),
            ).fetchall()
        return [_credential_from_row(row) for row in rows]

    def get_credential_by_id(self, credential_id: bytes) -> StoredCredential | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, user_id, credential_id, public_key, sign_count, transports,
                       aaguid, credential_type, device_type, backed_up, created_at, updated_at
                FROM credentials
                WHERE credential_id = ?
                """,
                (credential_id,),
            ).fetchone()
        return _credential_from_row(row) if row else None

    def save_credential(
        self,
        *,
        user_id: int,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        transports: Iterable[str],
        aaguid: str | None,
        credential_type: str | None,
        device_type: str | None,
        backed_up: bool,
    ) -> StoredCredential:
        now = int(time.time())
        transport_json = json.dumps(list(transports))
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO credentials (
                    user_id, credential_id, public_key, sign_count, transports, aaguid,
                    credential_type, device_type, backed_up, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    credential_id,
                    public_key,
                    sign_count,
                    transport_json,
                    aaguid,
                    credential_type,
                    device_type,
                    int(backed_up),
                    now,
                    now,
                ),
            )
            credential_row_id = int(cursor.lastrowid)
        return StoredCredential(
            id=credential_row_id,
            user_id=user_id,
            credential_id=credential_id,
            public_key=public_key,
            sign_count=sign_count,
            transports=list(transports),
            aaguid=aaguid,
            credential_type=credential_type,
            device_type=device_type,
            backed_up=backed_up,
            created_at=now,
            updated_at=now,
        )

    def update_sign_count(self, credential_id: bytes, sign_count: int) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE credentials
                SET sign_count = ?, updated_at = ?
                WHERE credential_id = ?
                """,
                (sign_count, int(time.time()), credential_id),
            )

    def create_oauth_authorization_code(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        user_id: int,
        ttl_seconds: int,
        code_factory,
    ) -> str:
        now = int(time.time())
        code = code_factory()
        with self.connect() as conn:
            conn.execute(
                """
                DELETE FROM oauth_authorization_codes
                WHERE consumed_at IS NOT NULL OR expires_at < ?
                """,
                (now,),
            )
            conn.execute(
                """
                INSERT INTO oauth_authorization_codes (
                    code_hash, client_id, redirect_uri, user_id, created_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    _derive_oauth_code_digest(code),
                    client_id,
                    redirect_uri,
                    user_id,
                    now,
                    now + ttl_seconds,
                ),
            )
        return code

    def consume_oauth_authorization_code(
        self,
        *,
        code: str,
        client_id: str,
        redirect_uri: str,
    ) -> OAuthAuthorizationCode | None:
        now = int(time.time())
        code_hash = _derive_oauth_code_digest(code)
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, client_id, redirect_uri, user_id, created_at, expires_at, consumed_at
                FROM oauth_authorization_codes
                WHERE code_hash = ?
                """,
                (code_hash,),
            ).fetchone()
            if not row:
                return None

            oauth_code = _oauth_code_from_row(row)
            if (
                oauth_code.client_id != client_id
                or oauth_code.redirect_uri != redirect_uri
                or oauth_code.consumed_at is not None
                or oauth_code.expires_at < now
            ):
                return None

            cursor = conn.execute(
                """
                UPDATE oauth_authorization_codes
                SET consumed_at = ?
                WHERE id = ? AND consumed_at IS NULL
                """,
                (now, oauth_code.id),
            )
            if cursor.rowcount != 1:
                return None
        return oauth_code

    def create_oauth_challenge_request(
        self,
        *,
        client_id: str,
        return_uri: str,
        username: str,
        state: str,
        ttl_seconds: int,
        challenge_factory,
    ) -> str:
        now = int(time.time())
        challenge_id = challenge_factory()
        with self.connect() as conn:
            conn.execute(
                """
                DELETE FROM oauth_challenge_requests
                WHERE consumed_at IS NOT NULL OR expires_at < ?
                """,
                (now,),
            )
            conn.execute(
                """
                INSERT INTO oauth_challenge_requests (
                    challenge_id, client_id, return_uri, username, state,
                    created_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge_id,
                    client_id,
                    return_uri,
                    username,
                    state,
                    now,
                    now + ttl_seconds,
                ),
            )
        return challenge_id

    def get_oauth_challenge_request(
        self,
        challenge_id: str,
    ) -> OAuthChallengeRequest | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, challenge_id, client_id, return_uri, username, state,
                       created_at, expires_at, completed_at, consumed_at, user_id
                FROM oauth_challenge_requests
                WHERE challenge_id = ?
                """,
                (challenge_id,),
            ).fetchone()
        return _oauth_challenge_from_row(row) if row else None

    def complete_oauth_challenge_request(
        self,
        *,
        challenge_id: str,
        user_id: int,
    ) -> OAuthChallengeRequest | None:
        now = int(time.time())
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, challenge_id, client_id, return_uri, username, state,
                       created_at, expires_at, completed_at, consumed_at, user_id
                FROM oauth_challenge_requests
                WHERE challenge_id = ?
                """,
                (challenge_id,),
            ).fetchone()
            if not row:
                return None

            challenge = _oauth_challenge_from_row(row)
            if (
                challenge.expires_at < now
                or challenge.completed_at is not None
                or challenge.consumed_at is not None
            ):
                return None

            cursor = conn.execute(
                """
                UPDATE oauth_challenge_requests
                SET completed_at = ?, user_id = ?
                WHERE id = ? AND completed_at IS NULL AND consumed_at IS NULL
                """,
                (now, user_id, challenge.id),
            )
            if cursor.rowcount != 1:
                return None

            row = conn.execute(
                """
                SELECT id, challenge_id, client_id, return_uri, username, state,
                       created_at, expires_at, completed_at, consumed_at, user_id
                FROM oauth_challenge_requests
                WHERE id = ?
                """,
                (challenge.id,),
            ).fetchone()
        return _oauth_challenge_from_row(row) if row else None

    def consume_oauth_challenge_request(
        self,
        *,
        challenge_id: str,
        user_id: int,
    ) -> OAuthChallengeRequest | None:
        now = int(time.time())
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, challenge_id, client_id, return_uri, username, state,
                       created_at, expires_at, completed_at, consumed_at, user_id
                FROM oauth_challenge_requests
                WHERE challenge_id = ?
                """,
                (challenge_id,),
            ).fetchone()
            if not row:
                return None

            challenge = _oauth_challenge_from_row(row)
            if (
                challenge.user_id != user_id
                or challenge.expires_at < now
                or challenge.completed_at is None
                or challenge.consumed_at is not None
            ):
                return None

            cursor = conn.execute(
                """
                UPDATE oauth_challenge_requests
                SET consumed_at = ?
                WHERE id = ? AND consumed_at IS NULL
                """,
                (now, challenge.id),
            )
            if cursor.rowcount != 1:
                return None
        return challenge

    def get_registration_settings(
        self,
        *,
        default_enabled: bool = False,
    ) -> RegistrationSettings:
        defaults = {
            "registration_mode": "open" if default_enabled else "closed",
            "registration_enabled_until": "",
            "default_demo_allowed": "true",
        }
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT setting_key, setting_value FROM app_settings
                WHERE setting_key IN (
                    'registration_mode',
                    'registration_enabled_until',
                    'default_demo_allowed'
                )
                """
            ).fetchall()
        values = defaults | {
            str(row["setting_key"]): str(row["setting_value"]) for row in rows
        }
        enabled_until = values["registration_enabled_until"]
        return RegistrationSettings(
            mode=values["registration_mode"],
            enabled_until=int(enabled_until) if enabled_until else None,
            default_demo_allowed=values["default_demo_allowed"] == "true",
        )

    def set_registration_settings(
        self,
        *,
        mode: str,
        enabled_until: int | None,
        default_demo_allowed: bool,
    ) -> None:
        if mode not in {"closed", "open", "temporary"}:
            raise ValueError("无效的注册模式")
        now = int(time.time())
        values = {
            "registration_mode": mode,
            "registration_enabled_until": str(enabled_until or ""),
            "default_demo_allowed": "true" if default_demo_allowed else "false",
        }
        with self.connect() as conn:
            for key, value in values.items():
                conn.execute(
                    """
                    INSERT INTO app_settings (setting_key, setting_value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(setting_key)
                    DO UPDATE SET setting_value = excluded.setting_value,
                                  updated_at = excluded.updated_at
                    """,
                    (key, value, now),
                )

    def get_passkey_settings(self) -> PasskeySettings:
        defaults = {
            "passkey_algorithms": "[-7, -8, -257]",
            "passkey_authenticator_attachment": "any",
            "passkey_resident_key": "required",
            "passkey_user_verification": "preferred",
            "passkey_attestation": "none",
            "passkey_exclude_credentials": "true",
            "passkey_hints": '["client-device", "security-key", "hybrid"]',
        }
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT setting_key, setting_value FROM app_settings
                WHERE setting_key LIKE 'passkey_%'
                """
            ).fetchall()
        values = defaults | {
            str(row["setting_key"]): str(row["setting_value"]) for row in rows
        }
        return PasskeySettings(
            algorithms=[int(value) for value in json.loads(values["passkey_algorithms"])],
            authenticator_attachment=values["passkey_authenticator_attachment"],
            resident_key=values["passkey_resident_key"],
            user_verification=values["passkey_user_verification"],
            attestation=values["passkey_attestation"],
            exclude_credentials=values["passkey_exclude_credentials"] == "true",
            hints=[str(value) for value in json.loads(values["passkey_hints"])],
        )

    def set_passkey_settings(
        self,
        *,
        algorithms: list[int],
        authenticator_attachment: str,
        resident_key: str,
        user_verification: str,
        attestation: str,
        exclude_credentials: bool,
        hints: list[str],
    ) -> None:
        allowed_algorithms = {-7, -8, -36, -37, -38, -39, -257, -258, -259}
        allowed_attachments = {"any", "platform", "cross-platform"}
        allowed_resident_keys = {"discouraged", "preferred", "required"}
        allowed_user_verification = {"discouraged", "preferred", "required"}
        allowed_attestation = {"none", "indirect", "direct", "enterprise"}
        allowed_hints = {"client-device", "security-key", "hybrid"}
        algorithms = list(dict.fromkeys(int(value) for value in algorithms))
        hints = list(dict.fromkeys(str(value) for value in hints))
        if not algorithms or any(value not in allowed_algorithms for value in algorithms):
            raise ValueError("至少选择一种受支持的公钥签名算法")
        if authenticator_attachment not in allowed_attachments:
            raise ValueError("无效的认证器类型")
        if resident_key not in allowed_resident_keys:
            raise ValueError("无效的 Resident Key 设置")
        if user_verification not in allowed_user_verification:
            raise ValueError("无效的用户验证设置")
        if attestation not in allowed_attestation:
            raise ValueError("无效的 Attestation 设置")
        if any(value not in allowed_hints for value in hints):
            raise ValueError("无效的认证器提示")

        now = int(time.time())
        values = {
            "passkey_algorithms": json.dumps(algorithms),
            "passkey_authenticator_attachment": authenticator_attachment,
            "passkey_resident_key": resident_key,
            "passkey_user_verification": user_verification,
            "passkey_attestation": attestation,
            "passkey_exclude_credentials": "true" if exclude_credentials else "false",
            "passkey_hints": json.dumps(hints),
        }
        with self.connect() as conn:
            for key, value in values.items():
                conn.execute(
                    """
                    INSERT INTO app_settings (setting_key, setting_value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(setting_key)
                    DO UPDATE SET setting_value = excluded.setting_value,
                                  updated_at = excluded.updated_at
                    """,
                    (key, value, now),
                )

    def reserve_username(
        self,
        *,
        username: str,
        reservation_token: str,
        ttl_seconds: int,
    ) -> bool:
        now = int(time.time())
        with self.connect() as conn:
            conn.execute(
                "DELETE FROM registration_reservations WHERE expires_at < ?",
                (now,),
            )
            if conn.execute(
                "SELECT 1 FROM users WHERE username = ?",
                (username,),
            ).fetchone():
                return False
            try:
                conn.execute(
                    """
                    INSERT INTO registration_reservations (
                        username, reservation_token, expires_at
                    ) VALUES (?, ?, ?)
                    """,
                    (username, reservation_token, now + ttl_seconds),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def add_admin_recovery_token(self, token: str) -> bool:
        digest = _token_digest(token)
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT 1 FROM admin_recovery_tokens WHERE token_hash = ?",
                (digest,),
            ).fetchone()
            if existing:
                return False
            try:
                conn.execute(
                    """
                    INSERT INTO admin_recovery_tokens (token_hash, created_at)
                    VALUES (?, ?)
                    """,
                    (digest, int(time.time())),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def admin_recovery_available(self, token: str) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM admin_recovery_tokens
                WHERE token_hash = ? AND consumed_at IS NULL
                """,
                (_token_digest(token),),
            ).fetchone()
        return bool(row)

    def consume_admin_recovery_token(self, token: str) -> bool:
        with self.connect() as conn:
            cursor = conn.execute(
                """
                UPDATE admin_recovery_tokens SET consumed_at = ?
                WHERE token_hash = ? AND consumed_at IS NULL
                """,
                (int(time.time()), _token_digest(token)),
            )
        return cursor.rowcount == 1

    def complete_admin_recovery(
        self,
        *,
        token: str,
        username: str,
        user_handle: bytes,
        reservation_token: str,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        transports: Iterable[str],
        aaguid: str | None,
        credential_type: str | None,
        device_type: str | None,
        backed_up: bool,
    ) -> User | None:
        now = int(time.time())
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            token_row = conn.execute(
                """
                SELECT id FROM admin_recovery_tokens
                WHERE token_hash = ? AND consumed_at IS NULL
                """,
                (_token_digest(token),),
            ).fetchone()
            reservation = conn.execute(
                """
                SELECT 1 FROM registration_reservations
                WHERE username = ? AND reservation_token = ? AND expires_at >= ?
                """,
                (username, reservation_token, now),
            ).fetchone()
            duplicate = conn.execute(
                "SELECT 1 FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if not token_row or not reservation or duplicate:
                conn.rollback()
                return None
            cursor = conn.execute(
                """
                INSERT INTO users (
                    username, user_handle, session_version, created_at
                ) VALUES (?, ?, 1, ?)
                """,
                (username, user_handle, now),
            )
            user_id = int(cursor.lastrowid)
            conn.executemany(
                """
                INSERT INTO user_permissions (
                    user_id, permission_key, allowed, updated_at
                ) VALUES (?, ?, 1, ?)
                """,
                [(user_id, key, now) for key in ("admin", "login", "demo")],
            )
            conn.execute(
                """
                INSERT INTO user_platform_policies (user_id, mode, updated_at)
                VALUES (?, 'allow_all', ?)
                """,
                (user_id, now),
            )
            conn.execute(
                """
                INSERT INTO credentials (
                    user_id, credential_id, public_key, sign_count, transports,
                    aaguid, credential_type, device_type, backed_up, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    credential_id,
                    public_key,
                    sign_count,
                    json.dumps(list(transports)),
                    aaguid,
                    credential_type,
                    device_type,
                    int(backed_up),
                    now,
                    now,
                ),
            )
            conn.execute(
                "UPDATE admin_recovery_tokens SET consumed_at = ? WHERE id = ?",
                (now, int(token_row["id"])),
            )
            conn.execute(
                "DELETE FROM registration_reservations WHERE username = ?",
                (username,),
            )
        return User(
            id=user_id,
            username=username,
            user_handle=user_handle,
            session_version=1,
            disabled_at=None,
            created_at=now,
        )

    def complete_registration(
        self,
        *,
        username: str,
        user_handle: bytes,
        reservation_token: str,
        default_demo_allowed: bool,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        transports: Iterable[str],
        aaguid: str | None,
        credential_type: str | None,
        device_type: str | None,
        backed_up: bool,
    ) -> User | None:
        now = int(time.time())
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            reservation = conn.execute(
                """
                SELECT 1 FROM registration_reservations
                WHERE username = ? AND reservation_token = ? AND expires_at >= ?
                """,
                (username, reservation_token, now),
            ).fetchone()
            duplicate = conn.execute(
                "SELECT 1 FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if not reservation or duplicate:
                conn.rollback()
                return None
            cursor = conn.execute(
                """
                INSERT INTO users (
                    username, user_handle, session_version, created_at
                ) VALUES (?, ?, 1, ?)
                """,
                (username, user_handle, now),
            )
            user_id = int(cursor.lastrowid)
            conn.executemany(
                """
                INSERT INTO user_permissions (
                    user_id, permission_key, allowed, updated_at
                ) VALUES (?, ?, ?, ?)
                """,
                [
                    (user_id, "admin", 0, now),
                    (user_id, "login", 1, now),
                    (user_id, "demo", int(default_demo_allowed), now),
                ],
            )
            conn.execute(
                """
                INSERT INTO user_platform_policies (user_id, mode, updated_at)
                VALUES (?, 'allow_all', ?)
                """,
                (user_id, now),
            )
            conn.execute(
                """
                INSERT INTO credentials (
                    user_id, credential_id, public_key, sign_count, transports,
                    aaguid, credential_type, device_type, backed_up, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    credential_id,
                    public_key,
                    sign_count,
                    json.dumps(list(transports)),
                    aaguid,
                    credential_type,
                    device_type,
                    int(backed_up),
                    now,
                    now,
                ),
            )
            conn.execute(
                "DELETE FROM registration_reservations WHERE username = ?",
                (username,),
            )
        return User(
            id=user_id,
            username=username,
            user_handle=user_handle,
            session_version=1,
            disabled_at=None,
            created_at=now,
        )

    def record_login(
        self,
        *,
        user: User | None,
        client_id: str | None,
        flow: str,
        result: str,
        credential_hint: str | None,
        ip_address: str,
        user_agent: str,
        sub: str | None = None,
        username: str | None = None,
    ) -> None:
        now = int(time.time())
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO login_history (
                    user_id, username_snapshot, sub_snapshot, client_id, flow,
                    result, credential_hint, ip_address, user_agent, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user.id if user else None,
                    user.username if user else username,
                    sub,
                    client_id,
                    flow,
                    result,
                    credential_hint,
                    ip_address,
                    user_agent,
                    now,
                ),
            )
            conn.execute(
                "DELETE FROM login_history WHERE created_at < ?",
                (now - 180 * 24 * 60 * 60,),
            )

    def record_audit(
        self,
        *,
        actor: User,
        action: str,
        target_type: str,
        target_id: str,
        details: dict,
        ip_address: str,
        user_agent: str,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (
                    actor_user_id, actor_username, action, target_type, target_id,
                    details, ip_address, user_agent, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    actor.id,
                    actor.username,
                    action,
                    target_type,
                    target_id,
                    json.dumps(details, ensure_ascii=False, sort_keys=True),
                    ip_address,
                    user_agent,
                    int(time.time()),
                ),
            )

    def list_login_history(self, *, limit: int = 500) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, user_id, username_snapshot, sub_snapshot, client_id,
                       flow, result, credential_hint, ip_address, user_agent, created_at
                FROM login_history ORDER BY created_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_audit_logs(self, *, limit: int = 500) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, actor_user_id, actor_username, action, target_type,
                       target_id, details, ip_address, user_agent, created_at
                FROM audit_logs ORDER BY created_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def clear_logs(
        self,
        *,
        log_type: str,
        actor: User,
        before: int | None,
    ) -> int:
        table = {"login": "login_history", "audit": "audit_logs"}.get(log_type)
        if not table:
            raise ValueError("无效的日志类型")
        where = " WHERE created_at < ?" if before is not None else ""
        params = (before,) if before is not None else ()
        with self.connect() as conn:
            cursor = conn.execute(f"DELETE FROM {table}{where}", params)
            deleted = int(cursor.rowcount)
            conn.execute(
                """
                INSERT INTO maintenance_events (
                    actor_user_id, actor_username, log_type, deleted_count, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (actor.id, actor.username, log_type, deleted, int(time.time())),
            )
        return deleted

    def count_logs(self, *, log_type: str, before: int | None) -> int:
        table = {"login": "login_history", "audit": "audit_logs"}.get(log_type)
        if not table:
            raise ValueError("无效的日志类型")
        where = " WHERE created_at < ?" if before is not None else ""
        params = (before,) if before is not None else ()
        with self.connect() as conn:
            row = conn.execute(
                f"SELECT COUNT(*) AS count FROM {table}{where}",
                params,
            ).fetchone()
        return int(row["count"])


def _user_from_row(row: sqlite3.Row) -> User:
    disabled_at = row["disabled_at"]
    return User(
        id=int(row["id"]),
        username=str(row["username"]),
        user_handle=bytes(row["user_handle"]),
        created_at=int(row["created_at"]),
        session_version=int(row["session_version"]),
        disabled_at=int(disabled_at) if disabled_at is not None else None,
    )


def _credential_from_row(row: sqlite3.Row) -> StoredCredential:
    return StoredCredential(
        id=int(row["id"]),
        user_id=int(row["user_id"]),
        credential_id=bytes(row["credential_id"]),
        public_key=bytes(row["public_key"]),
        sign_count=int(row["sign_count"]),
        transports=json.loads(row["transports"] or "[]"),
        aaguid=row["aaguid"],
        credential_type=row["credential_type"],
        device_type=row["device_type"],
        backed_up=bool(row["backed_up"]),
        created_at=int(row["created_at"]),
        updated_at=int(row["updated_at"]),
    )


def _oauth_code_from_row(row: sqlite3.Row) -> OAuthAuthorizationCode:
    consumed_at = row["consumed_at"]
    return OAuthAuthorizationCode(
        id=int(row["id"]),
        client_id=str(row["client_id"]),
        redirect_uri=str(row["redirect_uri"]),
        user_id=int(row["user_id"]),
        created_at=int(row["created_at"]),
        expires_at=int(row["expires_at"]),
        consumed_at=int(consumed_at) if consumed_at is not None else None,
    )


def _oauth_challenge_from_row(row: sqlite3.Row) -> OAuthChallengeRequest:
    completed_at = row["completed_at"]
    consumed_at = row["consumed_at"]
    user_id = row["user_id"]
    return OAuthChallengeRequest(
        id=int(row["id"]),
        challenge_id=str(row["challenge_id"]),
        client_id=str(row["client_id"]),
        return_uri=str(row["return_uri"]),
        username=str(row["username"]),
        state=str(row["state"]),
        created_at=int(row["created_at"]),
        expires_at=int(row["expires_at"]),
        completed_at=int(completed_at) if completed_at is not None else None,
        consumed_at=int(consumed_at) if consumed_at is not None else None,
        user_id=int(user_id) if user_id is not None else None,
    )


def _oauth_client_from_row(row: sqlite3.Row) -> OAuthClient:
    return OAuthClient(
        id=int(row["id"]),
        client_id=str(row["client_id"]),
        name=str(row["name"]),
        redirect_uris=json.loads(row["redirect_uris"] or "[]"),
        enabled=bool(row["enabled"]),
        is_demo=bool(row["is_demo"]),
        created_at=int(row["created_at"]),
        updated_at=int(row["updated_at"]),
    )


def _derive_oauth_code_digest(code: str) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        code.encode("utf-8"),
        _OAUTH_CODE_KDF_SALT,
        _OAUTH_CODE_KDF_ITERATIONS,
    ).hex()
    return f"{_OAUTH_CODE_KDF_ALGORITHM}${_OAUTH_CODE_KDF_ITERATIONS}${digest}"


def _derive_secret_hash(secret: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode(),
        salt,
        _SECRET_KDF_ITERATIONS,
    )
    return (
        f"pbkdf2_sha256${_SECRET_KDF_ITERATIONS}$"
        f"{salt.hex()}${digest.hex()}"
    )


def _verify_secret_hash(secret: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt_hex, digest_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            secret.encode(),
            bytes.fromhex(salt_hex),
            int(iterations),
        ).hex()
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(digest, digest_hex)


def _token_digest(token: str) -> str:
    return hashlib.sha256(f"passkey-admin-recovery:v1:{token}".encode()).hexdigest()
