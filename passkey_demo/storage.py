from __future__ import annotations

import json
import sqlite3
import time
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

_OAUTH_CODE_KDF_ALGORITHM = "pbkdf2_sha256"
_OAUTH_CODE_KDF_ITERATIONS = 120_000
_OAUTH_CODE_KDF_SALT = b"passkey-auth:oauth-authorization-code:v1"


@dataclass(frozen=True)
class User:
    id: int
    username: str
    user_handle: bytes
    created_at: int


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


class PasskeyStore:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        if self.database_path.parent:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.init()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    user_handle BLOB NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS credentials (
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

                CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    code_hash TEXT NOT NULL UNIQUE,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    consumed_at INTEGER
                );

                CREATE TABLE IF NOT EXISTS oauth_challenge_requests (
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
                """
            )

    def get_user_by_username(self, username: str) -> User | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id, username, user_handle, created_at FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        return _user_from_row(row) if row else None

    def get_user_by_id(self, user_id: int) -> User | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id, username, user_handle, created_at FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        return _user_from_row(row) if row else None

    def get_user_by_handle(self, user_handle: bytes) -> User | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id, username, user_handle, created_at FROM users WHERE user_handle = ?",
                (user_handle,),
            ).fetchone()
        return _user_from_row(row) if row else None

    def create_user(self, username: str, user_handle: bytes) -> User:
        now = int(time.time())
        with self.connect() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, user_handle, created_at) VALUES (?, ?, ?)",
                (username, user_handle, now),
            )
            user_id = int(cursor.lastrowid)
        return User(id=user_id, username=username, user_handle=user_handle, created_at=now)

    def get_or_create_user(self, username: str, user_handle_factory) -> User:
        existing = self.get_user_by_username(username)
        if existing:
            return existing
        return self.create_user(username, user_handle_factory())

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


def _user_from_row(row: sqlite3.Row) -> User:
    return User(
        id=int(row["id"]),
        username=str(row["username"]),
        user_handle=bytes(row["user_handle"]),
        created_at=int(row["created_at"]),
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


def _derive_oauth_code_digest(code: str) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        code.encode("utf-8"),
        _OAUTH_CODE_KDF_SALT,
        _OAUTH_CODE_KDF_ITERATIONS,
    ).hex()
    return f"{_OAUTH_CODE_KDF_ALGORITHM}${_OAUTH_CODE_KDF_ITERATIONS}${digest}"
