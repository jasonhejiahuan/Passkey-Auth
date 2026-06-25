from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import math
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from importlib import import_module
from pathlib import Path
from urllib.parse import urlsplit

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .storage import (
    TELEMETRY_FEATURES,
    PasskeyStore,
    TelemetrySettings,
    UserTelemetryPolicy,
)

_TOKEN_MAX_AGE_SECONDS = 300
_MAX_PAYLOAD_BYTES = 16_384
_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class TelemetryDecision:
    features: tuple[str, ...]
    policy_key: str


class TelemetryRuntime:
    """In-memory policy gate plus lazy local or external delivery."""

    def __init__(
        self,
        *,
        settings_store: PasskeyStore,
        database_path: str | Path,
        secret_key: str,
        default_enabled: bool = False,
    ):
        self._settings_store = settings_store
        self._database_path = Path(database_path)
        self._serializer = URLSafeTimedSerializer(
            secret_key,
            salt="passkey-auth:telemetry:v1",
        )
        self._policy_secret = secret_key.encode("utf-8")
        self._lock = threading.RLock()
        self._settings = settings_store.get_telemetry_settings(
            default_enabled=default_enabled
        )
        if default_enabled and self._settings.updated_at == 0:
            self._settings = replace(
                self._settings,
                enabled=True,
                anonymous_enabled=True,
            )
        self._policies = settings_store.list_user_telemetry_policies()
        self._telemetry_store: TelemetryStore | None = None
        self._external_delivery = None
        self._used_external_tokens: dict[str, float] = {}
        self._next_prune_at = 0

    @property
    def enabled(self) -> bool:
        return self._settings.enabled

    @property
    def uses_builtin_store(self) -> bool:
        return self._settings.backend == "builtin"

    @property
    def delivery_mode(self) -> str:
        return self._settings.delivery_mode

    @property
    def direct_connect_origin(self) -> str:
        settings = self._settings
        if not settings.enabled or settings.delivery_mode != "direct":
            return ""
        url = (
            settings.jason_base_url
            if settings.backend == "jason"
            else settings.custom_url
        )
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""

    def decision_for(self, user_id: int | None) -> TelemetryDecision | None:
        settings = self._settings
        if not settings.enabled:
            return None
        if user_id is None:
            if not settings.anonymous_enabled:
                return None
            features = tuple(settings.default_features)
            revision = settings.updated_at
        else:
            policy = self._policies.get(int(user_id))
            if policy and policy.mode == "off":
                return None
            if policy and policy.mode == "custom":
                features = tuple(policy.features)
                revision = max(settings.updated_at, policy.updated_at)
            else:
                features = tuple(settings.default_features)
                revision = settings.updated_at
        if not features:
            return None
        identity = f"{user_id or 0}:{revision}:{','.join(features)}"
        policy_key = hmac.new(
            self._policy_secret,
            identity.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:20]
        return TelemetryDecision(features=features, policy_key=policy_key)

    def issue_collection_token(
        self,
        *,
        user_id: int | None,
        decision: TelemetryDecision,
    ) -> str:
        return self._serializer.dumps(
            {
                "j": secrets.token_urlsafe(18),
                "u": int(user_id) if user_id is not None else None,
                "f": list(decision.features),
                "p": decision.policy_key,
            }
        )

    def collect(
        self,
        *,
        payload: dict,
        remote_addr: str,
        user_agent: str,
    ) -> tuple[dict, int]:
        if not self.enabled:
            return {"ok": False, "error": "telemetry_disabled"}, 404
        settings = self._settings
        if settings.delivery_mode == "direct":
            return {"ok": False, "error": "telemetry_uses_direct_delivery"}, 409
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        if len(raw) > _MAX_PAYLOAD_BYTES:
            return {"ok": False, "error": "telemetry_payload_too_large"}, 413
        validated, error = self._validate_token(str(payload.get("token") or ""))
        if error:
            return error
        token_data, user_id, decision = validated

        normalized = _normalize_payload(payload, decision.features, user_agent)
        if normalized is None:
            return {"ok": False, "error": "telemetry_payload_invalid"}, 400
        normalized["token_id"] = str(token_data.get("j") or "")
        normalized["user_id"] = user_id
        normalized["policy_key"] = decision.policy_key
        normalized["ip_hash"] = hmac.new(
            self._policy_secret,
            str(remote_addr or "").encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()[:20]
        normalized["payload_bytes"] = len(raw)
        if settings.backend == "builtin":
            inserted = self._store().record(normalized)
            self._prune_if_due()
            return {"ok": True, "duplicate": not inserted}, 202

        token_id = normalized["token_id"]
        if not self._claim_external_token(token_id):
            return {"ok": True, "duplicate": True}, 202
        accepted = self._delivery().enqueue(_external_payload(normalized))
        if not accepted:
            self._release_external_token(token_id)
        return {
            "ok": True,
            "duplicate": False,
            "queued": accepted,
            "dropped": not accepted,
        }, 202

    def direct_target(self, *, token: str) -> tuple[dict, int]:
        settings = self._settings
        if (
            not settings.enabled
            or settings.backend == "builtin"
            or settings.delivery_mode != "direct"
        ):
            return {"ok": False, "error": "telemetry_direct_unavailable"}, 404
        validated, error = self._validate_token(token)
        if error:
            return error
        token_data, user_id, decision = validated
        token_id = str(token_data.get("j") or "")
        if not self._claim_external_token(token_id):
            return {"ok": False, "error": "telemetry_token_used"}, 409
        try:
            module = import_module("jstu_passkey.telemetry_delivery")
            target = module.create_direct_target(
                settings,
                {
                    "source": "passkey-auth",
                    "user_id": user_id,
                    "features": list(decision.features),
                    "policy_key": decision.policy_key,
                },
            )
        except Exception:
            self._release_external_token(token_id)
            return {"ok": False, "error": "telemetry_backend_unavailable"}, 503
        return {"ok": True, "target": target}, 200

    def settings_payload(self) -> dict:
        settings = self._settings
        return {
            "enabled": settings.enabled,
            "anonymousEnabled": settings.anonymous_enabled,
            "defaultFeatures": settings.default_features,
            "retentionDays": settings.retention_days,
            "backend": settings.backend,
            "deliveryMode": settings.delivery_mode,
            "availableBackends": ["builtin", "jason", "custom"],
            "availableDeliveryModes": ["relay", "direct"],
            "jason": {
                "baseUrl": settings.jason_base_url,
                "apiKeyConfigured": bool(settings.jason_api_key),
            },
            "custom": {
                "url": settings.custom_url,
                "authMode": settings.custom_auth_mode,
                "authHeader": settings.custom_auth_header,
                "secretConfigured": bool(settings.custom_secret),
                "headers": settings.custom_headers,
                "directContentType": settings.custom_direct_content_type,
            },
            "timeoutSeconds": settings.timeout_seconds,
            "localStorageActive": settings.backend == "builtin",
            "delivery": self.delivery_status(),
            "availableFeatures": list(TELEMETRY_FEATURES),
        }

    def policies_payload(self) -> dict[str, dict]:
        return {
            str(user_id): {
                "mode": policy.mode,
                "features": policy.features,
            }
            for user_id, policy in self._policies.items()
        }

    def update_settings(
        self,
        *,
        enabled: bool,
        anonymous_enabled: bool,
        default_features: list[str],
        retention_days: int,
        backend: str | None = None,
        delivery_mode: str | None = None,
        jason_base_url: str | None = None,
        jason_api_key: str | None = None,
        custom_url: str | None = None,
        custom_auth_mode: str | None = None,
        custom_auth_header: str | None = None,
        custom_secret: str | None = None,
        custom_headers: dict[str, str] | None = None,
        custom_direct_content_type: str | None = None,
        timeout_seconds: float | None = None,
    ) -> TelemetrySettings:
        current = self._settings
        settings = self._settings_store.set_telemetry_settings(
            enabled=enabled,
            anonymous_enabled=anonymous_enabled,
            default_features=default_features,
            retention_days=retention_days,
            backend=backend if backend is not None else current.backend,
            delivery_mode=(
                delivery_mode
                if delivery_mode is not None
                else current.delivery_mode
            ),
            jason_base_url=(
                jason_base_url
                if jason_base_url is not None
                else current.jason_base_url
            ),
            jason_api_key=(
                jason_api_key
                if jason_api_key is not None
                else current.jason_api_key
            ),
            custom_url=(
                custom_url if custom_url is not None else current.custom_url
            ),
            custom_auth_mode=(
                custom_auth_mode
                if custom_auth_mode is not None
                else current.custom_auth_mode
            ),
            custom_auth_header=(
                custom_auth_header
                if custom_auth_header is not None
                else current.custom_auth_header
            ),
            custom_secret=(
                custom_secret
                if custom_secret is not None
                else current.custom_secret
            ),
            custom_headers=(
                custom_headers
                if custom_headers is not None
                else current.custom_headers
            ),
            custom_direct_content_type=(
                custom_direct_content_type
                if custom_direct_content_type is not None
                else current.custom_direct_content_type
            ),
            timeout_seconds=(
                timeout_seconds
                if timeout_seconds is not None
                else current.timeout_seconds
            ),
        )
        with self._lock:
            self._settings = settings
            if _delivery_signature(current) != _delivery_signature(settings):
                self._reset_delivery_locked()
        return settings

    def update_user_policy(
        self,
        *,
        user_id: int,
        mode: str,
        features: list[str],
    ) -> UserTelemetryPolicy:
        policy = self._settings_store.set_user_telemetry_policy(
            user_id=user_id,
            mode=mode,
            features=features,
        )
        with self._lock:
            if mode == "inherit":
                self._policies.pop(user_id, None)
            else:
                self._policies[user_id] = policy
        return policy

    def drop_user_policy(self, user_id: int) -> None:
        with self._lock:
            self._policies.pop(int(user_id), None)

    def statistics(self) -> dict:
        if not self.uses_builtin_store:
            return TelemetryStore.empty_statistics()
        if not self._database_path.exists() and self._telemetry_store is None:
            return TelemetryStore.empty_statistics()
        return self._store().statistics()

    def count_events(self, *, before: int | None = None) -> int:
        if not self.uses_builtin_store:
            raise ValueError("当前遥测后端不使用内置事件库")
        if not self._database_path.exists() and self._telemetry_store is None:
            return 0
        return self._store().count(before=before)

    def clear_events(self, *, before: int | None = None) -> int:
        if not self.uses_builtin_store:
            raise ValueError("当前遥测后端不使用内置事件库")
        if not self._database_path.exists() and self._telemetry_store is None:
            return 0
        return self._store().clear(before=before)

    def export_csv(self) -> str:
        if not self.uses_builtin_store:
            raise ValueError("当前遥测后端不使用内置事件库")
        rows = (
            self._store().export_rows()
            if self._database_path.exists() or self._telemetry_store is not None
            else []
        )
        fields = [
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
        ]
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key)) for key in fields})
        return "\ufeff" + output.getvalue()

    def delivery_status(self) -> dict:
        if self._settings.backend == "builtin":
            return {
                "state": "builtin",
                "queued": 0,
                "sent": 0,
                "failed": 0,
                "dropped": 0,
                "lastError": "",
                "lastAttemptAt": None,
                "lastSuccessAt": None,
            }
        with self._lock:
            delivery = self._external_delivery
        if delivery is None:
            return {
                "state": "idle",
                "queued": 0,
                "sent": 0,
                "failed": 0,
                "dropped": 0,
                "lastError": "",
                "lastAttemptAt": None,
                "lastSuccessAt": None,
            }
        return delivery.status()

    def test_backend(self) -> dict:
        settings = self._settings
        if settings.backend == "builtin":
            return {"ok": True, "backend": "builtin", "message": "内置事件库可用"}
        module = import_module("jstu_passkey.telemetry_delivery")
        return module.test_backend(settings)

    def pair_jason(
        self,
        *,
        base_url: str,
        pairing_code: str,
        timeout_seconds: float,
        delivery_mode: str = "relay",
    ) -> dict:
        parts = urlsplit(str(base_url or "").strip())
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username
            or parts.password
            or parts.fragment
        ):
            raise ValueError("Jason Telemetry 地址必须是安全的完整 HTTP(S) URL")
        if parts.scheme != "https" and parts.hostname not in {
            "localhost",
            "127.0.0.1",
            "::1",
        }:
            raise ValueError("Jason Telemetry 自动配对要求 HTTPS 或本机回环地址")
        module = import_module(
            "jstu_passkey.telemetry_backends.jason_telemetry_integrate"
        )
        result = module.pair(
            base_url=base_url,
            pairing_code=pairing_code,
            timeout_seconds=timeout_seconds,
        )
        api_key = str(result.get("apiKey") or "")
        if not api_key:
            raise ValueError("Jason Telemetry 未返回 API Key")
        current = self._settings
        settings = self.update_settings(
            enabled=current.enabled,
            anonymous_enabled=current.anonymous_enabled,
            default_features=current.default_features,
            retention_days=current.retention_days,
            backend="jason",
            delivery_mode=delivery_mode,
            jason_base_url=base_url,
            jason_api_key=api_key,
            timeout_seconds=timeout_seconds,
        )
        return {
            "ok": True,
            "backend": settings.backend,
            "apiKeyConfigured": True,
            "serverVersion": result.get("serverVersion"),
        }

    def _store(self) -> "TelemetryStore":
        with self._lock:
            if self._telemetry_store is None:
                self._telemetry_store = TelemetryStore(self._database_path)
            return self._telemetry_store

    def _delivery(self):
        with self._lock:
            if self._external_delivery is None:
                module = import_module("jstu_passkey.telemetry_delivery")
                self._external_delivery = module.AsyncTelemetryDelivery(
                    self._settings
                )
            return self._external_delivery

    def _reset_delivery_locked(self) -> None:
        delivery = self._external_delivery
        self._external_delivery = None
        self._used_external_tokens.clear()
        if delivery is not None:
            delivery.stop()

    def _validate_token(
        self,
        token: str,
    ) -> tuple[
        tuple[dict, int | None, TelemetryDecision] | None,
        tuple[dict, int] | None,
    ]:
        try:
            token_data = self._serializer.loads(
                token,
                max_age=_TOKEN_MAX_AGE_SECONDS,
            )
        except SignatureExpired:
            return None, ({"ok": False, "error": "telemetry_token_expired"}, 410)
        except BadSignature:
            return None, ({"ok": False, "error": "telemetry_token_invalid"}, 403)
        if not isinstance(token_data, dict):
            return None, ({"ok": False, "error": "telemetry_token_invalid"}, 403)
        try:
            user_id = (
                int(token_data.get("u"))
                if token_data.get("u") is not None
                else None
            )
        except (TypeError, ValueError):
            return None, ({"ok": False, "error": "telemetry_token_invalid"}, 403)
        if user_id is not None and not self._settings_store.get_user_by_id(user_id):
            return None, ({"ok": False, "error": "telemetry_user_unavailable"}, 403)
        decision = self.decision_for(user_id)
        token_features = tuple(str(value) for value in token_data.get("f") or [])
        if (
            not decision
            or decision.features != token_features
            or decision.policy_key != str(token_data.get("p") or "")
        ):
            return None, ({"ok": False, "error": "telemetry_policy_changed"}, 409)
        return (token_data, user_id, decision), None

    def _claim_external_token(self, token_id: str) -> bool:
        if not token_id:
            return False
        now = time.time()
        with self._lock:
            expired = [
                key
                for key, used_at in self._used_external_tokens.items()
                if used_at < now - _TOKEN_MAX_AGE_SECONDS
            ]
            for key in expired:
                self._used_external_tokens.pop(key, None)
            if token_id in self._used_external_tokens:
                return False
            self._used_external_tokens[token_id] = now
            return True

    def _release_external_token(self, token_id: str) -> None:
        with self._lock:
            self._used_external_tokens.pop(token_id, None)

    def _prune_if_due(self) -> None:
        now = int(time.time())
        if now < self._next_prune_at:
            return
        with self._lock:
            if now < self._next_prune_at:
                return
            cutoff = now - self._settings.retention_days * 86_400
            self._store().clear(before=cutoff)
            self._next_prune_at = now + 3_600


def _delivery_signature(settings: TelemetrySettings) -> tuple:
    return (
        settings.backend,
        settings.delivery_mode,
        settings.jason_base_url,
        settings.jason_api_key,
        settings.custom_url,
        settings.custom_auth_mode,
        settings.custom_auth_header,
        settings.custom_secret,
        tuple(sorted(settings.custom_headers.items())),
        settings.custom_direct_content_type,
        settings.timeout_seconds,
    )


def _external_payload(event: dict) -> dict:
    return {
        "event": "passkey_auth.browser_telemetry",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "passkey-auth",
        "schema_version": 1,
        "subject": {
            "user_id": event["user_id"],
            "anonymous": event["user_id"] is None,
        },
        "telemetry": {
            "path": event["path"],
            "referrer_origin": event["referrer_origin"],
            "client": {
                "os_family": event["os_family"],
                "browser_family": event["browser_family"],
                "device_class": event["device_class"],
            },
            "features": event["features"],
            "signals": event["signals"],
            "payload_bytes": event["payload_bytes"],
            "policy_key": event["policy_key"],
            "ip_hash": event["ip_hash"],
        },
    }


class TelemetryStore:
    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.init()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init(self) -> None:
        with self.connect() as conn:
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, _SCHEMA_VERSION}:
                raise RuntimeError("Unsupported telemetry database schema.")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS telemetry_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id TEXT NOT NULL UNIQUE,
                    user_id INTEGER,
                    policy_key TEXT NOT NULL,
                    path TEXT NOT NULL,
                    referrer_origin TEXT,
                    os_family TEXT NOT NULL,
                    browser_family TEXT NOT NULL,
                    device_class TEXT NOT NULL,
                    features TEXT NOT NULL,
                    signals TEXT NOT NULL,
                    payload_bytes INTEGER NOT NULL,
                    ip_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS telemetry_event_features (
                    event_id INTEGER NOT NULL
                        REFERENCES telemetry_events(id) ON DELETE CASCADE,
                    feature TEXT NOT NULL,
                    PRIMARY KEY (event_id, feature)
                );

                CREATE INDEX IF NOT EXISTS idx_telemetry_created_at
                    ON telemetry_events(created_at);
                CREATE INDEX IF NOT EXISTS idx_telemetry_user_id
                    ON telemetry_events(user_id);
                """
            )
            conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    def record(self, event: dict) -> bool:
        now = int(time.time())
        try:
            with self.connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO telemetry_events (
                        token_id, user_id, policy_key, path, referrer_origin,
                        os_family, browser_family, device_class, features,
                        signals, payload_bytes, ip_hash, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event["token_id"],
                        event["user_id"],
                        event["policy_key"],
                        event["path"],
                        event["referrer_origin"],
                        event["os_family"],
                        event["browser_family"],
                        event["device_class"],
                        json.dumps(event["features"], separators=(",", ":")),
                        json.dumps(
                            event["signals"],
                            separators=(",", ":"),
                            ensure_ascii=False,
                            sort_keys=True,
                        ),
                        event["payload_bytes"],
                        event["ip_hash"],
                        now,
                    ),
                )
                event_id = int(cursor.lastrowid)
                conn.executemany(
                    """
                    INSERT INTO telemetry_event_features (event_id, feature)
                    VALUES (?, ?)
                    """,
                    [(event_id, feature) for feature in event["features"]],
                )
        except sqlite3.IntegrityError:
            return False
        return True

    def statistics(self) -> dict:
        now = int(time.time())
        with self.connect() as conn:
            summary = conn.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) AS last_24h,
                       COUNT(DISTINCT user_id) AS identified_users,
                       SUM(CASE WHEN user_id IS NULL THEN 1 ELSE 0 END) AS anonymous,
                       COALESCE(AVG(payload_bytes), 0) AS average_bytes,
                       MAX(created_at) AS latest_at
                FROM telemetry_events
                """,
                (now - 86_400,),
            ).fetchone()
            recent = conn.execute(
                """
                SELECT id, user_id, path, referrer_origin, os_family,
                       browser_family, device_class, features, signals,
                       payload_bytes, created_at
                FROM telemetry_events
                ORDER BY created_at DESC, id DESC
                LIMIT 60
                """
            ).fetchall()
            feature_rows = conn.execute(
                """
                SELECT feature AS label, COUNT(*) AS count
                FROM telemetry_event_features
                GROUP BY feature ORDER BY count DESC, feature
                """
            ).fetchall()
            distributions = {
                "operatingSystems": _distribution(
                    conn, "os_family", "telemetry_events"
                ),
                "browsers": _distribution(
                    conn, "browser_family", "telemetry_events"
                ),
                "devices": _distribution(
                    conn, "device_class", "telemetry_events"
                ),
                "features": [
                    {"label": str(row["label"]), "count": int(row["count"])}
                    for row in feature_rows
                ],
            }
        return {
            "summary": {
                "total": int(summary["total"] or 0),
                "last24h": int(summary["last_24h"] or 0),
                "identifiedUsers": int(summary["identified_users"] or 0),
                "anonymous": int(summary["anonymous"] or 0),
                "averagePayloadBytes": int(round(float(summary["average_bytes"] or 0))),
                "latestAt": int(summary["latest_at"]) if summary["latest_at"] else None,
            },
            "distributions": distributions,
            "recent": [_event_payload(row) for row in recent],
        }

    @staticmethod
    def empty_statistics() -> dict:
        return {
            "summary": {
                "total": 0,
                "last24h": 0,
                "identifiedUsers": 0,
                "anonymous": 0,
                "averagePayloadBytes": 0,
                "latestAt": None,
            },
            "distributions": {
                "operatingSystems": [],
                "browsers": [],
                "devices": [],
                "features": [],
            },
            "recent": [],
        }

    def count(self, *, before: int | None = None) -> int:
        where = " WHERE created_at < ?" if before is not None else ""
        params = (before,) if before is not None else ()
        with self.connect() as conn:
            row = conn.execute(
                f"SELECT COUNT(*) AS count FROM telemetry_events{where}",
                params,
            ).fetchone()
        return int(row["count"])

    def clear(self, *, before: int | None = None) -> int:
        where = " WHERE created_at < ?" if before is not None else ""
        params = (before,) if before is not None else ()
        with self.connect() as conn:
            cursor = conn.execute(f"DELETE FROM telemetry_events{where}", params)
        return int(cursor.rowcount)

    def export_rows(self) -> list[dict]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, user_id, path, referrer_origin, os_family,
                       browser_family, device_class, features, signals,
                       payload_bytes, created_at
                FROM telemetry_events
                ORDER BY created_at DESC, id DESC
                """
            ).fetchall()
        return [dict(row) for row in rows]


def _normalize_payload(
    payload: dict,
    features: tuple[str, ...],
    user_agent: str,
) -> dict | None:
    if not isinstance(payload, dict):
        return None
    reported_features = payload.get("features")
    if not isinstance(reported_features, list):
        return None
    normalized_features = tuple(
        feature for feature in TELEMETRY_FEATURES if feature in reported_features
    )
    if normalized_features != features:
        return None
    signals = payload.get("signals")
    if not isinstance(signals, dict):
        return None
    normalized_signals = {}
    for feature in features:
        value = signals.get(feature)
        if not isinstance(value, dict):
            return None
        normalized_signals[feature] = _normalize_signal(feature, value)
    client = payload.get("client") if isinstance(payload.get("client"), dict) else {}
    os_family = str(client.get("osFamily") or "other")
    if os_family not in {"windows", "macos", "ios", "android", "linux", "chromeos", "other"}:
        os_family = "other"
    device_class = str(client.get("deviceClass") or "desktop")
    if device_class not in {"desktop", "tablet", "mobile"}:
        device_class = "desktop"
    return {
        "path": _safe_path(payload.get("path")),
        "referrer_origin": _short_text(payload.get("referrerOrigin"), 240),
        "os_family": os_family,
        "browser_family": _browser_family(user_agent),
        "device_class": device_class,
        "features": list(features),
        "signals": normalized_signals,
    }


def _normalize_signal(feature: str, value: dict) -> dict:
    allowed = {
        "screen": {
            "width",
            "height",
            "availableWidth",
            "availableHeight",
            "pixelRatio",
            "colorDepth",
            "orientation",
        },
        "hardware": {
            "logicalProcessors",
            "deviceMemoryGb",
            "architecture",
            "bitness",
            "model",
        },
        "fonts": {"platform", "available"},
        "battery": {
            "supported",
            "charging",
            "levelBucket",
            "chargingTimeBucket",
            "dischargingTimeBucket",
        },
        "network": {
            "supported",
            "effectiveType",
            "downlinkBucket",
            "rttBucket",
            "saveData",
        },
        "preferences": {
            "colorScheme",
            "reducedMotion",
            "contrast",
            "forcedColors",
        },
    }[feature]
    normalized = {}
    for key in allowed:
        item = value.get(key)
        if isinstance(item, bool):
            normalized[key] = item
        elif isinstance(item, (int, float)):
            number = float(item)
            if math.isfinite(number):
                normalized[key] = round(number, 2)
        elif isinstance(item, str):
            normalized[key] = _short_text(item, 80)
        elif key == "available" and isinstance(item, list):
            normalized[key] = [
                _short_text(font, 80) for font in item[:16] if str(font).strip()
            ]
    return normalized


def _distribution(
    conn: sqlite3.Connection,
    column: str,
    table: str,
) -> list[dict]:
    rows = conn.execute(
        f"""
        SELECT {column} AS label, COUNT(*) AS count
        FROM {table}
        GROUP BY {column}
        ORDER BY count DESC, {column}
        """
    ).fetchall()
    return [
        {"label": str(row["label"]), "count": int(row["count"])}
        for row in rows
    ]


def _event_payload(row: sqlite3.Row) -> dict:
    return {
        "id": int(row["id"]),
        "userId": int(row["user_id"]) if row["user_id"] is not None else None,
        "path": str(row["path"]),
        "referrerOrigin": str(row["referrer_origin"] or ""),
        "osFamily": str(row["os_family"]),
        "browserFamily": str(row["browser_family"]),
        "deviceClass": str(row["device_class"]),
        "features": json.loads(row["features"]),
        "signals": json.loads(row["signals"]),
        "payloadBytes": int(row["payload_bytes"]),
        "createdAt": int(row["created_at"]),
    }


def _browser_family(user_agent: str) -> str:
    value = str(user_agent or "").lower()
    if "edg/" in value:
        return "edge"
    if "firefox/" in value or "fxios/" in value:
        return "firefox"
    if "chrome/" in value or "crios/" in value:
        return "chrome"
    if "safari/" in value:
        return "safari"
    return "other"


def _safe_path(value) -> str:
    path = _short_text(value, 320)
    return path if path.startswith("/") else "/"


def _short_text(value, limit: int) -> str:
    return str(value or "").strip()[:limit]


def _csv_value(value):
    if value is None:
        return ""
    text = str(value)
    if text[:1] in {"=", "+", "-", "@"}:
        return "'" + text
    return text
