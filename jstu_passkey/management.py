from __future__ import annotations

import csv
import io
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from flask import (
    Blueprint,
    Response,
    current_app,
    g,
    jsonify,
    render_template,
    request,
    session,
    stream_with_context,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from .storage import PasskeyStore, User
from .webauthn_service import normalize_username

_CHANNEL_TTL_SECONDS = 30 * 60
_CHANNEL_STALE_SECONDS = 5 * 60
_CHANNEL_DEFAULT_ACK_MS = 45_000
_CHANNEL_MIN_ACK_MS = 30_000
_CHANNEL_MAX_ACK_MS = 300_000
_CHANNEL_REGISTRY_KEY = "management_channels"


@dataclass
class ManagementChannel:
    channel_id: str
    user_id: int
    action_token_session_id: str
    public_key: EllipticCurvePublicKey
    server_nonce: str
    last_counter: int
    created_at: int
    expires_at: int
    last_seen_at: int
    ack_after_ms: int


def create_management_blueprint() -> Blueprint:
    blueprint = Blueprint("management", __name__)

    @blueprint.after_request
    def finalize_action_token(response):
        next_token = getattr(g, "next_action_token", "")
        if not next_token:
            return response

        payload = response.get_json(silent=True)
        if 200 <= response.status_code < 300 and isinstance(payload, dict):
            payload["next_action_token"] = next_token
            response.set_data(current_app.json.dumps(payload))
            return response

        _store().rotate_action_token(
            session_id=g.action_token_session_id,
            user_id=g.action_token_user_id,
            current_token=next_token,
            next_token=g.previous_action_token,
        )
        return response

    @blueprint.get("/management")
    def management_page():
        user = _require_admin(html=True)
        if not isinstance(user, User):
            return user
        csrf_token = session.get("management_csrf_token") or secrets.token_urlsafe(32)
        session["management_csrf_token"] = csrf_token
        response = current_app.make_response(
            render_template("management.html", csrf_token=csrf_token)
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @blueprint.get("/api/management/overview")
    def overview():
        actor = _require_admin()
        if not isinstance(actor, User):
            return actor
        store = _store()
        users = []
        for row in store.list_users():
            user = store.get_user_by_id(int(row["id"]))
            if not user:
                continue
            users.append(
                {
                    "id": user.id,
                    "username": user.username,
                    "sub": bytes_to_base64url(user.user_handle),
                    "createdAt": user.created_at,
                    "disabledAt": user.disabled_at,
                    "sessionVersion": user.session_version,
                    "credentialCount": int(row["credential_count"]),
                    "lastLoginAt": row["last_login_at"],
                    "permissions": store.get_permissions(user.id),
                    "platformPolicy": store.get_platform_policy(user.id),
                    "credentials": [
                        {
                            "id": credential.id,
                            "createdAt": credential.created_at,
                            "updatedAt": credential.updated_at,
                            "deviceType": credential.device_type,
                            "backedUp": credential.backed_up,
                            "transports": credential.transports,
                            "aaguid": credential.aaguid,
                        }
                        for credential in store.list_credentials_for_user(user.id)
                    ],
                }
            )
        settings = store.get_registration_settings(
            default_enabled=bool(current_app.config["PASSKEY_REGISTRATION_ENABLED"])
        )
        passkey_settings = store.get_passkey_settings()
        return _no_store(
            jsonify(
                {
                    "ok": True,
                    "currentUserId": actor.id,
                    "users": users,
                    "platforms": [_client_payload(client) for client in store.list_oauth_clients()],
                    "loginHistory": store.list_login_history(limit=500),
                    "auditLogs": store.list_audit_logs(limit=500),
                    "registration": {
                        "mode": settings.mode,
                        "enabledUntil": settings.enabled_until,
                        "defaultDemoAllowed": settings.default_demo_allowed,
                    },
                    "passkeySettings": {
                        "algorithms": passkey_settings.algorithms,
                        "authenticatorAttachment": passkey_settings.authenticator_attachment,
                        "residentKey": passkey_settings.resident_key,
                        "userVerification": passkey_settings.user_verification,
                        "attestation": passkey_settings.attestation,
                        "excludeCredentials": passkey_settings.exclude_credentials,
                        "hints": passkey_settings.hints,
                    },
                }
            )
        )

    @blueprint.post("/api/management/channel/start")
    def start_channel():
        actor = _require_admin()
        if not isinstance(actor, User):
            return actor
        csrf_error = _require_csrf()
        if csrf_error:
            return csrf_error
        recent_error = _require_recent_management_auth()
        if recent_error:
            return recent_error
        action_token_session_id = str(session.get("action_token_session_id") or "")
        if not action_token_session_id:
            return _action_token_error("action_token_missing")
        data = request.get_json(force=True)
        try:
            public_key = _public_key_from_jwk(data.get("publicKeyJwk"))
        except ValueError as error:
            return _error(str(error), 400)
        now = int(time.time())
        channel = ManagementChannel(
            channel_id=secrets.token_urlsafe(24),
            user_id=actor.id,
            action_token_session_id=action_token_session_id,
            public_key=public_key,
            server_nonce=secrets.token_urlsafe(24),
            last_counter=0,
            created_at=now,
            expires_at=now + _CHANNEL_TTL_SECONDS,
            last_seen_at=now,
            ack_after_ms=_CHANNEL_DEFAULT_ACK_MS,
        )
        registry = _channels()
        _prune_channels(registry, now=now)
        registry[channel.channel_id] = channel
        session["management_channel_id"] = channel.channel_id
        return _no_store(jsonify({"ok": True, **_channel_payload(channel)}))

    @blueprint.get("/api/management/channel/events")
    def channel_events():
        actor = _require_admin()
        if not isinstance(actor, User):
            return actor
        channel = _session_channel(actor)
        if not channel:
            return _channel_error("channel_missing", 409)

        @stream_with_context
        def stream():
            while True:
                current = _channels().get(channel.channel_id)
                now = int(time.time())
                if not current or current.expires_at <= now:
                    yield _sse_event(
                        "reauth",
                        {
                            "ok": False,
                            "reason": "channel_expired",
                            "reauth_required": True,
                        },
                    )
                    break
                current.server_nonce = secrets.token_urlsafe(24)
                yield _sse_event("challenge", _channel_payload(current))
                time.sleep(max(5, min(current.ack_after_ms, _CHANNEL_MAX_ACK_MS) / 1000))

        response = Response(stream(), mimetype="text/event-stream")
        response.headers["Cache-Control"] = "no-store, no-transform"
        response.headers["X-Accel-Buffering"] = "no"
        return response

    @blueprint.post("/api/management/channel/ack")
    def acknowledge_channel():
        actor = _require_admin()
        if not isinstance(actor, User):
            return actor
        csrf_error = _require_csrf()
        if csrf_error:
            return csrf_error
        data = request.get_json(force=True)
        channel = _session_channel(actor, channel_id=str(data.get("channelId") or ""))
        if not channel:
            return _channel_error("channel_missing", 409)
        result = _verify_channel_proof(
            channel=channel,
            purpose="ack",
            method="POST",
            path="/api/management/channel/ack",
            counter=data.get("counter"),
            client_nonce=str(data.get("clientNonce") or ""),
            signature=str(data.get("signature") or ""),
            visibility=str(data.get("visibility") or "unknown"),
            effective_type=str(data.get("effectiveType") or "unknown"),
            save_data=bool(data.get("saveData", False)),
            rtt_ms=data.get("rttMs"),
        )
        if result:
            return result
        channel.ack_after_ms = _adaptive_ack_ms(data)
        channel.last_seen_at = int(time.time())
        return _no_store(jsonify({"ok": True, **_channel_payload(channel)}))

    @blueprint.patch("/api/management/users/<int:user_id>")
    def update_user(user_id: int):
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        store = _store()
        target = store.get_user_by_id(user_id)
        if not target:
            return _error("用户不存在", 404)
        data = request.get_json(force=True)
        permissions = store.get_permissions(target.id)
        requested_permissions = data.get("permissions") or {}
        next_permissions = {
            key: bool(requested_permissions.get(key, value))
            for key, value in permissions.items()
        }
        disabled = bool(data.get("disabled", target.disabled_at is not None))
        if actor.id == target.id and (
            disabled or not next_permissions.get("admin") or not next_permissions.get("login")
        ):
            return _error("不能停用、降权或关闭自己的登录权限", 409)
        if permissions.get("admin") and (
            disabled or not next_permissions.get("admin") or not next_permissions.get("login")
        ) and store.count_enabled_admins() <= 1:
            return _error("系统必须保留至少一名可用管理员", 409)
        username = normalize_username(data.get("username", target.username))
        if username.casefold() != target.username.casefold():
            if store.get_user_by_username(username):
                return _error("用户名已注册", 409)
            store.rename_user(target.id, username)
        store.set_permissions(target.id, next_permissions)
        store.set_user_disabled(target.id, disabled)
        policy = data.get("platformPolicy")
        if isinstance(policy, dict):
            store.set_platform_policy(
                target.id,
                str(policy.get("mode") or "allow_all"),
                policy.get("clientIds") or [],
            )
        if actor.id == target.id:
            refreshed = store.get_user_by_id(actor.id)
            session["signed_in_session_version"] = refreshed.session_version
        _audit(actor, "user.update", "user", str(target.id), {"username": username})
        return _no_store(jsonify({"ok": True}))

    @blueprint.delete("/api/management/users/<int:user_id>")
    def delete_user(user_id: int):
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        store = _store()
        target = store.get_user_by_id(user_id)
        if not target:
            return _error("用户不存在", 404)
        if actor.id == target.id:
            return _error("不能删除自己的管理员账户", 409)
        if store.get_permissions(target.id)["admin"] and store.count_enabled_admins() <= 1:
            return _error("系统必须保留至少一名可用管理员", 409)
        store.delete_user(target.id)
        _telemetry().drop_user_policy(target.id)
        _audit(actor, "user.delete", "user", str(target.id), {"username": target.username})
        return _no_store(jsonify({"ok": True}))

    @blueprint.post("/api/management/users/<int:user_id>/revoke-sessions")
    def revoke_sessions(user_id: int):
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        if actor.id == user_id:
            return _error("不能在当前控制台撤销自己的全部会话", 409)
        store = _store()
        if not store.get_user_by_id(user_id):
            return _error("用户不存在", 404)
        store.bump_session_version(user_id)
        _audit(actor, "user.revoke_sessions", "user", str(user_id), {})
        return _no_store(jsonify({"ok": True}))

    @blueprint.delete(
        "/api/management/users/<int:user_id>/credentials/<int:credential_id>"
    )
    def delete_credential(user_id: int, credential_id: int):
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        if actor.id == user_id:
            return _error("不能在当前控制台删除自己的 Passkey", 409)
        if not _store().delete_credential(credential_id, user_id):
            return _error("Passkey 不存在", 404)
        _audit(actor, "credential.delete", "user", str(user_id), {"credentialId": credential_id})
        return _no_store(jsonify({"ok": True}))

    @blueprint.post("/api/management/platforms")
    def create_platform():
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        data = request.get_json(force=True)
        client_id = str(data.get("clientId") or "").strip()
        name = str(data.get("name") or "").strip()
        redirect_uris = _redirect_uris(data.get("redirectUris"))
        if not client_id or not name or not redirect_uris:
            return _error("平台名称、client_id 和回调地址不能为空", 400)
        secret = secrets.token_urlsafe(32)
        try:
            _store().create_oauth_client(
                client_id=client_id,
                name=name,
                client_secret=secret,
                redirect_uris=redirect_uris,
            )
        except Exception:
            return _error("client_id 已存在或平台配置无效", 409)
        _audit(actor, "platform.create", "platform", client_id, {"name": name})
        return _no_store(jsonify({"ok": True, "clientSecret": secret}))

    @blueprint.patch("/api/management/platforms/<client_id>")
    def update_platform(client_id: str):
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        data = request.get_json(force=True)
        _store().update_oauth_client(
            client_id,
            name=str(data.get("name") or client_id).strip(),
            redirect_uris=_redirect_uris(data.get("redirectUris")),
            enabled=bool(data.get("enabled", True)),
        )
        _audit(actor, "platform.update", "platform", client_id, {})
        return _no_store(jsonify({"ok": True}))

    @blueprint.post("/api/management/platforms/<client_id>/rotate-secret")
    def rotate_platform_secret(client_id: str):
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        if not _store().get_oauth_client(client_id):
            return _error("平台不存在", 404)
        secret = secrets.token_urlsafe(32)
        _store().rotate_oauth_client_secret(client_id, secret)
        _audit(actor, "platform.rotate_secret", "platform", client_id, {})
        return _no_store(jsonify({"ok": True, "clientSecret": secret}))

    @blueprint.delete("/api/management/platforms/<client_id>")
    def delete_platform(client_id: str):
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        client = _store().get_oauth_client(client_id)
        if not client:
            return _error("平台不存在", 404)
        if client.is_demo:
            return _error("不能删除内置平台，可以将其停用", 409)
        _store().delete_oauth_client(client_id)
        _audit(actor, "platform.delete", "platform", client_id, {})
        return _no_store(jsonify({"ok": True}))

    @blueprint.patch("/api/management/settings/registration")
    def update_registration():
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        data = request.get_json(force=True)
        mode = str(data.get("mode") or "closed")
        enabled_until = data.get("enabledUntil")
        if mode == "temporary":
            enabled_until = int(enabled_until or 0)
            if enabled_until <= int(time.time()):
                return _error("临时开放时间必须晚于当前时间", 400)
        else:
            enabled_until = None
        _store().set_registration_settings(
            mode=mode,
            enabled_until=enabled_until,
            default_demo_allowed=bool(data.get("defaultDemoAllowed", True)),
        )
        _audit(actor, "registration.update", "settings", "registration", {"mode": mode})
        return _no_store(jsonify({"ok": True}))

    @blueprint.patch("/api/management/settings/passkey")
    def update_passkey_settings():
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        data = request.get_json(force=True)
        try:
            _store().set_passkey_settings(
                algorithms=data.get("algorithms") or [],
                authenticator_attachment=str(
                    data.get("authenticatorAttachment") or "any"
                ),
                resident_key=str(data.get("residentKey") or "required"),
                user_verification=str(
                    data.get("userVerification") or "preferred"
                ),
                attestation=str(data.get("attestation") or "none"),
                exclude_credentials=bool(data.get("excludeCredentials", True)),
                hints=data.get("hints") or [],
            )
        except (TypeError, ValueError) as error:
            return _error(str(error), 400)
        _audit(
            actor,
            "passkey_settings.update",
            "settings",
            "passkey",
            {
                "algorithms": data.get("algorithms") or [],
                "residentKey": data.get("residentKey"),
                "userVerification": data.get("userVerification"),
            },
        )
        return _no_store(jsonify({"ok": True}))

    @blueprint.get("/api/management/telemetry")
    def telemetry_overview():
        actor = _require_admin()
        if not isinstance(actor, User):
            return actor
        runtime = _telemetry()
        return _no_store(
            jsonify(
                {
                    "ok": True,
                    "settings": runtime.settings_payload(),
                    "userPolicies": runtime.policies_payload(),
                    "statistics": runtime.statistics(),
                }
            )
        )

    @blueprint.patch("/api/management/settings/telemetry")
    def update_telemetry_settings():
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        data = request.get_json(force=True)
        try:
            settings = _telemetry().update_settings(
                enabled=bool(data.get("enabled", False)),
                anonymous_enabled=bool(data.get("anonymousEnabled", False)),
                default_features=data.get("defaultFeatures") or [],
                retention_days=int(data.get("retentionDays") or 30),
                backend=(
                    str(data["backend"])
                    if "backend" in data
                    else None
                ),
                delivery_mode=(
                    str(data["deliveryMode"])
                    if "deliveryMode" in data
                    else None
                ),
                jason_base_url=(
                    str(data["jasonBaseUrl"])
                    if "jasonBaseUrl" in data
                    else None
                ),
                jason_api_key=_secret_update(
                    data,
                    value_key="jasonApiKey",
                    clear_key="clearJasonApiKey",
                ),
                custom_url=(
                    str(data["customUrl"])
                    if "customUrl" in data
                    else None
                ),
                custom_auth_mode=(
                    str(data["customAuthMode"])
                    if "customAuthMode" in data
                    else None
                ),
                custom_auth_header=(
                    str(data["customAuthHeader"])
                    if "customAuthHeader" in data
                    else None
                ),
                custom_secret=_secret_update(
                    data,
                    value_key="customSecret",
                    clear_key="clearCustomSecret",
                ),
                custom_headers=(
                    data["customHeaders"]
                    if "customHeaders" in data
                    else None
                ),
                custom_direct_content_type=(
                    str(data["customDirectContentType"])
                    if "customDirectContentType" in data
                    else None
                ),
                timeout_seconds=(
                    float(data["timeoutSeconds"])
                    if "timeoutSeconds" in data
                    else None
                ),
            )
        except (TypeError, ValueError) as error:
            return _error(str(error), 400)
        _audit(
            actor,
            "telemetry_settings.update",
            "settings",
            "telemetry",
            {
                "enabled": settings.enabled,
                "anonymousEnabled": settings.anonymous_enabled,
                "defaultFeatures": settings.default_features,
                "retentionDays": settings.retention_days,
                "backend": settings.backend,
                "deliveryMode": settings.delivery_mode,
            },
        )
        return _no_store(jsonify({"ok": True}))

    @blueprint.post("/api/management/telemetry/backend/test")
    def test_telemetry_backend():
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        try:
            result = _telemetry().test_backend()
        except Exception:
            return _error("遥测后端连接失败", 502)
        _audit(
            actor,
            "telemetry_backend.test",
            "settings",
            "telemetry",
            {"backend": result.get("backend")},
        )
        return _no_store(jsonify(result))

    @blueprint.post("/api/management/telemetry/backend/pair-jason")
    def pair_jason_telemetry():
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        data = request.get_json(force=True)
        try:
            result = _telemetry().pair_jason(
                base_url=str(data.get("baseUrl") or ""),
                pairing_code=str(data.get("pairingCode") or ""),
                timeout_seconds=float(data.get("timeoutSeconds") or 1.0),
                delivery_mode=str(data.get("deliveryMode") or "relay"),
            )
        except (TypeError, ValueError) as error:
            return _error(str(error), 400)
        except Exception:
            return _error("自动配对失败，请检查地址、配对码和 TLS", 502)
        _audit(
            actor,
            "telemetry_backend.pair",
            "settings",
            "telemetry",
            {
                "backend": "jason",
                "serverVersion": result.get("serverVersion"),
            },
        )
        return _no_store(jsonify(result))

    @blueprint.patch("/api/management/users/<int:user_id>/telemetry")
    def update_user_telemetry(user_id: int):
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        data = request.get_json(force=True)
        try:
            policy = _telemetry().update_user_policy(
                user_id=user_id,
                mode=str(data.get("mode") or "inherit"),
                features=data.get("features") or [],
            )
        except (TypeError, ValueError) as error:
            return _error(str(error), 400)
        _audit(
            actor,
            "user.telemetry.update",
            "user",
            str(user_id),
            {"mode": policy.mode, "features": policy.features},
        )
        return _no_store(jsonify({"ok": True}))

    @blueprint.get("/api/management/telemetry/events/count")
    def count_telemetry_events():
        actor = _require_admin()
        if not isinstance(actor, User):
            return actor
        before = int(request.args["before"]) if request.args.get("before") else None
        try:
            count = _telemetry().count_events(before=before)
        except ValueError as error:
            return _error(str(error), 409)
        return _no_store(jsonify({"ok": True, "count": count}))

    @blueprint.post("/api/management/telemetry/events/clear")
    def clear_telemetry_events():
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        data = request.get_json(silent=True) or {}
        before = int(data["before"]) if data.get("before") else None
        try:
            deleted = _telemetry().clear_events(before=before)
        except ValueError as error:
            return _error(str(error), 409)
        _audit(
            actor,
            "telemetry.clear",
            "telemetry",
            "events",
            {"deleted": deleted, "before": before},
        )
        return _no_store(jsonify({"ok": True, "deleted": deleted}))

    @blueprint.get("/api/management/export/telemetry.csv")
    def export_telemetry_csv():
        actor = _require_admin()
        if not isinstance(actor, User):
            return actor
        try:
            content = _telemetry().export_csv()
        except ValueError as error:
            return _error(str(error), 409)
        response = Response(content, mimetype="text/csv; charset=utf-8")
        response.headers["Content-Disposition"] = (
            'attachment; filename="passkey-auth-telemetry.csv"'
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @blueprint.post("/api/management/logs/<log_type>/clear")
    def clear_logs(log_type: str):
        actor = _require_write()
        if not isinstance(actor, User):
            return actor
        data = request.get_json(silent=True) or {}
        before = int(data["before"]) if data.get("before") else None
        try:
            deleted = _store().clear_logs(
                log_type=log_type,
                actor=actor,
                before=before,
            )
        except ValueError as error:
            return _error(str(error), 400)
        return _no_store(jsonify({"ok": True, "deleted": deleted}))

    @blueprint.get("/api/management/logs/<log_type>/count")
    def count_logs(log_type: str):
        actor = _require_admin()
        if not isinstance(actor, User):
            return actor
        before = int(request.args["before"]) if request.args.get("before") else None
        try:
            count = _store().count_logs(log_type=log_type, before=before)
        except ValueError as error:
            return _error(str(error), 400)
        return _no_store(jsonify({"ok": True, "count": count}))

    @blueprint.get("/api/management/export/<export_type>.csv")
    def export_csv(export_type: str):
        actor = _require_admin()
        if not isinstance(actor, User):
            return actor
        rows, fields = _export_rows(export_type)
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key)) for key in fields})
        response = Response(
            "\ufeff" + output.getvalue(),
            mimetype="text/csv; charset=utf-8",
        )
        response.headers["Content-Disposition"] = (
            f'attachment; filename="passkey-auth-{export_type}.csv"'
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    return blueprint


def _store() -> PasskeyStore:
    return current_app.extensions["passkey_store"]


def _telemetry():
    return current_app.extensions["telemetry_runtime"]


def _current_user() -> User | None:
    user_id = session.get("signed_in_user_id")
    user = _store().get_user_by_id(int(user_id or 0))
    if (
        not user
        or user.disabled_at is not None
        or session.get("signed_in_session_version") != user.session_version
        or not _store().get_permissions(user.id)["login"]
    ):
        return None
    return user


def _require_admin(*, html: bool = False):
    user = _current_user()
    if not user:
        if html:
            return _management_error_page("请先完成 Passkey 登录", 401)
        return _error("请先完成 Passkey 登录", 401)
    if not _store().get_permissions(user.id)["admin"]:
        if html:
            return _management_error_page("没有管理权限", 403)
        return _error("没有管理权限", 403)
    return user


def _require_write():
    user = _require_admin()
    if not isinstance(user, User):
        return user
    expected = session.get("management_csrf_token")
    provided = request.headers.get("X-CSRF-Token", "")
    if not expected or not secrets.compare_digest(str(expected), provided):
        return _error("CSRF 校验失败", 403)
    reauthenticated_at = int(session.get("management_reauthenticated_at") or 0)
    if reauthenticated_at < int(time.time()) - 300:
        return _error("请重新完成 Passkey 登录后再执行此操作", 428)
    channel_id = str(session.get("management_channel_id") or "")
    if channel_id:
        channel = _session_channel(user, channel_id=channel_id)
        if not channel:
            return _channel_error("channel_missing", 409)
        if channel.last_seen_at < int(time.time()) - _CHANNEL_STALE_SECONDS:
            return _channel_error("channel_stale", 409)
        if request.headers.get("X-Management-Channel-Id", "") != channel.channel_id:
            return _channel_error("channel_proof_missing", 409)
        channel_error = _verify_channel_proof(
            channel=channel,
            purpose="write",
            method=request.method,
            path=request.path,
            counter=request.headers.get("X-Management-Channel-Counter"),
            client_nonce=request.headers.get("X-Management-Channel-Client-Nonce", ""),
            signature=request.headers.get("X-Management-Channel-Signature", ""),
            visibility=request.headers.get("X-Management-Channel-Visibility", "unknown"),
            effective_type=request.headers.get(
                "X-Management-Channel-Effective-Type",
                "unknown",
            ),
            save_data=request.headers.get("X-Management-Channel-Save-Data") == "1",
            rtt_ms=None,
        )
        if channel_error:
            return channel_error
    session_id = str(session.get("action_token_session_id") or "")
    provided = request.headers.get("X-Action-Token", "")
    if not session_id or not provided:
        return _action_token_error("action_token_missing")
    next_token = secrets.token_urlsafe(32)
    if not _store().rotate_action_token(
        session_id=session_id,
        user_id=user.id,
        current_token=provided,
        next_token=next_token,
    ):
        return _action_token_error("action_token_mismatch")
    g.action_token_session_id = session_id
    g.action_token_user_id = user.id
    g.previous_action_token = provided
    g.next_action_token = next_token
    return user


def _require_csrf():
    expected = session.get("management_csrf_token")
    provided = request.headers.get("X-CSRF-Token", "")
    if not expected or not secrets.compare_digest(str(expected), provided):
        return _error("CSRF 校验失败", 403)
    return None


def _require_recent_management_auth():
    reauthenticated_at = int(session.get("management_reauthenticated_at") or 0)
    if reauthenticated_at < int(time.time()) - 300:
        return _error("请重新完成 Passkey 登录后再执行此操作", 428)
    return None


def _channels() -> dict[str, ManagementChannel]:
    return current_app.extensions.setdefault(_CHANNEL_REGISTRY_KEY, {})


def _prune_channels(
    registry: dict[str, ManagementChannel],
    *,
    now: int,
) -> None:
    for channel_id, channel in list(registry.items()):
        if channel.expires_at <= now:
            registry.pop(channel_id, None)


def _session_channel(
    user: User,
    *,
    channel_id: str | None = None,
) -> ManagementChannel | None:
    expected_id = channel_id or str(session.get("management_channel_id") or "")
    channel = _channels().get(expected_id)
    now = int(time.time())
    if not channel or channel.expires_at <= now:
        _channels().pop(expected_id, None)
        session.pop("management_channel_id", None)
        return None
    if (
        channel.user_id != user.id
        or channel.action_token_session_id != str(session.get("action_token_session_id") or "")
    ):
        return None
    return channel


def _channel_payload(channel: ManagementChannel) -> dict:
    return {
        "channel_id": channel.channel_id,
        "server_nonce": channel.server_nonce,
        "ack_after_ms": channel.ack_after_ms,
        "min_ack_after_ms": _CHANNEL_MIN_ACK_MS,
        "max_ack_after_ms": _CHANNEL_MAX_ACK_MS,
        "expires_at": channel.expires_at,
        "last_seen_at": channel.last_seen_at,
    }


def _public_key_from_jwk(value) -> EllipticCurvePublicKey:
    if not isinstance(value, dict):
        raise ValueError("通道公钥无效")
    if value.get("kty") != "EC" or value.get("crv") != "P-256":
        raise ValueError("通道公钥必须使用 P-256 ECDSA")
    try:
        x = int.from_bytes(base64url_to_bytes(str(value["x"])), "big")
        y = int.from_bytes(base64url_to_bytes(str(value["y"])), "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except Exception as exc:
        raise ValueError("通道公钥无效") from exc


def _verify_channel_proof(
    *,
    channel: ManagementChannel,
    purpose: str,
    method: str,
    path: str,
    counter,
    client_nonce: str,
    signature: str,
    visibility: str,
    effective_type: str,
    save_data: bool,
    rtt_ms,
):
    try:
        counter_value = int(counter)
    except (TypeError, ValueError):
        return _channel_error("channel_counter_invalid", 409)
    if counter_value <= channel.last_counter:
        return _channel_error("channel_replay", 409)
    if not client_nonce or not signature:
        return _channel_error("channel_proof_missing", 409)
    message = _channel_message(
        purpose=purpose,
        channel_id=channel.channel_id,
        counter=counter_value,
        server_nonce=channel.server_nonce,
        client_nonce=client_nonce,
        method=method,
        path=path,
        visibility=visibility,
        effective_type=effective_type,
        save_data=save_data,
        rtt_ms=rtt_ms,
    )
    try:
        channel.public_key.verify(
            _ecdsa_signature_bytes(signature),
            message.encode("utf-8"),
            ec.ECDSA(SHA256()),
        )
    except (InvalidSignature, ValueError):
        return _channel_error("channel_signature_invalid", 409)
    channel.last_counter = counter_value
    channel.last_seen_at = int(time.time())
    return None


def _channel_message(
    *,
    purpose: str,
    channel_id: str,
    counter: int,
    server_nonce: str,
    client_nonce: str,
    method: str,
    path: str,
    visibility: str,
    effective_type: str,
    save_data: bool,
    rtt_ms,
) -> str:
    rtt_value = "" if rtt_ms is None else str(int(rtt_ms))
    return "\n".join(
        [
            "passkey-management-channel-v1",
            purpose,
            channel_id,
            str(counter),
            server_nonce,
            client_nonce,
            method.upper(),
            path,
            visibility,
            effective_type,
            "1" if save_data else "0",
            rtt_value,
        ]
    )


def _ecdsa_signature_bytes(value: str) -> bytes:
    signature = base64url_to_bytes(value)
    if len(signature) != 64:
        return signature
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    return utils.encode_dss_signature(r, s)


def _adaptive_ack_ms(data: dict) -> int:
    visibility = str(data.get("visibility") or "unknown")
    effective_type = str(data.get("effectiveType") or "unknown")
    save_data = bool(data.get("saveData", False))
    try:
        rtt_ms = int(data.get("rttMs") or 0)
    except (TypeError, ValueError):
        rtt_ms = 0
    if visibility != "visible":
        interval = 180_000
    elif save_data:
        interval = 180_000
    elif effective_type in {"slow-2g", "2g"}:
        interval = 120_000
    elif effective_type == "3g" or rtt_ms > 1500:
        interval = 90_000
    else:
        interval = _CHANNEL_DEFAULT_ACK_MS
    return max(_CHANNEL_MIN_ACK_MS, min(interval, _CHANNEL_MAX_ACK_MS))


def _sse_event(event: str, payload: dict) -> str:
    return f"event: {event}\ndata: {current_app.json.dumps(payload)}\n\n"


def _audit(
    actor: User,
    action: str,
    target_type: str,
    target_id: str,
    details: dict,
) -> None:
    _store().record_audit(
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details,
        ip_address=request.remote_addr or "",
        user_agent=request.headers.get("User-Agent", ""),
    )


def _client_payload(client) -> dict:
    return {
        "id": client.id,
        "clientId": client.client_id,
        "name": client.name,
        "redirectUris": client.redirect_uris,
        "enabled": client.enabled,
        "isDemo": client.is_demo,
        "createdAt": client.created_at,
        "updatedAt": client.updated_at,
    }


def _redirect_uris(value) -> list[str]:
    if isinstance(value, list):
        redirect_uris = {str(item).strip() for item in value if str(item).strip()}
    else:
        redirect_uris = {
            item.strip()
            for line in str(value or "").splitlines()
            for item in line.split(",")
            if item.strip()
        }
    for redirect_uri in redirect_uris:
        parts = urlsplit(redirect_uri)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise ValueError("回调地址必须是完整的 HTTP 或 HTTPS URL")
    return sorted(redirect_uris)


def _secret_update(data: dict, *, value_key: str, clear_key: str) -> str | None:
    if bool(data.get(clear_key, False)):
        return ""
    if value_key not in data:
        return None
    value = str(data.get(value_key) or "")
    return value if value else None


def _export_rows(export_type: str) -> tuple[list[dict], list[str]]:
    store = _store()
    if export_type == "users":
        rows = []
        for row in store.list_users():
            user = store.get_user_by_id(int(row["id"]))
            if not user:
                continue
            permissions = store.get_permissions(user.id)
            policy = store.get_platform_policy(user.id)
            rows.append(
                {
                    "id": user.id,
                    "username": user.username,
                    "sub": bytes_to_base64url(user.user_handle),
                    "admin": permissions["admin"],
                    "login": permissions["login"],
                    "demo": permissions["demo"],
                    "disabled_at": _iso(user.disabled_at),
                    "created_at": _iso(user.created_at),
                    "credential_count": row["credential_count"],
                    "last_login_at": _iso(row["last_login_at"]),
                    "platform_policy_mode": policy["mode"],
                    "platform_client_ids": ",".join(policy["client_ids"]),
                }
            )
        return rows, [
            "id", "username", "sub", "admin", "login", "demo", "disabled_at",
            "created_at", "credential_count", "last_login_at",
            "platform_policy_mode", "platform_client_ids",
        ]
    if export_type == "platforms":
        rows = [
            {
                "client_id": client.client_id,
                "name": client.name,
                "redirect_uris": ",".join(client.redirect_uris),
                "enabled": client.enabled,
                "is_demo": client.is_demo,
                "created_at": _iso(client.created_at),
                "updated_at": _iso(client.updated_at),
            }
            for client in store.list_oauth_clients()
        ]
        return rows, [
            "client_id", "name", "redirect_uris", "enabled", "is_demo",
            "created_at", "updated_at",
        ]
    if export_type == "login-history":
        rows = store.list_login_history(limit=100_000)
        for row in rows:
            row["created_at"] = _iso(row["created_at"])
        return rows, [
            "id", "user_id", "username_snapshot", "sub_snapshot", "client_id",
            "flow", "result", "credential_hint", "ip_address", "user_agent", "created_at",
        ]
    if export_type == "audit-logs":
        rows = store.list_audit_logs(limit=100_000)
        for row in rows:
            row["created_at"] = _iso(row["created_at"])
        return rows, [
            "id", "actor_user_id", "actor_username", "action", "target_type",
            "target_id", "details", "ip_address", "user_agent", "created_at",
        ]
    raise ValueError("未知导出类型")


def _csv_value(value):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value)
    if text[:1] in {"=", "+", "-", "@"}:
        return "'" + text
    return text


def _iso(value) -> str:
    if value is None or value == "":
        return ""
    return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()


def _error(message: str, status: int):
    return _no_store((jsonify({"ok": False, "error": message}), status))


def _action_token_error(reason: str):
    return _no_store(
        (
            jsonify(
                {
                    "ok": False,
                    "error": "操作令牌无效，请重新完成 Passkey 验证",
                    "reauth_required": True,
                    "reason": reason,
                }
            ),
            409,
        )
    )


def _channel_error(reason: str, status: int):
    return _no_store(
        (
            jsonify(
                {
                    "ok": False,
                    "error": "管理通道已失效，请重新完成 Passkey 验证",
                    "reauth_required": True,
                    "reason": reason,
                }
            ),
            status,
        )
    )


def _management_error_page(message: str, status: int):
    response = current_app.make_response(
        (
            render_template(
                "error.html",
                status_code=status,
                status_label=f"{status} · {'Unauthorized' if status == 401 else 'Forbidden'}",
                error_message=message,
                home_auth_enabled=current_app.config["PASSKEY_HOME_AUTH_ENABLED"],
            ),
            status,
        )
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _no_store(response):
    target = response[0] if isinstance(response, tuple) else response
    target.headers["Cache-Control"] = "no-store"
    return response
