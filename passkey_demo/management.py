from __future__ import annotations

import csv
import io
import secrets
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from flask import Blueprint, Response, current_app, jsonify, render_template, request, session
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException

from .storage import PasskeyStore, User
from .webauthn_service import (
    WebAuthnConfig,
    build_authentication_options,
    credential_for_options,
    normalize_username,
    verify_authentication,
)


def create_management_blueprint() -> Blueprint:
    blueprint = Blueprint("management", __name__)

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

    @blueprint.post("/api/management/reauth/options")
    def reauth_options():
        actor = _require_admin()
        if not isinstance(actor, User):
            return actor
        csrf_error = _require_csrf()
        if csrf_error:
            return csrf_error
        credentials = _store().list_credentials_for_user(actor.id)
        if not credentials:
            return _error("当前账户没有可用于验证的 Passkey", 409)
        public_key, challenge = build_authentication_options(
            allowed_credentials=[
                credential_for_options(credential) for credential in credentials
            ],
            config=_management_webauthn_config(require_user_verification=True),
        )
        session["management_reauth_challenge"] = challenge
        return _no_store(jsonify({"ok": True, "publicKey": public_key}))

    @blueprint.post("/api/management/reauth/verify")
    def reauth_verify():
        actor = _require_admin()
        if not isinstance(actor, User):
            return actor
        csrf_error = _require_csrf()
        if csrf_error:
            return csrf_error
        challenge = session.get("management_reauth_challenge")
        if not challenge:
            return _error("验证会话已过期，请重新开始", 400)

        credential_json = (request.get_json(force=True) or {}).get("credential", {})
        credential_id = base64url_to_bytes(credential_json.get("rawId", ""))
        credential = _store().get_credential_by_id(credential_id)
        if not credential or credential.user_id != actor.id:
            session.pop("management_reauth_challenge", None)
            return _error("必须使用当前管理员账户的 Passkey", 403)
        try:
            result = verify_authentication(
                credential=credential_json,
                expected_challenge=str(challenge),
                credential_public_key=credential.public_key,
                credential_current_sign_count=credential.sign_count,
                config=_management_webauthn_config(require_user_verification=True),
            )
        except WebAuthnException:
            session.pop("management_reauth_challenge", None)
            raise

        _store().update_sign_count(result.credential_id, result.new_sign_count)
        session.pop("management_reauth_challenge", None)
        session["management_reauthenticated_at"] = int(time.time())
        _audit(actor, "management.reauthenticate", "session", str(actor.id), {})
        return _no_store(jsonify({"ok": True}))

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
    return user


def _require_csrf():
    expected = session.get("management_csrf_token")
    provided = request.headers.get("X-CSRF-Token", "")
    if not expected or not secrets.compare_digest(str(expected), provided):
        return _error("CSRF 校验失败", 403)
    return None


def _management_webauthn_config(
    *,
    require_user_verification: bool,
) -> WebAuthnConfig:
    settings = _store().get_passkey_settings()
    origin = current_app.config["PASSKEY_ORIGIN"] or request.host_url.rstrip("/")
    return WebAuthnConfig(
        rp_id=current_app.config["PASSKEY_RP_ID"],
        rp_name=current_app.config["PASSKEY_RP_NAME"],
        origin=origin,
        require_user_verification=require_user_verification,
        user_verification="required" if require_user_verification else settings.user_verification,
    )


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
