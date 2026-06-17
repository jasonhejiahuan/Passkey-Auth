from __future__ import annotations

import secrets
import time
import json
from base64 import b64decode
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from flask import Flask, g, jsonify, redirect, render_template, request, session
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import AppConfig, ServerConfig
from .register_client import REGISTER_CLIENT_JS
from .storage import OAuthChallengeRequest, PasskeyStore, User
from .webauthn_service import (
    WebAuthnConfig,
    build_authentication_options,
    build_registration_options,
    credential_for_options,
    normalize_username,
    verify_authentication,
    verify_registration,
)


def create_app() -> Flask:
    app = Flask(__name__)
    config = AppConfig.from_env(instance_path=app.instance_path)
    app.secret_key = config.flask_secret_key
    app.config.update(config.flask_mapping())
    _configure_proxy_support(app)

    store = PasskeyStore(config.passkey_database)

    @app.after_request
    def add_observability_and_protocol_headers(response):
        _inject_browser_telemetry(app, response)
        _apply_server_timing_header(app, response)
        _apply_security_headers(app, response)
        return response

    @app.before_request
    def start_server_timing():
        _start_server_timing(app)

    @app.get("/_error/<int:status_code>")
    def edge_error(status_code: int):
        return _render_error_page(status_code)

    @app.errorhandler(HTTPException)
    def app_error(error: HTTPException):
        return _render_error_page(error.code or 500)

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/me")
    def me():
        user = _current_user(store, session)
        if not user:
            return jsonify({"authenticated": False})
        return jsonify({"authenticated": True})

    @app.post("/api/telemetry/browser-token")
    def telemetry_browser_token():
        payload, status = _create_telemetry_browser_token(app)
        return _no_store(jsonify(payload)), status

    @app.get("/demo/oauth")
    def oauth_demo():
        state = secrets.token_urlsafe(24)
        session["demo_oauth_state"] = state
        client = _default_oauth_client(app)
        redirect_uri = _external_url("/demo/oauth/callback")
        authorize_url = _url_with_params(
            _external_url("/oauth/authorize"),
            {
                "response_type": "code",
                "client_id": client["client_id"],
                "redirect_uri": redirect_uri,
                "state": state,
            },
        )
        return render_template(
            "oauth_demo.html",
            authorize_url=authorize_url,
            client_id=client["client_id"],
            redirect_uri=redirect_uri,
        )

    @app.get("/demo/oauth/callback")
    def oauth_demo_callback():
        error = request.args.get("error")
        if error:
            return render_template(
                "oauth_result.html",
                ok=False,
                error=error,
                error_description=request.args.get("error_description", ""),
                token_response=None,
            )

        state = request.args.get("state", "")
        expected_state = session.pop("demo_oauth_state", "")
        if not state or not secrets.compare_digest(state, expected_state):
            return render_template(
                "oauth_result.html",
                ok=False,
                error="invalid_state",
                error_description="OAuth state 校验失败",
                token_response=None,
            )

        payload, status = _exchange_authorization_code(
            app=app,
            store=store,
            code=request.args.get("code", ""),
            client_id=_default_oauth_client(app)["client_id"],
            client_secret=_default_oauth_client(app)["client_secret"],
            redirect_uri=_external_url("/demo/oauth/callback"),
        )
        return render_template(
            "oauth_result.html",
            ok=status == 200,
            error=payload.get("error", ""),
            error_description=payload.get("error_description", ""),
            token_response=payload if status == 200 else None,
        )

    @app.get("/demo/third-party")
    def third_party_demo():
        state = secrets.token_urlsafe(24)
        session["third_party_oauth_state"] = state
        client = _default_oauth_client(app)
        redirect_uri = _external_url("/demo/third-party/callback")
        authorize_url = _url_with_params(
            _external_url("/oauth/authorize"),
            {
                "response_type": "code",
                "client_id": client["client_id"],
                "redirect_uri": redirect_uri,
                "state": state,
            },
        )
        return render_template(
            "third_party_demo.html",
            authorize_url=authorize_url,
            client_id=client["client_id"],
            redirect_uri=redirect_uri,
        )

    @app.get("/demo/link-login")
    def link_login_demo():
        client = _default_oauth_client(app)
        return render_template(
            "link_login_demo.html",
            client_id=client["client_id"],
            return_uri=_external_url("/demo/link-login/callback"),
            auth_base_url=_external_url("/oauth/challenge/"),
        )

    @app.post("/demo/link-login/start")
    def link_login_start():
        try:
            username = normalize_username(request.form.get("username", ""))
        except ValueError as error:
            return render_template(
                "link_login_demo.html",
                error=str(error),
                client_id=_default_oauth_client(app)["client_id"],
                return_uri=_external_url("/demo/link-login/callback"),
                auth_base_url=_external_url("/oauth/challenge/"),
            ), 400

        state = secrets.token_urlsafe(24)
        session["link_login_state"] = state
        client_id = _default_oauth_client(app)["client_id"]
        return_uri = _external_url("/demo/link-login/callback")
        challenge_id = store.create_oauth_challenge_request(
            client_id=client_id,
            return_uri=return_uri,
            username=username,
            state=state,
            ttl_seconds=app.config["PASSKEY_OAUTH_CHALLENGE_TTL_SECONDS"],
            challenge_factory=lambda: secrets.token_urlsafe(32),
        )
        return redirect(_external_url(f"/oauth/challenge/{challenge_id}"))

    @app.get("/demo/link-login/callback")
    def link_login_callback():
        callback_params = request.args.to_dict(flat=True)
        state = request.args.get("state", "")
        expected_state = session.pop("link_login_state", "")
        if not state or not secrets.compare_digest(state, expected_state):
            return render_template(
                "link_login_result.html",
                ok=False,
                error="invalid_state",
                error_description="原网站 state 校验失败",
                callback_params=callback_params,
                user=None,
            )

        user, error, error_description = _consume_challenge_result_token(
            app=app,
            store=store,
            challenge_id=request.args.get("challenge", ""),
            token=request.args.get("challenge_result", ""),
        )
        return render_template(
            "link_login_result.html",
            ok=user is not None,
            error=error,
            error_description=error_description,
            callback_params=callback_params,
            user=_oauth_user_payload(user) if user else None,
        )

    @app.get("/demo/third-party/callback")
    def third_party_callback():
        callback_params = request.args.to_dict(flat=True)
        redirect_uri = _external_url("/demo/third-party/callback")
        error = request.args.get("error")
        if error:
            return render_template(
                "third_party_result.html",
                ok=False,
                error=error,
                error_description=request.args.get("error_description", ""),
                callback_params=callback_params,
                token_response=None,
                userinfo_response=None,
            )

        state = request.args.get("state", "")
        expected_state = session.pop("third_party_oauth_state", "")
        if not state or not secrets.compare_digest(state, expected_state):
            return render_template(
                "third_party_result.html",
                ok=False,
                error="invalid_state",
                error_description="第三方网页 state 校验失败",
                callback_params=callback_params,
                token_response=None,
                userinfo_response=None,
            )

        token_response, token_status = _exchange_authorization_code(
            app=app,
            store=store,
            code=request.args.get("code", ""),
            client_id=_default_oauth_client(app)["client_id"],
            client_secret=_default_oauth_client(app)["client_secret"],
            redirect_uri=redirect_uri,
        )
        if token_status != 200:
            return render_template(
                "third_party_result.html",
                ok=False,
                error=token_response.get("error", "invalid_grant"),
                error_description=token_response.get("error_description", ""),
                callback_params=callback_params,
                token_response=token_response,
                userinfo_response=None,
            )

        userinfo_response, userinfo_status = _fetch_oauth_userinfo(
            app,
            token_response.get("access_token", ""),
        )
        return render_template(
            "third_party_result.html",
            ok=userinfo_status == 200,
            error="" if userinfo_status == 200 else "invalid_userinfo",
            error_description=""
            if userinfo_status == 200
            else userinfo_response.get("error", "userinfo 请求失败"),
            callback_params=callback_params,
            token_response=token_response,
            userinfo_response=userinfo_response,
        )

    @app.get("/oauth/challenge/<challenge_id>")
    def oauth_challenge(challenge_id: str):
        challenge = store.get_oauth_challenge_request(challenge_id)
        if (
            not challenge
            or challenge.expires_at < int(time.time())
            or challenge.completed_at is not None
            or challenge.consumed_at is not None
        ):
            return render_template(
                "oauth_authorize.html",
                ok=False,
                error="invalid_challenge",
                error_description="challenge 不存在或已过期",
            ), 400

        client = _oauth_client(app, challenge.client_id)
        if not client or challenge.return_uri not in client["redirect_uris"]:
            return render_template(
                "oauth_authorize.html",
                ok=False,
                error="invalid_client",
                error_description="OAuth client 或 return_uri 无效",
            ), 400

        return render_template(
            "oauth_authorize.html",
            ok=True,
            mode="challenge",
            client_name=client["name"],
            client_id=challenge.client_id,
            redirect_uri=challenge.return_uri,
            state=challenge.state,
            challenge_id=challenge.challenge_id,
            username=challenge.username,
        )

    @app.post("/oauth/challenge/<challenge_id>/complete")
    def oauth_challenge_complete(challenge_id: str):
        challenge = store.get_oauth_challenge_request(challenge_id)
        if not challenge or challenge.expires_at < int(time.time()):
            return _error("challenge 不存在或已过期", 400)

        client = _oauth_client(app, challenge.client_id)
        if not client or challenge.return_uri not in client["redirect_uris"]:
            return _error("OAuth client 或 return_uri 无效", 400)

        user = _current_user(store, session)
        if not user:
            return _error("请先完成 Passkey 登录", 401)
        if user.username.casefold() != challenge.username.casefold():
            return _error("Passkey 用户和原网站用户名不匹配", 403)

        completed = store.complete_oauth_challenge_request(
            challenge_id=challenge.challenge_id,
            user_id=user.id,
        )
        if not completed:
            return _error("challenge 已完成、已消费或已过期", 400)

        result_token = _issue_challenge_result_token(app, completed, user)
        return _no_store(
            jsonify(
                {
                    "ok": True,
                    "redirectUrl": _url_with_params(
                        completed.return_uri,
                        {
                            "challenge": completed.challenge_id,
                            "challenge_result": result_token,
                            "state": completed.state,
                            "status": "success",
                        },
                    ),
                }
            )
        )

    @app.get("/oauth/authorize")
    def oauth_authorize():
        response_type = request.args.get("response_type", "")
        client_id = request.args.get("client_id", "")
        redirect_uri = request.args.get("redirect_uri", "")
        state = request.args.get("state", "")

        client = _oauth_client(app, client_id)
        if not client or redirect_uri not in client["redirect_uris"]:
            return render_template(
                "oauth_authorize.html",
                ok=False,
                error="invalid_client",
                error_description="OAuth client 或 redirect_uri 无效",
            ), 400

        if response_type != "code":
            return _oauth_redirect_error(
                redirect_uri,
                state,
                "unsupported_response_type",
                "仅支持 authorization code flow",
            )

        return render_template(
            "oauth_authorize.html",
            ok=True,
            mode="code",
            client_name=client["name"],
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            challenge_id="",
            username="",
        )

    @app.post("/oauth/authorize/complete")
    def oauth_authorize_complete():
        data = request.get_json(force=True)
        client_id = data.get("client_id", "")
        redirect_uri = data.get("redirect_uri", "")
        state = data.get("state", "")
        client = _oauth_client(app, client_id)
        if not client or redirect_uri not in client["redirect_uris"]:
            return _error("OAuth client 或 redirect_uri 无效", 400)

        user = _current_user(store, session)
        if not user:
            return _error("请先完成 Passkey 登录", 401)

        code = store.create_oauth_authorization_code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            user_id=user.id,
            ttl_seconds=app.config["PASSKEY_OAUTH_CODE_TTL_SECONDS"],
            code_factory=lambda: secrets.token_urlsafe(32),
        )
        return _no_store(
            jsonify(
                {
                    "ok": True,
                    "redirectUrl": _url_with_params(
                        redirect_uri,
                        {"code": code, "state": state},
                    ),
                }
            )
        )

    @app.post("/oauth/token")
    def oauth_token():
        data = _oauth_request_data()
        client_id, client_secret = _oauth_client_credentials(data)
        payload, status = _exchange_authorization_code(
            app=app,
            store=store,
            code=data.get("code", ""),
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=data.get("redirect_uri", ""),
        )
        return _no_store(jsonify(payload)), status

    @app.get("/oauth/userinfo")
    def oauth_userinfo():
        user = _user_from_access_token(app, store)
        if not user:
            return _error("access token 无效或已过期", 401)
        return _no_store(jsonify(_oauth_user_payload(user)))

    @app.post("/api/server/session/verify")
    def server_verify_session():
        if not _server_api_allowed(app):
            return _error("服务端验证 API 未启用或令牌无效", 401)

        session_data = _session_data_for_server_verify(app)
        if session_data is None:
            return _no_store(
                jsonify(
                    {
                        "ok": True,
                        "authenticated": False,
                        "error": "无效的 session cookie",
                    }
                )
            )

        user = _current_user(store, session_data)
        if not user:
            return _no_store(jsonify({"ok": True, "authenticated": False}))

        return _no_store(
            jsonify(
                {
                    "ok": True,
                    "authenticated": True,
                    "user": {
                        "sub": bytes_to_base64url(user.user_handle),
                        "id": user.id,
                        "username": user.username,
                        "createdAt": user.created_at,
                    },
                }
            )
        )

    @app.post("/api/ui/intent")
    def ui_intent():
        data = request.get_json(force=True)
        if data.get("intent") != "register":
            return _error("未知操作", 400)
        if not _registration_enabled(app):
            _clear_registration_unlock()
            return _error("注册功能未启用", 403)

        session["registration_unlocked"] = True
        session["registration_unlock_expires_at"] = (
            int(time.time()) + app.config["REGISTER_UNLOCK_TTL_SECONDS"]
        )
        return _no_store(
            jsonify(
                {
                    "ok": True,
                    "register": {
                        "usernameMaxLength": 64,
                        "usernamePlaceholder": "用户名",
                        "buttonText": "注册",
                        "clientPath": "/api/ui/register-client.js",
                    },
                }
            )
        )

    @app.get("/api/ui/register-client.js")
    def register_client():
        if not _registration_enabled(app):
            return _no_store(
                app.response_class(
                    "throw new Error('注册功能未启用');",
                    status=403,
                    mimetype="application/javascript",
                )
            )
        if not _registration_unlocked():
            return _no_store(
                app.response_class(
                    "throw new Error('注册入口未解锁或已过期');",
                    status=403,
                    mimetype="application/javascript",
                )
            )
        return _no_store(
            app.response_class(
                REGISTER_CLIENT_JS,
                mimetype="application/javascript",
            )
        )

    @app.post("/api/register/options")
    def register_options():
        data = request.get_json(force=True)
        if not _registration_enabled(app):
            _clear_registration_state()
            _clear_registration_unlock()
            return _no_store(_error("注册功能未启用", 403))
        if not _registration_unlocked():
            return _no_store(_error("注册入口未解锁或已过期", 403))

        username = normalize_username(data.get("username", ""))
        user = store.get_or_create_user(username, lambda: secrets.token_bytes(32))
        credentials = [
            credential_for_options(credential)
            for credential in store.list_credentials_for_user(user.id)
        ]
        public_key, challenge = build_registration_options(
            username=user.username,
            user_handle=user.user_handle,
            existing_credentials=credentials,
            config=_config(app),
        )
        session["registration_challenge"] = challenge
        session["registration_user_id"] = user.id
        return _no_store(jsonify({"publicKey": public_key}))

    @app.post("/api/register/verify")
    def register_verify():
        data = request.get_json(force=True)
        if not _registration_enabled(app):
            _clear_registration_state()
            _clear_registration_unlock()
            return _no_store(_error("注册功能未启用", 403))
        user_id = session.get("registration_user_id")
        challenge = session.get("registration_challenge")
        if not user_id or not challenge:
            return _error("注册会话已过期，请重新开始注册", 400)

        user = store.get_user_by_id(int(user_id))
        if not user:
            return _error("用户不存在，请重新开始注册", 400)

        try:
            result = verify_registration(
                credential=data.get("credential", {}),
                expected_challenge=challenge,
                config=_config(app),
            )
        except WebAuthnException:
            _clear_registration_state()
            raise

        store.save_credential(
            user_id=user.id,
            credential_id=result.credential_id,
            public_key=result.public_key,
            sign_count=result.sign_count,
            transports=result.transports,
            aaguid=result.aaguid,
            credential_type=result.credential_type,
            device_type=result.device_type,
            backed_up=result.backed_up,
        )
        _clear_registration_state()
        session["signed_in_user_id"] = user.id
        return _no_store(jsonify({"ok": True}))

    @app.post("/api/login/options")
    def login_options():
        data = request.get_json(force=True)
        username = (data.get("username") or "").strip()
        credentials = None
        if username:
            username = normalize_username(username)
            user = store.get_user_by_username(username)
            if not user:
                return _error("没有找到这个用户名，请先注册 Passkey", 404)

            credentials = store.list_credentials_for_user(user.id)
            if not credentials:
                return _error("这个用户还没有注册 Passkey", 404)

        public_key, challenge = build_authentication_options(
            allowed_credentials=[
                credential_for_options(credential) for credential in credentials
            ]
            if credentials is not None
            else None,
            config=_config(app),
        )
        session["authentication_challenge"] = challenge
        session["authentication_user_id"] = user.id if username else None
        return jsonify({"publicKey": public_key})

    @app.post("/api/login/verify")
    def login_verify():
        data = request.get_json(force=True)
        challenge = session.get("authentication_challenge")
        user_id = session.get("authentication_user_id")
        if not challenge:
            return _error("登录会话已过期，请重新开始登录", 400)

        credential_json = data.get("credential", {})
        credential_id = base64url_to_bytes(credential_json.get("rawId", ""))
        credential = store.get_credential_by_id(credential_id)
        if not credential:
            return _error("没有找到对应的 Passkey", 404)

        user = None
        if user_id:
            user = store.get_user_by_id(int(user_id))
            if not user or credential.user_id != user.id:
                return _error("这个 Passkey 不属于当前用户名", 403)

        result = verify_authentication(
            credential=credential_json,
            expected_challenge=challenge,
            credential_public_key=credential.public_key,
            credential_current_sign_count=credential.sign_count,
            config=_config(app),
        )

        if result.user_handle:
            handle_user = store.get_user_by_handle(result.user_handle)
            if not handle_user:
                return _error("没有找到这个 Passkey 对应的用户", 404)
            if handle_user.id != credential.user_id:
                return _error("Passkey 的用户句柄和凭据归属不一致", 403)
            user = handle_user

        if not user:
            user = store.get_user_by_id(credential.user_id)
        if not user:
            return _error("没有找到这个 Passkey 对应的用户", 404)

        store.update_sign_count(result.credential_id, result.new_sign_count)
        session.pop("authentication_challenge", None)
        session.pop("authentication_user_id", None)
        session["signed_in_user_id"] = user.id
        return jsonify({"ok": True})

    @app.post("/api/logout")
    def logout():
        session.clear()
        return jsonify({"ok": True})

    @app.errorhandler(ValueError)
    def value_error(error: ValueError):
        return _error(str(error), 400)

    @app.errorhandler(WebAuthnException)
    def webauthn_error(error: WebAuthnException):
        return _error(f"Passkey 校验失败：{error}", 400)

    return app


def _config(app: Flask) -> WebAuthnConfig:
    origin = app.config["PASSKEY_ORIGIN"] or request.host_url.rstrip("/")
    return WebAuthnConfig(
        rp_id=app.config["PASSKEY_RP_ID"],
        rp_name=app.config["PASSKEY_RP_NAME"],
        origin=origin,
    )


def _configure_proxy_support(app: Flask) -> None:
    if not app.config["PASSKEY_TRUST_PROXY_HEADERS"]:
        return

    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=app.config["PASSKEY_PROXY_FIX_X_FOR"],
        x_proto=app.config["PASSKEY_PROXY_FIX_X_PROTO"],
        x_host=app.config["PASSKEY_PROXY_FIX_X_HOST"],
    )


def _start_server_timing(app: Flask) -> None:
    if app.config["PASSKEY_SERVER_TIMING_ENABLED"]:
        g.server_timing_started_at = time.perf_counter()


def _apply_server_timing_header(app: Flask, response) -> None:
    if not app.config["PASSKEY_SERVER_TIMING_ENABLED"]:
        return

    started_at = getattr(g, "server_timing_started_at", None)
    if started_at is None:
        return

    duration_ms = max((time.perf_counter() - started_at) * 1000, 0)
    app_timing = f"app;dur={duration_ms:.1f}"
    existing = response.headers.get("Server-Timing")
    response.headers["Server-Timing"] = (
        f"{existing}, {app_timing}" if existing else app_timing
    )


def _inject_browser_telemetry(app: Flask, response) -> None:
    if not _browser_telemetry_enabled(app) or response.is_streamed:
        return

    content_type = response.headers.get("Content-Type", "")
    if "text/html" not in content_type.lower():
        return

    body = response.get_data(as_text=True)
    if "</body>" not in body or "data-passkey-telemetry-status-url" in body:
        return

    script = (
        '<script defer src="/static/telemetry.js" '
        'data-passkey-telemetry-token-url="/api/telemetry/browser-token">'
        "</script>"
    )
    response.set_data(body.replace("</body>", f"{script}</body>", 1))


def _browser_telemetry_enabled(app: Flask) -> bool:
    return bool(
        str(app.config.get("PASSKEY_TELEMETRY_TOKEN_URL") or "").strip()
        and str(app.config.get("PASSKEY_TELEMETRY_API_KEY") or "").strip()
    )


def _create_telemetry_browser_token(app: Flask) -> tuple[dict, int]:
    token_url = str(app.config.get("PASSKEY_TELEMETRY_TOKEN_URL") or "").strip()
    api_key = str(app.config.get("PASSKEY_TELEMETRY_API_KEY") or "").strip()
    if not token_url or not api_key:
        return {"ok": False, "error": "telemetry_not_configured"}, 404

    data = request.get_json(silent=True) or {}
    payload = {
        "event": "passkey_auth.browser_visit",
        "source": "passkey-auth",
        "path": data.get("path", "") if isinstance(data, dict) else "",
        "referrer": data.get("referrer", "") if isinstance(data, dict) else "",
    }
    body = json.dumps(payload).encode("utf-8")
    telemetry_request = Request(
        token_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Api-Key": api_key,
        },
        method="POST",
    )
    timeout = float(app.config.get("PASSKEY_TELEMETRY_TIMEOUT_SECONDS") or 1.0)

    try:
        with urlopen(telemetry_request, timeout=timeout) as telemetry_response:
            response_data = json.loads(telemetry_response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        return {"ok": False, "error": "telemetry_unavailable"}, 503

    if not isinstance(response_data, dict):
        return {"ok": False, "error": "telemetry_invalid_response"}, 502

    status_url = str(
        response_data.get("status_url") or response_data.get("statusUrl") or ""
    ).strip()
    if not status_url:
        status_path = str(response_data.get("status_path") or "").strip()
        status_url = status_path
    if not status_url:
        return {"ok": False, "error": "telemetry_missing_status_url"}, 502

    return {"ok": True, "statusUrl": status_url}, 200


def _apply_security_headers(app: Flask, response) -> None:
    if not app.config["PASSKEY_SECURITY_HEADERS_ENABLED"]:
        return

    _set_header_if_missing(response, "X-Content-Type-Options", "nosniff")
    _set_header_if_missing(response, "Referrer-Policy", "no-referrer")
    _set_header_if_missing(
        response,
        "Permissions-Policy",
        "publickey-credentials-create=(self), publickey-credentials-get=(self)",
    )
    _set_header_if_missing(
        response,
        "Content-Security-Policy",
        (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self' https://115.29.205.236:15000; "
            "frame-src 'self' https://115.29.205.236:15000; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        ),
    )

    if _request_is_https(app):
        alt_svc = app.config["PASSKEY_HTTP3_ALT_SVC"]
        if alt_svc:
            _set_header_if_missing(response, "Alt-Svc", alt_svc)

        hsts = _hsts_header(app)
        if hsts:
            _set_header_if_missing(response, "Strict-Transport-Security", hsts)


def _request_is_https(app: Flask) -> bool:
    origin = app.config["PASSKEY_ORIGIN"] or ""
    return request.is_secure or origin.startswith("https://")


def _hsts_header(app: Flask) -> str:
    max_age = int(app.config["PASSKEY_HSTS_MAX_AGE_SECONDS"] or 0)
    if max_age <= 0:
        return ""

    parts = [f"max-age={max_age}"]
    if app.config["PASSKEY_HSTS_INCLUDE_SUBDOMAINS"]:
        parts.append("includeSubDomains")
    if app.config["PASSKEY_HSTS_PRELOAD"]:
        parts.append("preload")
    return "; ".join(parts)


def _set_header_if_missing(response, name: str, value: str) -> None:
    if name not in response.headers:
        response.headers[name] = value


def _current_user(store: PasskeyStore, session_data) -> User | None:
    user_id = session_data.get("signed_in_user_id")
    if user_id:
        user = store.get_user_by_id(_safe_int(user_id))
        if user:
            return user

    username = session_data.get("signed_in_username")
    if username:
        return store.get_user_by_username(str(username))

    return None


def _server_api_allowed(app: Flask) -> bool:
    token = app.config["PASSKEY_SERVER_API_TOKEN"]
    auth_header = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if not token or not auth_header.startswith(prefix):
        return False
    return secrets.compare_digest(auth_header[len(prefix) :], token)


def _default_oauth_client(app: Flask) -> dict:
    return {
        "client_id": app.config["PASSKEY_OAUTH_CLIENT_ID"],
        "client_secret": app.config["PASSKEY_OAUTH_CLIENT_SECRET"],
        "name": app.config["PASSKEY_OAUTH_CLIENT_NAME"],
        "redirect_uris": _default_oauth_redirect_uris(app),
    }


def _oauth_client(app: Flask, client_id: str) -> dict | None:
    client = _default_oauth_client(app)
    if client_id != client["client_id"]:
        return None

    return client


def _default_oauth_redirect_uris(app: Flask) -> set[str]:
    redirect_uris = {
        _external_url("/demo/oauth/callback"),
        _external_url("/demo/third-party/callback"),
        _external_url("/demo/link-login/callback"),
        "http://localhost:8765/api/auth/callback",
    }
    redirect_uris.update(
        _split_redirect_uris(str(app.config.get("PASSKEY_OAUTH_REDIRECT_URIS") or ""))
    )
    return redirect_uris


def _split_redirect_uris(value: str) -> set[str]:
    return {
        item.strip()
        for line in value.splitlines()
        for item in line.split(",")
        if item.strip()
    }


def _oauth_request_data() -> dict:
    if request.form:
        return request.form.to_dict()
    data = request.get_json(silent=True) or {}
    return data if isinstance(data, dict) else {}


def _oauth_client_credentials(data: dict) -> tuple[str, str]:
    auth_header = request.headers.get("Authorization", "")
    prefix = "Basic "
    if auth_header.startswith(prefix):
        try:
            decoded = b64decode(auth_header[len(prefix) :]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return "", ""
        client_id, separator, client_secret = decoded.partition(":")
        if separator:
            return client_id, client_secret

    return data.get("client_id", ""), data.get("client_secret", "")


def _fetch_oauth_userinfo(app: Flask, access_token: str) -> tuple[dict, int]:
    with app.test_client() as client:
        response = client.get(
            "/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
    payload = response.get_json(silent=True)
    if not isinstance(payload, dict):
        payload = {
            "ok": False,
            "error": f"userinfo 返回了非 JSON 响应：{response.status_code}",
        }
    return payload, response.status_code


def _exchange_authorization_code(
    *,
    app: Flask,
    store: PasskeyStore,
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
) -> tuple[dict, int]:
    client = _oauth_client(app, client_id)
    if not client or not secrets.compare_digest(
        client_secret or "",
        client["client_secret"],
    ):
        return {
            "ok": False,
            "error": "invalid_client",
            "error_description": "OAuth client 校验失败",
        }, 401

    if redirect_uri not in client["redirect_uris"]:
        return {
            "ok": False,
            "error": "invalid_grant",
            "error_description": "redirect_uri 不匹配",
        }, 400

    oauth_code = store.consume_oauth_authorization_code(
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
    )
    if not oauth_code:
        return {
            "ok": False,
            "error": "invalid_grant",
            "error_description": "authorization code 无效、已使用或已过期",
        }, 400

    user = store.get_user_by_id(oauth_code.user_id)
    if not user:
        return {
            "ok": False,
            "error": "invalid_grant",
            "error_description": "authorization code 对应的用户不存在",
        }, 400

    expires_in = app.config["PASSKEY_OAUTH_ACCESS_TOKEN_TTL_SECONDS"]
    return {
        "ok": True,
        "access_token": _issue_access_token(app, user),
        "token_type": "Bearer",
        "expires_in": expires_in,
        "authenticated": True,
        "user": _oauth_user_payload(user),
    }, 200


def _issue_access_token(app: Flask, user: User) -> str:
    serializer = URLSafeTimedSerializer(
        app.secret_key,
        salt="passkey-oauth-access-token",
    )
    return serializer.dumps(
        {
            "user_id": user.id,
            "sub": bytes_to_base64url(user.user_handle),
        }
    )


def _issue_challenge_result_token(
    app: Flask,
    challenge: OAuthChallengeRequest,
    user: User,
) -> str:
    serializer = URLSafeTimedSerializer(
        app.secret_key,
        salt="passkey-oauth-challenge-result",
    )
    return serializer.dumps(
        {
            "challenge_id": challenge.challenge_id,
            "client_id": challenge.client_id,
            "state": challenge.state,
            "user_id": user.id,
            "sub": bytes_to_base64url(user.user_handle),
        }
    )


def _consume_challenge_result_token(
    *,
    app: Flask,
    store: PasskeyStore,
    challenge_id: str,
    token: str,
) -> tuple[User | None, str, str]:
    if not challenge_id or not token:
        return (
            None,
            "missing_challenge_result",
            "callback 缺少 challenge 或 challenge_result",
        )

    serializer = URLSafeTimedSerializer(
        app.secret_key,
        salt="passkey-oauth-challenge-result",
    )
    try:
        data = serializer.loads(
            token,
            max_age=app.config["PASSKEY_OAUTH_CHALLENGE_TTL_SECONDS"],
        )
    except SignatureExpired:
        return None, "expired_challenge_result", "challenge_result 已过期"
    except BadSignature:
        return None, "invalid_challenge_result", "challenge_result 签名无效"

    if not isinstance(data, dict) or data.get("challenge_id") != challenge_id:
        return None, "invalid_challenge_result", "challenge_result 内容不匹配"

    user = store.get_user_by_id(_safe_int(data.get("user_id")))
    if not user or data.get("sub") != bytes_to_base64url(user.user_handle):
        return None, "invalid_challenge_result", "challenge_result 用户无效"

    challenge = store.get_oauth_challenge_request(challenge_id)
    if not challenge or challenge.user_id != user.id:
        return None, "invalid_challenge", "challenge 无效、已消费或已过期"
    if (
        data.get("client_id") != challenge.client_id
        or data.get("state") != challenge.state
    ):
        return None, "invalid_challenge_result", "challenge_result 绑定信息不匹配"

    consumed = store.consume_oauth_challenge_request(
        challenge_id=challenge_id,
        user_id=user.id,
    )
    if not consumed:
        return None, "invalid_challenge", "challenge 无效、已消费或已过期"

    return user, "", ""


def _user_from_access_token(app: Flask, store: PasskeyStore) -> User | None:
    auth_header = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if not auth_header.startswith(prefix):
        return None

    serializer = URLSafeTimedSerializer(
        app.secret_key,
        salt="passkey-oauth-access-token",
    )
    try:
        data = serializer.loads(
            auth_header[len(prefix) :],
            max_age=app.config["PASSKEY_OAUTH_ACCESS_TOKEN_TTL_SECONDS"],
        )
    except (BadSignature, SignatureExpired):
        return None

    if not isinstance(data, dict):
        return None
    user = store.get_user_by_id(_safe_int(data.get("user_id")))
    if not user or data.get("sub") != bytes_to_base64url(user.user_handle):
        return None
    return user


def _oauth_user_payload(user: User) -> dict:
    return {
        "sub": bytes_to_base64url(user.user_handle),
        "id": user.id,
        "username": user.username,
        "createdAt": user.created_at,
    }


def _oauth_redirect_error(
    redirect_uri: str,
    state: str,
    error: str,
    error_description: str,
):
    return redirect(
        _url_with_params(
            redirect_uri,
            {
                "error": error,
                "error_description": error_description,
                "state": state,
            },
        )
    )


def _external_url(path: str) -> str:
    return f"{request.host_url.rstrip('/')}{path}"


def _url_with_params(url: str, params: dict[str, str]) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update({key: value for key, value in params.items() if value})
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urlencode(query),
            parts.fragment,
        )
    )


def _session_data_for_server_verify(app: Flask):
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        data = {}
    session_cookie = (
        data.get("sessionCookie") or data.get("session_cookie") or ""
    ).strip()
    if not session_cookie:
        return session

    cookie_value = _extract_session_cookie_value(app, session_cookie)
    serializer = app.session_interface.get_signing_serializer(app)
    if not cookie_value or serializer is None:
        return None

    try:
        return serializer.loads(cookie_value)
    except BadSignature:
        return None


def _extract_session_cookie_value(app: Flask, raw_cookie: str) -> str:
    cookie_name = app.config["SESSION_COOKIE_NAME"]
    if "=" not in raw_cookie:
        return raw_cookie

    parsed = SimpleCookie()
    try:
        parsed.load(raw_cookie)
    except CookieError:
        return ""
    morsel = parsed.get(cookie_name)
    return morsel.value if morsel else ""


def _safe_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _render_error_page(status_code: int):
    safe_status_code = _safe_http_status(status_code)
    return render_template(
        "error.html",
        status_code=safe_status_code,
        status_label=_error_status_label(status_code, safe_status_code),
    ), safe_status_code


_KNOWN_EDGE_ERROR_STATUSES = {400, 401, 403, 404, 405, 408, 429, 500, 502, 503, 504}


def _safe_http_status(status_code: int) -> int:
    if 400 <= status_code <= 599:
        return status_code
    return 404


def _error_status_label(status_code: int, safe_status_code: int) -> str:
    if status_code not in _KNOWN_EDGE_ERROR_STATUSES:
        return f"{safe_status_code} · Unknown Ungix Error"

    phrase = HTTPStatus(safe_status_code).phrase
    return f"{status_code} · {phrase}"


def _registration_enabled(app: Flask) -> bool:
    return bool(app.config["PASSKEY_REGISTRATION_ENABLED"])


def _registration_unlocked() -> bool:
    unlocked = bool(session.get("registration_unlocked"))
    expires_at = int(session.get("registration_unlock_expires_at") or 0)
    if not unlocked or expires_at < int(time.time()):
        _clear_registration_unlock()
        return False
    return True


def _clear_registration_unlock() -> None:
    session.pop("registration_unlocked", None)
    session.pop("registration_unlock_expires_at", None)


def _clear_registration_state() -> None:
    session.pop("registration_challenge", None)
    session.pop("registration_user_id", None)
    _clear_registration_unlock()


def _error(message: str, status: int):
    return jsonify({"ok": False, "error": message}), status


def _no_store(response):
    target = response[0] if isinstance(response, tuple) else response
    target.headers["Cache-Control"] = "no-store"
    return response


app = create_app()


if __name__ == "__main__":
    server_config = ServerConfig.from_env()
    app.run(
        host=server_config.host,
        port=server_config.port,
        debug=server_config.debug,
    )
