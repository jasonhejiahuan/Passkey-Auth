from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from webauthn.helpers import bytes_to_base64url

from jstu_passkey.app import create_app
from jstu_passkey.storage import PasskeyStore


class ManagementTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.tempdir.name, "management.sqlite3")
        self.previous_env = {
            key: os.environ.get(key)
            for key in (
                "PASSKEY_DATABASE",
                "FLASK_SECRET_KEY",
                "PASSKEY_HOME_AUTH_ENABLED",
                "PASSKEY_TELEMETRY_DATABASE",
            )
        }
        os.environ["PASSKEY_DATABASE"] = self.database_path
        os.environ["FLASK_SECRET_KEY"] = "management-test-secret"
        os.environ["PASSKEY_HOME_AUTH_ENABLED"] = "true"
        os.environ["PASSKEY_TELEMETRY_DATABASE"] = os.path.join(
            self.tempdir.name,
            "telemetry.sqlite3",
        )
        self.app = create_app()
        self.app.testing = True
        self.client = self.app.test_client()
        self.store = PasskeyStore(self.database_path)
        self.admin = self.store.create_user("af00", b"a" * 32)
        self.store.set_permissions(
            self.admin.id,
            {"admin": True, "login": True, "demo": True},
        )
        self.admin = self.store.get_user_by_id(self.admin.id)
        self.action_token = "current-action-token"
        self.action_token_session_id = "management-session"
        self.store.issue_action_token(
            session_id=self.action_token_session_id,
            user_id=self.admin.id,
            token=self.action_token,
        )
        with self.client.session_transaction() as session:
            session["signed_in_user_id"] = self.admin.id
            session["signed_in_session_version"] = self.admin.session_version
            session["management_reauthenticated_at"] = int(time.time())
            session["management_csrf_token"] = "csrf-token"
            session["action_token_session_id"] = self.action_token_session_id

    def tearDown(self) -> None:
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def write_headers(self, action_token: str | None = None) -> dict[str, str]:
        return {
            "X-CSRF-Token": "csrf-token",
            "X-Action-Token": self.action_token
            if action_token is None
            else action_token,
        }

    def channel_keypair(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        numbers = private_key.public_key().public_numbers()
        public_jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": bytes_to_base64url(numbers.x.to_bytes(32, "big")),
            "y": bytes_to_base64url(numbers.y.to_bytes(32, "big")),
        }
        return private_key, public_jwk

    def start_channel(self):
        private_key, public_jwk = self.channel_keypair()
        response = self.client.post(
            "/api/management/channel/start",
            json={"publicKeyJwk": public_jwk},
            headers={"X-CSRF-Token": "csrf-token"},
        )
        self.assertEqual(response.status_code, 200)
        return private_key, response.get_json()

    def sign_channel(
        self,
        private_key,
        *,
        purpose: str,
        channel_id: str,
        counter: int,
        server_nonce: str,
        client_nonce: str = "client-nonce",
        method: str = "POST",
        path: str = "/api/management/channel/ack",
        visibility: str = "visible",
        effective_type: str = "4g",
        save_data: bool = False,
        rtt_ms: int | None = None,
    ) -> str:
        message = "\n".join(
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
                "" if rtt_ms is None else str(rtt_ms),
            ]
        )
        return bytes_to_base64url(
            private_key.sign(message.encode("utf-8"), ec.ECDSA(SHA256()))
        )

    def channel_headers(
        self,
        private_key,
        payload: dict,
        *,
        counter: int = 1,
        method: str = "PATCH",
        path: str = "/api/management/settings/registration",
    ) -> dict[str, str]:
        client_nonce = f"write-nonce-{counter}"
        return {
            "X-Management-Channel-Id": payload["channel_id"],
            "X-Management-Channel-Counter": str(counter),
            "X-Management-Channel-Client-Nonce": client_nonce,
            "X-Management-Channel-Signature": self.sign_channel(
                private_key,
                purpose="write",
                channel_id=payload["channel_id"],
                counter=counter,
                server_nonce=payload["server_nonce"],
                client_nonce=client_nonce,
                method=method,
                path=path,
            ),
            "X-Management-Channel-Visibility": "visible",
            "X-Management-Channel-Effective-Type": "4g",
            "X-Management-Channel-Save-Data": "0",
        }

    def test_management_requires_admin(self) -> None:
        client = self.app.test_client()
        response = client.get("/management")
        self.assertEqual(response.status_code, 401)
        self.assertIn(b"jason-logo-black.png", response.data)
        self.assertIn(b"id=\"logo-button\"", response.data)
        self.assertIn(b"/static/main.js", response.data)
        self.assertIn("请先完成 Passkey 登录", response.get_data(as_text=True))
        self.assertNotIn(b"application/json", response.headers["Content-Type"].encode())

        api_response = client.get("/api/management/overview")
        self.assertEqual(api_response.status_code, 401)
        self.assertEqual(
            api_response.get_json(),
            {"ok": False, "error": "请先完成 Passkey 登录"},
        )

    def test_management_error_page_respects_disabled_home_auth(self) -> None:
        os.environ["PASSKEY_HOME_AUTH_ENABLED"] = "false"
        app = create_app()
        client = app.test_client()

        response = client.get("/management")

        self.assertEqual(response.status_code, 401)
        self.assertNotIn(b"/static/main.js", response.data)
        self.assertNotIn(b"id=\"logo-button\"", response.data)

    def test_management_non_admin_error_stays_persistent(self) -> None:
        user = self.store.create_user("member", b"m" * 32)
        self.store.set_permissions(
            user.id,
            {"admin": False, "login": True, "demo": False},
        )
        user = self.store.get_user_by_id(user.id)
        client = self.app.test_client()
        with client.session_transaction() as session:
            session["signed_in_user_id"] = user.id
            session["signed_in_session_version"] = user.session_version

        response = client.get("/management")

        self.assertEqual(response.status_code, 403)
        self.assertIn("没有管理权限", response.get_data(as_text=True))
        self.assertIn(b'data-persistent="true"', response.data)
        self.assertIn(b"/static/main.js", response.data)

    def test_management_settings_use_auto_save_controls(self) -> None:
        response = self.client.get("/management")

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn('id="logout-button"', body)
        self.assertIn("退出登录", body)
        self.assertIn('class="toggle-row"', body)
        self.assertIn('class="toggle-control"', body)
        self.assertIn('id="telemetry-backend-settings"', body)
        self.assertIn('id="pair-jason-telemetry"', body)
        self.assertIn("更改后自动保存", body)
        self.assertIn('data-view="telemetry"', body)
        self.assertIn('id="telemetry-settings"', body)
        self.assertIn("关闭后不读取遥测库", body)
        self.assertIn("按用户策略", body)
        self.assertNotIn("保存高级设置", body)
        self.assertNotIn(">保存设置</button>", body)

    def test_management_logout_returns_to_signed_out_home(self) -> None:
        logout_response = self.client.post("/api/logout")

        self.assertEqual(logout_response.status_code, 200)
        self.assertEqual(logout_response.get_json(), {"ok": True})
        management_response = self.client.get("/management")
        self.assertEqual(management_response.status_code, 401)

    def test_management_script_preserves_active_view_in_url_hash(self) -> None:
        response = self.client.get("/static/management.js")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('requestJson("/api/logout", { method: "POST" })', body)
        self.assertIn('window.location.replace("/")', body)
        self.assertIn('class="toggle-row"', body)
        self.assertIn('class="toggle-control"', body)
        self.assertIn('window.addEventListener("hashchange", showViewFromHash)', body)
        self.assertIn("window.location.hash.slice(1)", body)
        self.assertIn("window.history.pushState", body)
        self.assertIn("window.history.replaceState", body)
        self.assertIn('data-user-agent="${index}"', body)
        self.assertIn('openDetail("User-Agent"', body)
        self.assertIn('data-audit-detail="${index}"', body)
        self.assertIn('openDetail("审计详情"', body)
        self.assertIn("loadTelemetry", body)
        self.assertIn("data-telemetry-user-mode", body)
        self.assertIn("10000", body)
        self.assertIn("startManagementChannel", body)
        self.assertIn("EventSource", body)
        self.assertIn("X-Management-Channel-Signature", body)

    def test_telemetry_configuration_does_not_stick_over_user_policies(self) -> None:
        css = self.client.get("/static/management.css").get_data(as_text=True)
        stack_rule = css.split(".telemetry-config-stack {", 1)[1].split("}", 1)[0]

        self.assertNotIn("position: sticky", stack_rule)
        self.assertIn(".telemetry-user-policies {\n  grid-column: 1 / -1;\n  grid-row: 2;", css)

    def test_management_reauthentication_refreshes_recent_auth_without_logout(self) -> None:
        credential_id = b"credential-id"
        self.store.save_credential(
            user_id=self.admin.id,
            credential_id=credential_id,
            public_key=b"public-key",
            sign_count=0,
            transports=["internal"],
            aaguid=None,
            credential_type="public-key",
            device_type="single_device",
            backed_up=False,
        )
        with self.client.session_transaction() as session:
            session["management_reauthenticated_at"] = 0

        self.client.get("/auth/passkey?mode=reauth&return_to=/management")
        with self.client.session_transaction() as session:
            auth_flow_token = session["auth_flow_token"]
        options_response = self.client.post(
            "/auth/passkey/options",
            json={"mode": "reauth", "authFlowToken": auth_flow_token},
        )

        self.assertEqual(options_response.status_code, 200)
        public_key = options_response.get_json()["publicKey"]
        self.assertEqual(public_key["userVerification"], "required")
        self.assertEqual(len(public_key["allowCredentials"]), 1)

        with patch(
            "jstu_passkey.app.verify_authentication",
            return_value=SimpleNamespace(
                credential_id=credential_id,
                new_sign_count=1,
                user_handle=None,
            ),
        ):
            verify_response = self.client.post(
                "/auth/passkey/verify",
                json={
                    "credential": {
                        "rawId": bytes_to_base64url(credential_id),
                    },
                    "authFlowToken": auth_flow_token,
                },
            )

        self.assertEqual(verify_response.status_code, 200)
        refreshed_action_token = verify_response.get_json()["action_token"]
        self.assertNotEqual(refreshed_action_token, self.action_token)
        with self.client.session_transaction() as session:
            self.assertEqual(session["signed_in_user_id"], self.admin.id)
            self.assertEqual(
                session["action_token_session_id"],
                self.action_token_session_id,
            )
            self.assertGreaterEqual(
                session["management_reauthenticated_at"],
                int(time.time()) - 2,
            )
        with self.store.connect() as conn:
            stored_value = conn.execute(
                "SELECT setting_value FROM app_settings WHERE setting_key = ?",
                (f"session_action_token:{self.action_token_session_id}",),
            ).fetchone()[0]
        self.assertNotIn(refreshed_action_token, stored_value)

    def test_passkey_login_creates_hashed_action_token(self) -> None:
        credential_id = b"login-credential"
        self.store.save_credential(
            user_id=self.admin.id,
            credential_id=credential_id,
            public_key=b"public-key",
            sign_count=0,
            transports=["internal"],
            aaguid=None,
            credential_type="public-key",
            device_type="single_device",
            backed_up=False,
        )
        client = self.app.test_client()
        client.get("/auth/passkey")
        with client.session_transaction() as session:
            auth_flow_token = session["auth_flow_token"]
        options_response = client.post(
            "/auth/passkey/options",
            json={
                "username": self.admin.username,
                "mode": "login",
                "authFlowToken": auth_flow_token,
            },
        )
        self.assertEqual(options_response.status_code, 200)

        with patch(
            "jstu_passkey.app.verify_authentication",
            return_value=SimpleNamespace(
                credential_id=credential_id,
                new_sign_count=1,
                user_handle=None,
            ),
        ):
            verify_response = client.post(
                "/auth/passkey/verify",
                json={
                    "credential": {
                        "rawId": bytes_to_base64url(credential_id),
                    },
                    "authFlowToken": auth_flow_token,
                },
            )

        self.assertEqual(verify_response.status_code, 200)
        action_token = verify_response.get_json()["action_token"]
        with client.session_transaction() as session:
            action_token_session_id = session["action_token_session_id"]
        with self.store.connect() as conn:
            stored_value = conn.execute(
                "SELECT setting_value FROM app_settings WHERE setting_key = ?",
                (f"session_action_token:{action_token_session_id}",),
            ).fetchone()[0]
        self.assertNotIn(action_token, stored_value)

    def test_management_reauthentication_rejects_another_users_passkey(self) -> None:
        other = self.store.create_user("other", b"o" * 32)
        credential_id = b"other-credential"
        self.store.save_credential(
            user_id=other.id,
            credential_id=credential_id,
            public_key=b"public-key",
            sign_count=0,
            transports=[],
            aaguid=None,
            credential_type="public-key",
            device_type="single_device",
            backed_up=False,
        )
        with self.client.session_transaction() as session:
            session["authentication_challenge"] = "challenge"
            session["authentication_user_id"] = self.admin.id
            session["authentication_mode"] = "reauth"
            session["auth_flow_token"] = "auth-flow-token"

        response = self.client.post(
            "/auth/passkey/verify",
            json={
                "credential": {"rawId": bytes_to_base64url(credential_id)},
                "authFlowToken": "auth-flow-token",
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn("当前用户名", response.get_json()["error"])

    def test_admin_cannot_remove_own_access(self) -> None:
        response = self.client.patch(
            f"/api/management/users/{self.admin.id}",
            json={"permissions": {"admin": False, "login": True, "demo": True}},
            headers=self.write_headers(),
        )
        self.assertEqual(response.status_code, 409)

    def test_sensitive_write_rotates_token_and_rejects_replay(self) -> None:
        response = self.client.patch(
            "/api/management/settings/registration",
            json={
                "mode": "open",
                "enabledUntil": None,
                "defaultDemoAllowed": True,
            },
            headers=self.write_headers(),
        )

        self.assertEqual(response.status_code, 200)
        next_action_token = response.get_json()["next_action_token"]
        self.assertNotEqual(next_action_token, self.action_token)
        self.assertEqual(self.store.get_registration_settings().mode, "open")

        replay_response = self.client.patch(
            "/api/management/settings/registration",
            json={
                "mode": "closed",
                "enabledUntil": None,
                "defaultDemoAllowed": True,
            },
            headers=self.write_headers(),
        )

        self.assertEqual(replay_response.status_code, 409)
        self.assertEqual(
            replay_response.get_json()["reason"],
            "action_token_mismatch",
        )
        self.assertTrue(replay_response.get_json()["reauth_required"])
        self.assertEqual(self.store.get_registration_settings().mode, "open")

    def test_sensitive_write_without_action_token_requires_reauth(self) -> None:
        response = self.client.patch(
            "/api/management/settings/registration",
            json={
                "mode": "open",
                "enabledUntil": None,
                "defaultDemoAllowed": True,
            },
            headers={"X-CSRF-Token": "csrf-token"},
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["reason"], "action_token_missing")
        self.assertTrue(response.get_json()["reauth_required"])
        self.assertEqual(self.store.get_registration_settings().mode, "closed")

    def test_read_only_management_endpoint_does_not_require_action_token(self) -> None:
        response = self.client.get("/api/management/overview")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["ok"])
        self.assertNotIn("next_action_token", response.get_json())

    def test_management_channel_start_requires_csrf(self) -> None:
        _private_key, public_jwk = self.channel_keypair()

        response = self.client.post(
            "/api/management/channel/start",
            json={"publicKeyJwk": public_jwk},
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "CSRF 校验失败")

    def test_management_channel_ack_rejects_replay(self) -> None:
        private_key, payload = self.start_channel()
        signature = self.sign_channel(
            private_key,
            purpose="ack",
            channel_id=payload["channel_id"],
            counter=1,
            server_nonce=payload["server_nonce"],
            rtt_ms=120,
        )
        body = {
            "channelId": payload["channel_id"],
            "counter": 1,
            "serverNonce": payload["server_nonce"],
            "clientNonce": "client-nonce",
            "visibility": "visible",
            "effectiveType": "4g",
            "saveData": False,
            "rttMs": 120,
            "signature": signature,
        }

        response = self.client.post(
            "/api/management/channel/ack",
            json=body,
            headers={"X-CSRF-Token": "csrf-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["ack_after_ms"], 45000)

        replay = self.client.post(
            "/api/management/channel/ack",
            json=body,
            headers={"X-CSRF-Token": "csrf-token"},
        )
        self.assertEqual(replay.status_code, 409)
        self.assertEqual(replay.get_json()["reason"], "channel_replay")

    def test_management_channel_sse_emits_challenge(self) -> None:
        _private_key, payload = self.start_channel()

        response = self.client.get(
            f"/api/management/channel/events?channel_id={payload['channel_id']}",
            buffered=False,
        )
        try:
            chunk = next(response.response).decode("utf-8")
        finally:
            response.close()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/event-stream")
        self.assertIn("event: challenge", chunk)
        self.assertIn('"server_nonce"', chunk)

    def test_channel_started_write_requires_signed_channel_proof(self) -> None:
        private_key, payload = self.start_channel()

        missing_proof = self.client.patch(
            "/api/management/settings/registration",
            json={
                "mode": "open",
                "enabledUntil": None,
                "defaultDemoAllowed": True,
            },
            headers=self.write_headers(),
        )
        self.assertEqual(missing_proof.status_code, 409)
        self.assertEqual(missing_proof.get_json()["reason"], "channel_proof_missing")

        headers = {
            **self.write_headers(),
            **self.channel_headers(private_key, payload),
        }
        response = self.client.patch(
            "/api/management/settings/registration",
            json={
                "mode": "open",
                "enabledUntil": None,
                "defaultDemoAllowed": True,
            },
            headers=headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["next_action_token"])
        self.assertEqual(self.store.get_registration_settings().mode, "open")

    def test_other_admin_can_be_removed_when_an_admin_remains(self) -> None:
        other = self.store.create_user("operator", b"b" * 32)
        self.store.set_permissions(
            other.id,
            {"admin": True, "login": True, "demo": True},
        )
        response = self.client.delete(
            f"/api/management/users/{other.id}",
            headers=self.write_headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.store.get_user_by_id(other.id))

    def test_users_csv_has_bom_and_no_public_key(self) -> None:
        response = self.client.get("/api/management/export/users.csv")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data.startswith(b"\xef\xbb\xbf"))
        body = response.get_data(as_text=True)
        self.assertIn("username", body)
        self.assertNotIn("public_key", body)

    def test_registration_settings_are_persistent(self) -> None:
        enabled_until = int(time.time()) + 600
        response = self.client.patch(
            "/api/management/settings/registration",
            json={
                "mode": "temporary",
                "enabledUntil": enabled_until,
                "defaultDemoAllowed": False,
            },
            headers=self.write_headers(),
        )
        self.assertEqual(response.status_code, 200)
        settings = self.store.get_registration_settings()
        self.assertEqual(settings.mode, "temporary")
        self.assertEqual(settings.enabled_until, enabled_until)
        self.assertFalse(settings.default_demo_allowed)

    def test_passkey_settings_are_persistent_and_exposed(self) -> None:
        response = self.client.patch(
            "/api/management/settings/passkey",
            json={
                "algorithms": [-7, -8],
                "authenticatorAttachment": "platform",
                "residentKey": "preferred",
                "userVerification": "required",
                "attestation": "direct",
                "excludeCredentials": False,
                "hints": ["client-device"],
            },
            headers=self.write_headers(),
        )

        self.assertEqual(response.status_code, 200)
        settings = self.store.get_passkey_settings()
        self.assertEqual(settings.algorithms, [-7, -8])
        self.assertEqual(settings.authenticator_attachment, "platform")
        self.assertEqual(settings.resident_key, "preferred")
        self.assertEqual(settings.user_verification, "required")
        self.assertEqual(settings.attestation, "direct")
        self.assertFalse(settings.exclude_credentials)
        self.assertEqual(settings.hints, ["client-device"])

        overview = self.client.get("/api/management/overview").get_json()
        self.assertEqual(overview["passkeySettings"]["algorithms"], [-7, -8])
        self.assertEqual(
            overview["passkeySettings"]["authenticatorAttachment"],
            "platform",
        )

    def test_passkey_settings_reject_empty_algorithms(self) -> None:
        response = self.client.patch(
            "/api/management/settings/passkey",
            json={
                "algorithms": [],
                "authenticatorAttachment": "any",
                "residentKey": "required",
                "userVerification": "preferred",
                "attestation": "none",
                "excludeCredentials": True,
                "hints": [],
            },
            headers=self.write_headers(),
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("至少选择一种", response.get_json()["error"])

    def test_telemetry_settings_are_persistent_and_exposed_lazily(self) -> None:
        response = self.client.patch(
            "/api/management/settings/telemetry",
            json={
                "enabled": True,
                "anonymousEnabled": False,
                "defaultFeatures": ["screen", "hardware", "preferences"],
                "retentionDays": 90,
            },
            headers=self.write_headers(),
        )

        self.assertEqual(response.status_code, 200)
        settings = self.store.get_telemetry_settings()
        self.assertTrue(settings.enabled)
        self.assertFalse(settings.anonymous_enabled)
        self.assertEqual(settings.retention_days, 90)

        overview = self.client.get("/api/management/overview").get_json()
        self.assertNotIn("telemetry", overview)
        telemetry = self.client.get("/api/management/telemetry").get_json()
        self.assertTrue(telemetry["settings"]["enabled"])
        self.assertEqual(
            telemetry["settings"]["defaultFeatures"],
            ["screen", "hardware", "preferences"],
        )
        self.assertEqual(telemetry["statistics"]["summary"]["total"], 0)

    def test_per_user_telemetry_policy_is_persistent(self) -> None:
        member = self.store.create_user("telemetry-member", b"t" * 32)

        response = self.client.patch(
            f"/api/management/users/{member.id}/telemetry",
            json={"mode": "custom", "features": ["screen", "fonts"]},
            headers=self.write_headers(),
        )

        self.assertEqual(response.status_code, 200)
        policy = self.store.list_user_telemetry_policies()[member.id]
        self.assertEqual(policy.mode, "custom")
        self.assertEqual(policy.features, ["screen", "fonts"])
        telemetry = self.client.get("/api/management/telemetry").get_json()
        self.assertEqual(
            telemetry["userPolicies"][str(member.id)],
            {"mode": "custom", "features": ["screen", "fonts"]},
        )

    def test_external_telemetry_secret_is_persistent_but_never_returned(self) -> None:
        response = self.client.patch(
            "/api/management/settings/telemetry",
            json={
                "enabled": True,
                "anonymousEnabled": False,
                "defaultFeatures": ["screen"],
                "retentionDays": 30,
                "backend": "jason",
                "deliveryMode": "relay",
                "jasonBaseUrl": "https://telemetry.example.com",
                "jasonApiKey": "abcd-1234-ef56-7890",
                "timeoutSeconds": 1,
            },
            headers=self.write_headers(),
        )

        self.assertEqual(response.status_code, 200)
        stored = self.store.get_telemetry_settings()
        self.assertEqual(stored.backend, "jason")
        self.assertEqual(stored.jason_api_key, "abcd-1234-ef56-7890")
        payload = self.client.get("/api/management/telemetry").get_json()
        self.assertTrue(payload["settings"]["jason"]["apiKeyConfigured"])
        self.assertNotIn("apiKey", payload["settings"]["jason"])
        self.assertNotIn(
            "abcd-1234-ef56-7890",
            json.dumps(payload),
        )

    def test_jason_pairing_route_never_returns_negotiated_secret(self) -> None:
        runtime = self.app.extensions["telemetry_runtime"]
        with patch.object(
            runtime,
            "pair_jason",
            return_value={
                "ok": True,
                "backend": "jason",
                "apiKeyConfigured": True,
                "serverVersion": "13.0.0",
            },
        ):
            response = self.client.post(
                "/api/management/telemetry/backend/pair-jason",
                json={
                    "baseUrl": "https://telemetry.example.com",
                    "pairingCode": "one-time-pairing-code",
                    "timeoutSeconds": 1,
                },
                headers=self.write_headers(),
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["apiKeyConfigured"])
        self.assertNotIn("apiKey", response.get_json())

    def test_new_platform_secret_is_only_returned_and_hashed_in_storage(self) -> None:
        response = self.client.post(
            "/api/management/platforms",
            json={
                "clientId": "analysis-agent",
                "name": "Analysis Agent",
                "redirectUris": "https://agent.example/callback",
            },
            headers=self.write_headers(),
        )
        self.assertEqual(response.status_code, 200)
        secret = response.get_json()["clientSecret"]
        with self.store.connect() as conn:
            secret_hash = conn.execute(
                "SELECT secret_hash FROM oauth_clients WHERE client_id = ?",
                ("analysis-agent",),
            ).fetchone()[0]
        self.assertNotEqual(secret_hash, secret)
        self.assertNotIn(secret, secret_hash)
        self.assertTrue(
            self.store.verify_oauth_client_secret("analysis-agent", secret)
        )

    def test_log_cleanup_leaves_maintenance_event(self) -> None:
        self.store.record_login(
            user=self.admin,
            client_id=None,
            flow="passkey",
            result="success",
            credential_hint=None,
            ip_address="127.0.0.1",
            user_agent="test",
            sub="sub",
        )
        response = self.client.post(
            "/api/management/logs/login/clear",
            json={},
            headers=self.write_headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["deleted"], 1)
        with self.store.connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM maintenance_events"
            ).fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
