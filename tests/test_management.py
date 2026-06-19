from __future__ import annotations

import os
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from passkey_demo.app import create_app
from passkey_demo.storage import PasskeyStore
from webauthn.helpers import bytes_to_base64url


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
            )
        }
        os.environ["PASSKEY_DATABASE"] = self.database_path
        os.environ["FLASK_SECRET_KEY"] = "management-test-secret"
        os.environ["PASSKEY_HOME_AUTH_ENABLED"] = "true"
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
        with self.client.session_transaction() as session:
            session["signed_in_user_id"] = self.admin.id
            session["signed_in_session_version"] = self.admin.session_version
            session["management_reauthenticated_at"] = int(time.time())
            session["management_csrf_token"] = "csrf-token"

    def tearDown(self) -> None:
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

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
        self.assertIn("更改后自动保存", body)
        self.assertNotIn("保存高级设置", body)
        self.assertNotIn(">保存设置</button>", body)

    def test_management_script_preserves_active_view_in_url_hash(self) -> None:
        response = self.client.get("/static/management.js")
        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('window.addEventListener("hashchange", showViewFromHash)', body)
        self.assertIn("window.location.hash.slice(1)", body)
        self.assertIn("window.history.pushState", body)
        self.assertIn("window.history.replaceState", body)

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

        options_response = self.client.post(
            "/api/management/reauth/options",
            headers={"X-CSRF-Token": "csrf-token"},
        )

        self.assertEqual(options_response.status_code, 200)
        public_key = options_response.get_json()["publicKey"]
        self.assertEqual(public_key["userVerification"], "required")
        self.assertEqual(len(public_key["allowCredentials"]), 1)

        with patch(
            "passkey_demo.management.verify_authentication",
            return_value=SimpleNamespace(
                credential_id=credential_id,
                new_sign_count=1,
            ),
        ):
            verify_response = self.client.post(
                "/api/management/reauth/verify",
                json={
                    "credential": {
                        "rawId": bytes_to_base64url(credential_id),
                    }
                },
                headers={"X-CSRF-Token": "csrf-token"},
            )

        self.assertEqual(verify_response.status_code, 200)
        with self.client.session_transaction() as session:
            self.assertEqual(session["signed_in_user_id"], self.admin.id)
            self.assertGreaterEqual(
                session["management_reauthenticated_at"],
                int(time.time()) - 2,
            )

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
            session["management_reauth_challenge"] = "challenge"

        response = self.client.post(
            "/api/management/reauth/verify",
            json={"credential": {"rawId": bytes_to_base64url(credential_id)}},
            headers={"X-CSRF-Token": "csrf-token"},
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn("当前管理员账户", response.get_json()["error"])

    def test_admin_cannot_remove_own_access(self) -> None:
        response = self.client.patch(
            f"/api/management/users/{self.admin.id}",
            json={"permissions": {"admin": False, "login": True, "demo": True}},
            headers={"X-CSRF-Token": "csrf-token"},
        )
        self.assertEqual(response.status_code, 409)

    def test_other_admin_can_be_removed_when_an_admin_remains(self) -> None:
        other = self.store.create_user("operator", b"b" * 32)
        self.store.set_permissions(
            other.id,
            {"admin": True, "login": True, "demo": True},
        )
        response = self.client.delete(
            f"/api/management/users/{other.id}",
            headers={"X-CSRF-Token": "csrf-token"},
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
            headers={"X-CSRF-Token": "csrf-token"},
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
            headers={"X-CSRF-Token": "csrf-token"},
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
            headers={"X-CSRF-Token": "csrf-token"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("至少选择一种", response.get_json()["error"])

    def test_new_platform_secret_is_only_returned_and_hashed_in_storage(self) -> None:
        response = self.client.post(
            "/api/management/platforms",
            json={
                "clientId": "analysis-agent",
                "name": "Analysis Agent",
                "redirectUris": "https://agent.example/callback",
            },
            headers={"X-CSRF-Token": "csrf-token"},
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
            headers={"X-CSRF-Token": "csrf-token"},
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
