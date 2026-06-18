from __future__ import annotations

import os
import tempfile
import time
import unittest

from passkey_demo.app import create_app
from passkey_demo.storage import PasskeyStore


class ManagementTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.tempdir.name, "management.sqlite3")
        self.previous_env = {
            key: os.environ.get(key)
            for key in ("PASSKEY_DATABASE", "FLASK_SECRET_KEY")
        }
        os.environ["PASSKEY_DATABASE"] = self.database_path
        os.environ["FLASK_SECRET_KEY"] = "management-test-secret"
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
