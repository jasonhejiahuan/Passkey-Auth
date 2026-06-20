from __future__ import annotations

import os
import tempfile
import unittest

from jstu_passkey.app import create_app


class RegistrationGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.previous_env = {
            key: os.environ.get(key)
            for key in (
                "PASSKEY_DATABASE",
                "FLASK_SECRET_KEY",
                "PASSKEY_REGISTRATION_ENABLED",
            )
        }
        os.environ["PASSKEY_DATABASE"] = os.path.join(
            self.tempdir.name,
            "passkeys.sqlite3",
        )
        os.environ["FLASK_SECRET_KEY"] = "test-secret"
        os.environ.pop("PASSKEY_REGISTRATION_ENABLED", None)

    def tearDown(self) -> None:
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def test_registration_is_disabled_by_default(self) -> None:
        app = create_app()
        app.testing = True
        client = app.test_client()

        response = client.post("/api/ui/intent", json={"intent": "register"})

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "注册功能未启用")

    def test_registration_options_are_blocked_when_disabled(self) -> None:
        app = create_app()
        app.testing = True
        client = app.test_client()
        with client.session_transaction() as session:
            session["registration_unlocked"] = True
            session["registration_unlock_expires_at"] = 9999999999

        response = client.post("/api/register/options", json={"username": "jason"})

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"], "注册功能未启用")

    def test_registration_unlock_can_be_enabled_by_env(self) -> None:
        os.environ["PASSKEY_REGISTRATION_ENABLED"] = "true"
        app = create_app()
        app.testing = True
        client = app.test_client()

        response = client.post("/api/ui/intent", json={"intent": "register"})

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["register"]["clientPath"], "/api/ui/register-client.js")

    def test_duplicate_username_is_rejected_before_options_are_created(self) -> None:
        os.environ["PASSKEY_REGISTRATION_ENABLED"] = "true"
        app = create_app()
        app.testing = True
        client = app.test_client()
        store = app.extensions["passkey_store"]
        store.create_user("jason", b"j" * 32)
        with client.session_transaction() as session:
            session["registration_unlocked"] = True
            session["registration_unlock_expires_at"] = 9999999999

        response = client.post(
            "/api/register/options",
            json={"username": "jason"},
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["error"], "用户名已注册")


if __name__ == "__main__":
    unittest.main()
