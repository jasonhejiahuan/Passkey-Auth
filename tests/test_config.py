from __future__ import annotations

import os
import tempfile
import unittest

from passkey_demo.config import AppConfig, ServerConfig


class ConfigTest(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = (
            "FLASK_SECRET_KEY",
            "PASSKEY_RP_ID",
            "PASSKEY_RP_NAME",
            "PASSKEY_ORIGIN",
            "REGISTER_UNLOCK_TTL_SECONDS",
            "PASSKEY_REGISTRATION_ENABLED",
            "PASSKEY_SERVER_API_TOKEN",
            "PASSKEY_OAUTH_DEMO_CLIENT_ID",
            "PASSKEY_OAUTH_DEMO_CLIENT_SECRET",
            "PASSKEY_OAUTH_DEMO_REDIRECT_URI",
            "PASSKEY_OAUTH_CODE_TTL_SECONDS",
            "PASSKEY_OAUTH_ACCESS_TOKEN_TTL_SECONDS",
            "PASSKEY_OAUTH_CHALLENGE_TTL_SECONDS",
            "PASSKEY_DATABASE",
            "FLASK_DEBUG",
            "HOST",
            "PORT",
        )
        self.previous_env = {key: os.environ.get(key) for key in self.keys}
        for key in self.keys:
            os.environ.pop(key, None)
        self.tempdir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def test_app_config_defaults(self) -> None:
        config = AppConfig.from_env(instance_path=self.tempdir.name)

        self.assertEqual(config.passkey_rp_id, "localhost")
        self.assertEqual(config.passkey_rp_name, "Passkey Demo")
        self.assertIsNone(config.passkey_origin)
        self.assertEqual(config.register_unlock_ttl_seconds, 120)
        self.assertFalse(config.passkey_registration_enabled)
        self.assertEqual(config.passkey_oauth_demo_client_id, "passkey-demo-client")
        self.assertEqual(config.passkey_oauth_code_ttl_seconds, 300)
        self.assertEqual(config.passkey_oauth_access_token_ttl_seconds, 3600)
        self.assertEqual(config.passkey_oauth_challenge_ttl_seconds, 300)
        self.assertTrue(config.passkey_database.endswith("passkeys.sqlite3"))
        self.assertGreaterEqual(len(config.flask_secret_key), 32)

    def test_app_config_env_overrides(self) -> None:
        os.environ["FLASK_SECRET_KEY"] = "configured-secret"
        os.environ["PASSKEY_RP_ID"] = "xxxxx"
        os.environ["PASSKEY_ORIGIN"] = "https://auth.xxxxx"
        os.environ["PASSKEY_REGISTRATION_ENABLED"] = "true"
        os.environ["PASSKEY_OAUTH_CHALLENGE_TTL_SECONDS"] = "90"
        os.environ["PASSKEY_DATABASE"] = "/tmp/passkey-test.sqlite3"

        config = AppConfig.from_env(instance_path=self.tempdir.name)

        self.assertEqual(config.flask_secret_key, "configured-secret")
        self.assertEqual(config.passkey_rp_id, "xxxxx")
        self.assertEqual(config.passkey_origin, "https://auth.xxxxx")
        self.assertTrue(config.passkey_registration_enabled)
        self.assertEqual(config.passkey_oauth_challenge_ttl_seconds, 90)
        self.assertEqual(config.passkey_database, "/tmp/passkey-test.sqlite3")

    def test_flask_mapping_uses_existing_keys(self) -> None:
        os.environ["PASSKEY_DATABASE"] = "/tmp/passkey-test.sqlite3"
        config = AppConfig.from_env(instance_path=self.tempdir.name)

        mapping = config.flask_mapping()

        self.assertEqual(mapping["PASSKEY_DATABASE"], "/tmp/passkey-test.sqlite3")
        self.assertEqual(mapping["PASSKEY_RP_ID"], "localhost")
        self.assertIn("PASSKEY_OAUTH_CHALLENGE_TTL_SECONDS", mapping)

    def test_server_config_defaults_and_overrides(self) -> None:
        config = ServerConfig.from_env()
        self.assertFalse(config.debug)
        self.assertEqual(config.host, "localhost")
        self.assertEqual(config.port, 5003)

        os.environ["FLASK_DEBUG"] = "yes"
        os.environ["HOST"] = "0.0.0.0"
        os.environ["PORT"] = "8080"
        config = ServerConfig.from_env()
        self.assertTrue(config.debug)
        self.assertEqual(config.host, "0.0.0.0")
        self.assertEqual(config.port, 8080)


if __name__ == "__main__":
    unittest.main()
