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
            "PASSKEY_OAUTH_CLIENT_ID",
            "PASSKEY_OAUTH_CLIENT_SECRET",
            "PASSKEY_OAUTH_CLIENT_NAME",
            "PASSKEY_OAUTH_REDIRECT_URIS",
            "PASSKEY_OAUTH_CODE_TTL_SECONDS",
            "PASSKEY_OAUTH_ACCESS_TOKEN_TTL_SECONDS",
            "PASSKEY_OAUTH_CHALLENGE_TTL_SECONDS",
            "PASSKEY_DATABASE",
            "PASSKEY_TRUST_PROXY_HEADERS",
            "PASSKEY_PROXY_FIX_X_FOR",
            "PASSKEY_PROXY_FIX_X_PROTO",
            "PASSKEY_PROXY_FIX_X_HOST",
            "PASSKEY_HTTP3_ALT_SVC",
            "PASSKEY_SECURITY_HEADERS_ENABLED",
            "PASSKEY_HSTS_MAX_AGE_SECONDS",
            "PASSKEY_HSTS_INCLUDE_SUBDOMAINS",
            "PASSKEY_HSTS_PRELOAD",
            "PASSKEY_SECURE_COOKIES",
            "PASSKEY_SERVER_TIMING_ENABLED",
            "PASSKEY_TELEMETRY_TOKEN_URL",
            "PASSKEY_TELEMETRY_API_KEY",
            "PASSKEY_TELEMETRY_TIMEOUT_SECONDS",
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
        self.assertEqual(config.passkey_oauth_client_id, "passkey-demo-client")
        self.assertEqual(config.passkey_oauth_client_secret, "passkey-demo-secret")
        self.assertEqual(config.passkey_oauth_client_name, "Passkey OAuth Client")
        self.assertEqual(config.passkey_oauth_redirect_uris, "")
        self.assertEqual(config.passkey_oauth_code_ttl_seconds, 300)
        self.assertEqual(config.passkey_oauth_access_token_ttl_seconds, 3600)
        self.assertEqual(config.passkey_oauth_challenge_ttl_seconds, 300)
        self.assertTrue(config.passkey_database.endswith("passkeys-v2.sqlite3"))
        self.assertFalse(config.passkey_trust_proxy_headers)
        self.assertEqual(config.passkey_proxy_fix_x_for, 1)
        self.assertEqual(config.passkey_proxy_fix_x_proto, 1)
        self.assertEqual(config.passkey_proxy_fix_x_host, 1)
        self.assertEqual(config.passkey_http3_alt_svc, "")
        self.assertTrue(config.passkey_security_headers_enabled)
        self.assertEqual(config.passkey_hsts_max_age_seconds, 31536000)
        self.assertFalse(config.passkey_hsts_include_subdomains)
        self.assertFalse(config.passkey_hsts_preload)
        self.assertFalse(config.passkey_secure_cookies)
        self.assertTrue(config.passkey_server_timing_enabled)
        self.assertEqual(config.passkey_telemetry_token_url, "")
        self.assertEqual(config.passkey_telemetry_api_key, "")
        self.assertEqual(config.passkey_telemetry_timeout_seconds, 1.0)
        self.assertGreaterEqual(len(config.flask_secret_key), 32)

    def test_app_config_env_overrides(self) -> None:
        os.environ["FLASK_SECRET_KEY"] = "configured-secret"
        os.environ["PASSKEY_RP_ID"] = "xxxxx"
        os.environ["PASSKEY_ORIGIN"] = "https://auth.xxxxx"
        os.environ["PASSKEY_REGISTRATION_ENABLED"] = "true"
        os.environ["PASSKEY_OAUTH_CLIENT_ID"] = "production-client"
        os.environ["PASSKEY_OAUTH_CLIENT_SECRET"] = "production-secret"
        os.environ["PASSKEY_OAUTH_CLIENT_NAME"] = "Production Client"
        os.environ["PASSKEY_OAUTH_REDIRECT_URIS"] = (
            "https://app.example/callback,\nhttps://hyping.example/api/auth/callback"
        )
        os.environ["PASSKEY_OAUTH_CHALLENGE_TTL_SECONDS"] = "90"
        os.environ["PASSKEY_DATABASE"] = "/tmp/passkey-test.sqlite3"
        os.environ["PASSKEY_TRUST_PROXY_HEADERS"] = "true"
        os.environ["PASSKEY_PROXY_FIX_X_FOR"] = "2"
        os.environ["PASSKEY_HTTP3_ALT_SVC"] = 'h3=":443"; ma=86400'
        os.environ["PASSKEY_HSTS_MAX_AGE_SECONDS"] = "63072000"
        os.environ["PASSKEY_HSTS_INCLUDE_SUBDOMAINS"] = "yes"
        os.environ["PASSKEY_HSTS_PRELOAD"] = "on"
        os.environ["PASSKEY_SERVER_TIMING_ENABLED"] = "false"
        os.environ["PASSKEY_TELEMETRY_TOKEN_URL"] = "http://127.0.0.1:15000/v12/key/browser-token"
        os.environ["PASSKEY_TELEMETRY_API_KEY"] = "abcd-abcd-abcd-abcd"
        os.environ["PASSKEY_TELEMETRY_TIMEOUT_SECONDS"] = "0.5"

        config = AppConfig.from_env(instance_path=self.tempdir.name)

        self.assertEqual(config.flask_secret_key, "configured-secret")
        self.assertEqual(config.passkey_rp_id, "xxxxx")
        self.assertEqual(config.passkey_origin, "https://auth.xxxxx")
        self.assertTrue(config.passkey_registration_enabled)
        self.assertEqual(config.passkey_oauth_client_id, "production-client")
        self.assertEqual(config.passkey_oauth_client_secret, "production-secret")
        self.assertEqual(config.passkey_oauth_client_name, "Production Client")
        self.assertEqual(
            config.passkey_oauth_redirect_uris,
            "https://app.example/callback,\nhttps://hyping.example/api/auth/callback",
        )
        self.assertEqual(config.passkey_oauth_challenge_ttl_seconds, 90)
        self.assertEqual(config.passkey_database, "/tmp/passkey-test.sqlite3")
        self.assertTrue(config.passkey_trust_proxy_headers)
        self.assertEqual(config.passkey_proxy_fix_x_for, 2)
        self.assertEqual(config.passkey_http3_alt_svc, 'h3=":443"; ma=86400')
        self.assertEqual(config.passkey_hsts_max_age_seconds, 63072000)
        self.assertTrue(config.passkey_hsts_include_subdomains)
        self.assertTrue(config.passkey_hsts_preload)
        self.assertTrue(config.passkey_secure_cookies)
        self.assertFalse(config.passkey_server_timing_enabled)
        self.assertEqual(
            config.passkey_telemetry_token_url,
            "http://127.0.0.1:15000/v12/key/browser-token",
        )
        self.assertEqual(config.passkey_telemetry_api_key, "abcd-abcd-abcd-abcd")
        self.assertEqual(config.passkey_telemetry_timeout_seconds, 0.5)

    def test_flask_mapping_uses_existing_keys(self) -> None:
        os.environ["PASSKEY_DATABASE"] = "/tmp/passkey-test.sqlite3"
        config = AppConfig.from_env(instance_path=self.tempdir.name)

        mapping = config.flask_mapping()

        self.assertEqual(mapping["PASSKEY_DATABASE"], "/tmp/passkey-test.sqlite3")
        self.assertEqual(mapping["PASSKEY_RP_ID"], "localhost")
        self.assertIn("PASSKEY_OAUTH_CLIENT_ID", mapping)
        self.assertIn("PASSKEY_OAUTH_REDIRECT_URIS", mapping)
        self.assertIn("PASSKEY_OAUTH_CHALLENGE_TTL_SECONDS", mapping)
        self.assertEqual(mapping["SESSION_COOKIE_SAMESITE"], "Lax")
        self.assertFalse(mapping["SESSION_COOKIE_SECURE"])
        self.assertTrue(mapping["PASSKEY_SERVER_TIMING_ENABLED"])
        self.assertIn("PASSKEY_TELEMETRY_TOKEN_URL", mapping)

    def test_secure_cookie_env_can_override_https_origin_default(self) -> None:
        os.environ["PASSKEY_ORIGIN"] = "https://auth.xxxxx"
        os.environ["PASSKEY_SECURE_COOKIES"] = "false"

        config = AppConfig.from_env(instance_path=self.tempdir.name)

        self.assertFalse(config.passkey_secure_cookies)

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
