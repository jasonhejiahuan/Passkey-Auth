from __future__ import annotations

import os
import tempfile
import unittest

from passkey_demo.app import create_app


class ModernProtocolHeadersTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.previous_env = {
            key: os.environ.get(key)
            for key in (
                "PASSKEY_DATABASE",
                "FLASK_SECRET_KEY",
                "PASSKEY_ORIGIN",
                "PASSKEY_TRUST_PROXY_HEADERS",
                "PASSKEY_HTTP3_ALT_SVC",
                "PASSKEY_HSTS_INCLUDE_SUBDOMAINS",
                "PASSKEY_SERVER_TIMING_ENABLED",
            )
        }
        os.environ["PASSKEY_DATABASE"] = os.path.join(
            self.tempdir.name,
            "passkeys.sqlite3",
        )
        os.environ["FLASK_SECRET_KEY"] = "test-secret"

    def tearDown(self) -> None:
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tempdir.cleanup()

    def test_security_headers_are_sent_on_default_http_response(self) -> None:
        app = create_app()
        app.testing = True
        client = app.test_client()

        response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertIn(
            "publickey-credentials-get=(self)",
            response.headers["Permissions-Policy"],
        )
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertRegex(response.headers["Server-Timing"], r"^app;dur=\d+\.\d$")
        self.assertNotIn("Strict-Transport-Security", response.headers)
        self.assertNotIn("Alt-Svc", response.headers)

    def test_server_timing_can_be_disabled(self) -> None:
        os.environ["PASSKEY_SERVER_TIMING_ENABLED"] = "false"
        app = create_app()
        app.testing = True
        client = app.test_client()

        response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Server-Timing", response.headers)

    def test_https_response_can_advertise_http3_and_hsts(self) -> None:
        os.environ["PASSKEY_ORIGIN"] = "https://auth.example"
        os.environ["PASSKEY_HTTP3_ALT_SVC"] = 'h3=":443"; ma=86400'
        os.environ["PASSKEY_HSTS_INCLUDE_SUBDOMAINS"] = "true"
        app = create_app()
        app.testing = True
        client = app.test_client()

        response = client.get("/", base_url="https://auth.example")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Alt-Svc"], 'h3=":443"; ma=86400')
        self.assertEqual(
            response.headers["Strict-Transport-Security"],
            "max-age=31536000; includeSubDomains",
        )
        self.assertTrue(app.config["SESSION_COOKIE_SECURE"])

    def test_trusted_proxy_headers_build_external_https_urls(self) -> None:
        os.environ["PASSKEY_TRUST_PROXY_HEADERS"] = "true"
        app = create_app()
        app.testing = True
        client = app.test_client()

        response = client.get(
            "/demo/oauth",
            base_url="http://internal",
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "auth.example",
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn(
            "redirect_uri=https%3A%2F%2Fauth.example%2Fdemo%2Foauth%2Fcallback",
            body,
        )


if __name__ == "__main__":
    unittest.main()
