import os
import unittest

from jstu_passkey.app import create_app


class ErrorPageTest(unittest.TestCase):
    def setUp(self):
        self.previous_home_auth = os.environ.get("PASSKEY_HOME_AUTH_ENABLED")
        os.environ["PASSKEY_DATABASE"] = ":memory:"
        os.environ["PASSKEY_HOME_AUTH_ENABLED"] = "false"
        self.app = create_app()
        self.client = self.app.test_client()

    def tearDown(self):
        os.environ.pop("PASSKEY_DATABASE", None)
        if self.previous_home_auth is None:
            os.environ.pop("PASSKEY_HOME_AUTH_ENABLED", None)
        else:
            os.environ["PASSKEY_HOME_AUTH_ENABLED"] = self.previous_home_auth

    def test_edge_error_page_uses_status_label(self):
        response = self.client.get("/_error/404")

        self.assertEqual(response.status_code, 404)
        self.assertIn(b"404", response.data)
        self.assertIn(b"Not Found", response.data)
        self.assertIn(b"<title>404", response.data)
        self.assertNotIn(b"Jason Studio", response.data)

    def test_edge_error_page_supports_server_errors(self):
        response = self.client.get("/_error/500")

        self.assertEqual(response.status_code, 500)
        self.assertIn(b"500", response.data)
        self.assertIn(b"Internal Server Error", response.data)

    def test_edge_error_page_marks_unlisted_errors_as_unknown_ungix(self):
        response = self.client.get("/_error/418")

        self.assertEqual(response.status_code, 418)
        self.assertIn(b"418", response.data)
        self.assertIn(b"Unknown Ungix Error", response.data)

    def test_edge_error_page_falls_back_when_status_is_invalid(self):
        response = self.client.get("/_error/999")

        self.assertEqual(response.status_code, 404)
        self.assertIn(b"404", response.data)
        self.assertIn(b"Unknown Ungix Error", response.data)

    def test_unknown_route_uses_error_page(self):
        response = self.client.get("/missing-page")

        self.assertEqual(response.status_code, 404)
        self.assertIn(b"404", response.data)
        self.assertIn(b"Not Found", response.data)

    def test_error_page_enables_home_auth_controls_when_configured(self):
        os.environ["PASSKEY_HOME_AUTH_ENABLED"] = "true"
        app = create_app()
        client = app.test_client()

        response = client.get("/missing-page")

        self.assertEqual(response.status_code, 404)
        self.assertIn(b"/static/main.js", response.data)
        self.assertIn(b"id=\"logo-button\"", response.data)
        self.assertIn(b'id="status"', response.data)


if __name__ == "__main__":
    unittest.main()
