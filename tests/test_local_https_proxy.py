from __future__ import annotations

import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jstu_passkey.local_https_proxy import (
    _configure_modern_tls,
    _forward_headers,
    _subject_alt_names,
    build_backend_environment,
    certificate_paths,
    choose_origin,
    default_local_hostname,
    default_origin,
    detect_lan_ip,
    is_ip_address,
    origin_hostname,
)


class LocalHttpsProxyTest(unittest.TestCase):
    def test_modern_tls_policy_requires_tls13_only(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        _configure_modern_tls(context)

        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(context.maximum_version, ssl.TLSVersion.TLSv1_3)
        self.assertTrue(context.options & ssl.OP_NO_COMPRESSION)

    @patch("jstu_passkey.local_https_proxy.ssl.HAS_TLSv1_3", False)
    def test_modern_tls_policy_reports_unsupported_runtime(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        with self.assertRaisesRegex(RuntimeError, "requires TLS 1.3"):
            _configure_modern_tls(context)

    def test_default_origin_formats_ipv4_and_ipv6_hosts(self) -> None:
        self.assertEqual(
            default_origin("192.168.1.23", 5443),
            "https://192.168.1.23:5443",
        )
        self.assertEqual(default_origin("fe80::1", 5443), "https://[fe80::1]:5443")

    @patch("jstu_passkey.local_https_proxy.socket.gethostbyname")
    @patch("jstu_passkey.local_https_proxy.socket.socket")
    def test_detect_lan_ip_falls_back_to_loopback(
        self,
        socket_class,
        gethostbyname,
    ) -> None:
        socket_class.return_value.__enter__.return_value.connect.side_effect = OSError
        gethostbyname.side_effect = OSError

        self.assertEqual(detect_lan_ip(), "127.0.0.1")

    @patch("jstu_passkey.local_https_proxy.socket.gethostname")
    def test_default_local_hostname_uses_valid_local_domain(self, gethostname) -> None:
        gethostname.return_value = "Jason MacBook Pro.local"

        self.assertEqual(default_local_hostname(), "jason-macbook-pro.local")

    def test_origin_hostname_requires_https_origin(self) -> None:
        self.assertEqual(origin_hostname("https://passkey.local:5443"), "passkey.local")

        with self.assertRaises(ValueError):
            origin_hostname("http://localhost:5003")

    def test_origin_hostname_rejects_ip_hosts_for_webauthn(self) -> None:
        with self.assertRaisesRegex(ValueError, "raw IP address"):
            origin_hostname("https://192.168.1.23:5443")

    def test_choose_origin_ignores_existing_http_environment_origin(self) -> None:
        self.assertEqual(
            choose_origin(
                explicit_origin="",
                env_origin="http://localhost:5003",
                hostname="passkey.local",
                https_port=5443,
            ),
            "https://passkey.local:5443",
        )
        self.assertEqual(
            choose_origin(
                explicit_origin="https://explicit.local:5443",
                env_origin="https://env.local:5443",
                hostname="passkey.local",
                https_port=5443,
            ),
            "https://explicit.local:5443",
        )

    def test_backend_environment_sets_proxy_safe_local_defaults(self) -> None:
        env = build_backend_environment(
            base_env={"PASSKEY_RP_ID": "auth.local"},
            origin="https://passkey.local:5443",
            backend_port=5003,
            backend_host="127.0.0.1",
        )

        self.assertEqual(env["HOST"], "127.0.0.1")
        self.assertEqual(env["PORT"], "5003")
        self.assertEqual(env["PASSKEY_ORIGIN"], "https://passkey.local:5443")
        self.assertEqual(env["PASSKEY_TRUST_PROXY_HEADERS"], "true")
        self.assertEqual(env["PASSKEY_SECURE_COOKIES"], "true")
        self.assertEqual(env["PASSKEY_HSTS_MAX_AGE_SECONDS"], "0")
        self.assertEqual(env["FLASK_DEBUG"], "false")
        self.assertEqual(env["PASSKEY_RP_ID"], "auth.local")

    def test_backend_environment_defaults_rp_id_to_origin_host(self) -> None:
        env = build_backend_environment(
            base_env={},
            origin="https://passkey.local:5443",
            backend_port=5003,
            backend_host="127.0.0.1",
        )

        self.assertEqual(env["PASSKEY_RP_ID"], "passkey.local")

    def test_is_ip_address_recognizes_raw_ips(self) -> None:
        self.assertTrue(is_ip_address("192.168.1.23"))
        self.assertTrue(is_ip_address("::1"))
        self.assertFalse(is_ip_address("passkey.local"))

    def test_forward_headers_add_trusted_proxy_headers(self) -> None:
        headers = _forward_headers(
            source_headers={
                "Host": "192.168.1.23:5443",
                "Connection": "keep-alive",
                "Cookie": "session=abc",
                "X-Forwarded-For": "10.0.0.2",
            },
            client_ip="192.168.1.50",
            external_host="192.168.1.23:5443",
        )

        self.assertEqual(headers["Host"], "192.168.1.23:5443")
        self.assertEqual(headers["X-Forwarded-Proto"], "https")
        self.assertEqual(headers["X-Forwarded-Host"], "192.168.1.23:5443")
        self.assertEqual(headers["X-Forwarded-For"], "10.0.0.2, 192.168.1.50")
        self.assertEqual(headers["Cookie"], "session=abc")
        self.assertNotIn("Connection", headers)

    def test_subject_alt_names_include_localhost_and_requested_host(self) -> None:
        self.assertIn(("IP", "192.168.1.23"), _subject_alt_names("192.168.1.23"))
        self.assertIn(("DNS", "auth.local"), _subject_alt_names("auth.local"))
        self.assertIn(("DNS", "localhost"), _subject_alt_names("auth.local"))
        self.assertIn(("IP", "127.0.0.1"), _subject_alt_names("auth.local"))

    def test_certificate_paths_sanitize_hostname(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cert_path, key_path = certificate_paths(Path(tmp), "fe80::1")

        self.assertTrue(str(cert_path).endswith("fe80_1/cert.pem"))
        self.assertTrue(str(key_path).endswith("fe80_1/key.pem"))


if __name__ == "__main__":
    unittest.main()
