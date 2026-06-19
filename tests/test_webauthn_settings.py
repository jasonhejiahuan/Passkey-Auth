from __future__ import annotations

import unittest

from passkey_demo.webauthn_service import WebAuthnConfig, build_registration_options


class WebAuthnSettingsTest(unittest.TestCase):
    def test_registration_options_follow_advanced_settings(self) -> None:
        public_key, _ = build_registration_options(
            username="af01",
            user_handle=b"a" * 32,
            existing_credentials=[],
            config=WebAuthnConfig(
                rp_id="localhost",
                origin="http://localhost",
                algorithms=(-7, -8),
                authenticator_attachment="platform",
                resident_key="preferred",
                user_verification="required",
                attestation="direct",
                exclude_credentials=False,
                hints=("client-device",),
            ),
        )

        self.assertEqual(
            [entry["alg"] for entry in public_key["pubKeyCredParams"]],
            [-7, -8],
        )
        self.assertEqual(public_key["authenticatorSelection"]["authenticatorAttachment"], "platform")
        self.assertEqual(public_key["authenticatorSelection"]["residentKey"], "preferred")
        self.assertEqual(public_key["authenticatorSelection"]["userVerification"], "required")
        self.assertEqual(public_key["attestation"], "direct")
        self.assertEqual(public_key["hints"], ["client-device"])
        self.assertEqual(public_key["excludeCredentials"], [])


if __name__ == "__main__":
    unittest.main()
