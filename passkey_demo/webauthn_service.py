from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialHint,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


@dataclass(frozen=True)
class WebAuthnConfig:
    rp_id: str
    origin: str | Sequence[str]
    rp_name: str = "Passkey Demo"
    timeout_ms: int = 60_000
    require_user_verification: bool = False
    algorithms: tuple[int, ...] = (-7, -8, -257)
    authenticator_attachment: str = "any"
    resident_key: str = "required"
    user_verification: str = "preferred"
    attestation: str = "none"
    exclude_credentials: bool = True
    hints: tuple[str, ...] = ("client-device", "security-key", "hybrid")


@dataclass(frozen=True)
class CredentialForOptions:
    credential_id: bytes
    transports: list[str]


@dataclass(frozen=True)
class RegistrationResult:
    credential_id: bytes
    public_key: bytes
    sign_count: int
    aaguid: str
    credential_type: str
    device_type: str
    backed_up: bool
    transports: list[str]
    user_verified: bool


@dataclass(frozen=True)
class AuthenticationResult:
    credential_id: bytes
    new_sign_count: int
    device_type: str
    backed_up: bool
    user_verified: bool
    user_handle: bytes | None


def normalize_username(username: str) -> str:
    value = (username or "").strip()
    if not 1 <= len(value) <= 64:
        raise ValueError("用户名长度需要在 1 到 64 个字符之间")
    if not re.fullmatch(r"[\w.@+\-\u4e00-\u9fff ]+", value):
        raise ValueError("用户名只能包含中英文、数字、空格、_ . @ + -")
    return value


def build_registration_options(
    *,
    username: str,
    user_handle: bytes,
    existing_credentials: Iterable[CredentialForOptions],
    config: WebAuthnConfig,
) -> tuple[dict[str, Any], str]:
    options = generate_registration_options(
        rp_id=config.rp_id,
        rp_name=config.rp_name,
        user_name=normalize_username(username),
        user_display_name=username,
        user_id=user_handle,
        timeout=config.timeout_ms,
        attestation=AttestationConveyancePreference(config.attestation),
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=(
                None
                if config.authenticator_attachment == "any"
                else AuthenticatorAttachment(config.authenticator_attachment)
            ),
            resident_key=ResidentKeyRequirement(config.resident_key),
            require_resident_key=config.resident_key == "required",
            user_verification=UserVerificationRequirement(config.user_verification),
        ),
        exclude_credentials=[
            _descriptor_from_credential(credential)
            for credential in existing_credentials
        ] if config.exclude_credentials else [],
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier(algorithm) for algorithm in config.algorithms
        ],
        hints=[PublicKeyCredentialHint(hint) for hint in config.hints] or None,
    )
    return json.loads(options_to_json(options)), bytes_to_base64url(options.challenge)


def verify_registration(
    *,
    credential: dict[str, Any],
    expected_challenge: str,
    config: WebAuthnConfig,
) -> RegistrationResult:
    verified = verify_registration_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(expected_challenge),
        expected_rp_id=config.rp_id,
        expected_origin=config.origin,
        require_user_verification=config.require_user_verification,
    )
    return RegistrationResult(
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        aaguid=str(verified.aaguid),
        credential_type=str(verified.credential_type),
        device_type=str(verified.credential_device_type),
        backed_up=bool(verified.credential_backed_up),
        transports=_extract_transports(credential),
        user_verified=bool(verified.user_verified),
    )


def build_authentication_options(
    *,
    allowed_credentials: Iterable[CredentialForOptions] | None,
    config: WebAuthnConfig,
) -> tuple[dict[str, Any], str]:
    credentials = None
    if allowed_credentials is not None:
        credentials = [
            _descriptor_from_credential(credential)
            for credential in allowed_credentials
        ]

    options = generate_authentication_options(
        rp_id=config.rp_id,
        timeout=config.timeout_ms,
        allow_credentials=credentials,
        user_verification=UserVerificationRequirement(config.user_verification),
    )
    public_key = json.loads(options_to_json(options))
    if allowed_credentials is None:
        public_key.pop("allowCredentials", None)
    return public_key, bytes_to_base64url(options.challenge)


def verify_authentication(
    *,
    credential: dict[str, Any],
    expected_challenge: str,
    credential_public_key: bytes,
    credential_current_sign_count: int,
    config: WebAuthnConfig,
) -> AuthenticationResult:
    verified = verify_authentication_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(expected_challenge),
        expected_rp_id=config.rp_id,
        expected_origin=config.origin,
        credential_public_key=credential_public_key,
        credential_current_sign_count=credential_current_sign_count,
        require_user_verification=config.require_user_verification,
    )
    return AuthenticationResult(
        credential_id=verified.credential_id,
        new_sign_count=verified.new_sign_count,
        device_type=str(verified.credential_device_type),
        backed_up=bool(verified.credential_backed_up),
        user_verified=bool(verified.user_verified),
        user_handle=_extract_user_handle(credential),
    )


def credential_for_options(credential: Any) -> CredentialForOptions:
    return CredentialForOptions(
        credential_id=credential.credential_id,
        transports=list(getattr(credential, "transports", []) or []),
    )


def _descriptor_from_credential(
    credential: CredentialForOptions,
) -> PublicKeyCredentialDescriptor:
    return PublicKeyCredentialDescriptor(
        id=credential.credential_id,
        transports=[
            AuthenticatorTransport(transport)
            for transport in credential.transports
            if transport in {item.value for item in AuthenticatorTransport}
        ]
        or None,
    )


def _extract_transports(credential: dict[str, Any]) -> list[str]:
    response = credential.get("response") or {}
    transports = response.get("transports") or []
    allowed = {transport.value for transport in AuthenticatorTransport}
    return [transport for transport in transports if transport in allowed]


def _extract_user_handle(credential: dict[str, Any]) -> bytes | None:
    user_handle = (credential.get("response") or {}).get("userHandle")
    if not user_handle:
        return None
    return base64url_to_bytes(user_handle)
