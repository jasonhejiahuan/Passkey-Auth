"""PKCE bindings carried by opaque, signed authorization codes.

The complete code is still hash-only, single-use storage in the existing v2
database. The signed binding avoids a schema migration or a second code store.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from base64 import urlsafe_b64encode

from itsdangerous import BadSignature, URLSafeTimedSerializer


def valid_s256_challenge(challenge: str, method: str) -> bool:
    return bool(method == "S256" and re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge))


def new_authorization_code(secret_key: str, challenge: str = "") -> str:
    nonce = secrets.token_urlsafe(32)
    if not challenge:
        return nonce
    serializer = URLSafeTimedSerializer(secret_key, salt="oauth-pkce-code-v1")
    return "pkce." + serializer.dumps({"nonce": nonce, "challenge": challenge})


def verify_code_pkce(secret_key: str, code: str, verifier: str, ttl: int) -> bool:
    if not isinstance(code, str) or not isinstance(verifier, str):
        return False
    if not code.startswith("pkce."):
        return not verifier
    if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier):
        return False
    try:
        binding = URLSafeTimedSerializer(
            secret_key, salt="oauth-pkce-code-v1"
        ).loads(code[5:], max_age=ttl)
    except BadSignature:
        return False
    if not isinstance(binding, dict) or not isinstance(binding.get("challenge"), str):
        return False
    digest = urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return secrets.compare_digest(digest.decode("ascii").rstrip("="), binding["challenge"])
