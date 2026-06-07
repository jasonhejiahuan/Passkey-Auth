from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def _new_flask_secret_key() -> str:
    return secrets.token_hex(32)


# =========================
# 应用配置
# =========================


@dataclass(frozen=True)
class AppConfig:
    # Flask session 签名密钥；生产环境必须通过 FLASK_SECRET_KEY 固定配置。
    flask_secret_key: str = field(default_factory=_new_flask_secret_key)

    # WebAuthn RP ID；线上通常是根域名，例如 xxxxx。
    passkey_rp_id: str = "localhost"

    # 浏览器 passkey 弹窗里显示的服务名称。
    passkey_rp_name: str = "Passkey Demo"

    # WebAuthn origin；为空时自动使用当前请求 origin。
    passkey_origin: str | None = None

    # 注册入口解锁后的有效时间，单位秒。
    register_unlock_ttl_seconds: int = 120

    # 是否默认开放注册；默认关闭，避免被批量注册。
    passkey_registration_enabled: bool = False

    # 服务端 session 验证 API 的 Bearer token；空值表示不可用。
    passkey_server_api_token: str = ""

    # Demo OAuth client_id。
    passkey_oauth_demo_client_id: str = "passkey-demo-client"

    # Demo OAuth client_secret；生产环境请改成强随机值。
    passkey_oauth_demo_client_secret: str = "passkey-demo-secret"

    # 额外允许的 OAuth callback；空值表示只允许内置 demo callback。
    passkey_oauth_demo_redirect_uri: str = ""

    # OAuth authorization code 有效期，单位秒。
    passkey_oauth_code_ttl_seconds: int = 300

    # OAuth access token 有效期，单位秒。
    passkey_oauth_access_token_ttl_seconds: int = 3600

    # 链接跳转 challenge 有效期，单位秒。
    passkey_oauth_challenge_ttl_seconds: int = 300

    # SQLite 数据库路径；空值表示使用 Flask instance/passkeys.sqlite3。
    passkey_database: str = ""

    @classmethod
    def from_env(cls, *, instance_path: str | Path) -> AppConfig:
        defaults = cls(passkey_database=str(Path(instance_path) / "passkeys.sqlite3"))
        return cls(
            flask_secret_key=_env_str(
                "FLASK_SECRET_KEY",
                defaults.flask_secret_key,
            ),
            passkey_rp_id=_env_str("PASSKEY_RP_ID", defaults.passkey_rp_id),
            passkey_rp_name=_env_str("PASSKEY_RP_NAME", defaults.passkey_rp_name),
            passkey_origin=_env_optional_str("PASSKEY_ORIGIN"),
            register_unlock_ttl_seconds=_env_int(
                "REGISTER_UNLOCK_TTL_SECONDS",
                defaults.register_unlock_ttl_seconds,
            ),
            passkey_registration_enabled=_env_bool(
                "PASSKEY_REGISTRATION_ENABLED",
                default=defaults.passkey_registration_enabled,
            ),
            passkey_server_api_token=_env_str(
                "PASSKEY_SERVER_API_TOKEN",
                defaults.passkey_server_api_token,
            ),
            passkey_oauth_demo_client_id=_env_str(
                "PASSKEY_OAUTH_DEMO_CLIENT_ID",
                defaults.passkey_oauth_demo_client_id,
            ),
            passkey_oauth_demo_client_secret=_env_str(
                "PASSKEY_OAUTH_DEMO_CLIENT_SECRET",
                defaults.passkey_oauth_demo_client_secret,
            ),
            passkey_oauth_demo_redirect_uri=_env_str(
                "PASSKEY_OAUTH_DEMO_REDIRECT_URI",
                defaults.passkey_oauth_demo_redirect_uri,
            ),
            passkey_oauth_code_ttl_seconds=_env_int(
                "PASSKEY_OAUTH_CODE_TTL_SECONDS",
                defaults.passkey_oauth_code_ttl_seconds,
            ),
            passkey_oauth_access_token_ttl_seconds=_env_int(
                "PASSKEY_OAUTH_ACCESS_TOKEN_TTL_SECONDS",
                defaults.passkey_oauth_access_token_ttl_seconds,
            ),
            passkey_oauth_challenge_ttl_seconds=_env_int(
                "PASSKEY_OAUTH_CHALLENGE_TTL_SECONDS",
                defaults.passkey_oauth_challenge_ttl_seconds,
            ),
            passkey_database=_env_str("PASSKEY_DATABASE", defaults.passkey_database),
        )

    def flask_mapping(self) -> dict[str, object]:
        return {
            "PASSKEY_RP_ID": self.passkey_rp_id,
            "PASSKEY_RP_NAME": self.passkey_rp_name,
            "PASSKEY_ORIGIN": self.passkey_origin,
            "REGISTER_UNLOCK_TTL_SECONDS": self.register_unlock_ttl_seconds,
            "PASSKEY_REGISTRATION_ENABLED": self.passkey_registration_enabled,
            "PASSKEY_SERVER_API_TOKEN": self.passkey_server_api_token,
            "PASSKEY_OAUTH_DEMO_CLIENT_ID": self.passkey_oauth_demo_client_id,
            "PASSKEY_OAUTH_DEMO_CLIENT_SECRET": self.passkey_oauth_demo_client_secret,
            "PASSKEY_OAUTH_DEMO_REDIRECT_URI": self.passkey_oauth_demo_redirect_uri,
            "PASSKEY_OAUTH_CODE_TTL_SECONDS": self.passkey_oauth_code_ttl_seconds,
            "PASSKEY_OAUTH_ACCESS_TOKEN_TTL_SECONDS": (
                self.passkey_oauth_access_token_ttl_seconds
            ),
            "PASSKEY_OAUTH_CHALLENGE_TTL_SECONDS": (
                self.passkey_oauth_challenge_ttl_seconds
            ),
            "PASSKEY_DATABASE": self.passkey_database,
        }


# =========================
# 开发服务器配置
# =========================


@dataclass(frozen=True)
class ServerConfig:
    # 开发服务器 debug 模式。
    debug: bool = False

    # 开发服务器监听地址。
    host: str = "localhost"

    # 开发服务器端口。
    port: int = 5003

    @classmethod
    def from_env(cls) -> ServerConfig:
        defaults = cls()
        return cls(
            debug=_env_bool("FLASK_DEBUG", default=defaults.debug),
            host=_env_str("HOST", defaults.host),
            port=_env_int("PORT", defaults.port),
        )


# =========================
# 环境变量解析
# =========================


def _env_str(
    name: str,
    default: str | None = None,
) -> str:
    value = os.getenv(name)
    if value is not None:
        return value
    return "" if default is None else default


def _env_optional_str(name: str) -> str | None:
    value = os.getenv(name)
    return value if value else None


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return int(value)


def _env_bool(name: str, *, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
