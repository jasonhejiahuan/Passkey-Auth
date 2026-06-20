from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


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
    passkey_rp_name: str = "JSTU Passkey"

    # WebAuthn origin；为空时自动使用当前请求 origin。
    passkey_origin: str | None = None

    # 注册入口解锁后的有效时间，单位秒。
    register_unlock_ttl_seconds: int = 120

    # 是否默认开放注册；默认关闭，避免被批量注册。
    passkey_registration_enabled: bool = False

    # 是否在主页启用 Passkey 注册/登录交互；关闭时仅展示品牌页面。
    passkey_home_auth_enabled: bool = True

    # 服务端 session 验证 API 的 Bearer token；空值表示不可用。
    passkey_server_api_token: str = ""

    # 标准 OAuth client_id；示例页面也使用同一套 client 配置。
    passkey_oauth_client_id: str = "jstu-passkey-client"

    # 标准 OAuth client_secret；生产环境请改成强随机值。
    passkey_oauth_client_secret: str = "jstu-passkey-secret"

    # 标准 OAuth client 名称。
    passkey_oauth_client_name: str = "Passkey OAuth Client"

    # 额外允许的 OAuth callback 列表；使用逗号或换行分隔。
    passkey_oauth_redirect_uris: str = ""

    # OAuth authorization code 有效期，单位秒。
    passkey_oauth_code_ttl_seconds: int = 300

    # OAuth access token 有效期，单位秒。
    passkey_oauth_access_token_ttl_seconds: int = 3600

    # 链接跳转 challenge 有效期，单位秒。
    passkey_oauth_challenge_ttl_seconds: int = 300

    # SQLite 数据库路径；空值表示使用 Flask instance/passkeys-v2.sqlite3。
    passkey_database: str = ""

    # 是否信任反向代理注入的 X-Forwarded-* 头，用于 HTTPS/HTTP2/HTTP3 终止场景。
    passkey_trust_proxy_headers: bool = False

    # 代理链中可信 X-Forwarded-For hop 数。
    passkey_proxy_fix_x_for: int = 1

    # 代理链中可信 X-Forwarded-Proto hop 数。
    passkey_proxy_fix_x_proto: int = 1

    # 代理链中可信 X-Forwarded-Host hop 数。
    passkey_proxy_fix_x_host: int = 1

    # HTTP/3 由 TLS 反向代理终止；设置该值后 HTTPS 响应会带 Alt-Svc。
    passkey_http3_alt_svc: str = ""

    # 是否发送现代浏览器安全响应头。
    passkey_security_headers_enabled: bool = True

    # HTTPS 响应的 HSTS max-age；0 表示关闭。
    passkey_hsts_max_age_seconds: int = 31536000

    # HSTS 是否覆盖子域名。
    passkey_hsts_include_subdomains: bool = False

    # HSTS 是否声明 preload。
    passkey_hsts_preload: bool = False

    # Flask session cookie 是否仅通过 HTTPS 发送；HTTPS origin 默认开启。
    passkey_secure_cookies: bool = False

    # 是否发送低敏的 Server-Timing 总耗时，便于浏览器 DevTools 调试。
    passkey_server_timing_enabled: bool = True

    # Jason Telemetry v12 随机浏览器采集口令创建 URL；为空时不注入采集脚本。
    passkey_telemetry_token_url: str = ""

    # Jason Telemetry v12 服务端 API key；仅服务端使用，不发送给浏览器。
    passkey_telemetry_api_key: str = ""

    # Jason Telemetry 请求超时，单位秒。
    passkey_telemetry_timeout_seconds: float = 1.0

    @classmethod
    def from_env(cls, *, instance_path: str | Path) -> AppConfig:
        defaults = cls(passkey_database=str(Path(instance_path) / "passkeys-v2.sqlite3"))
        passkey_origin = _env_optional_str("PASSKEY_ORIGIN")
        secure_cookies_default = _origin_is_https(passkey_origin)
        return cls(
            flask_secret_key=_env_str(
                "FLASK_SECRET_KEY",
                defaults.flask_secret_key,
            ),
            passkey_rp_id=_env_str("PASSKEY_RP_ID", defaults.passkey_rp_id),
            passkey_rp_name=_env_str("PASSKEY_RP_NAME", defaults.passkey_rp_name),
            passkey_origin=passkey_origin,
            register_unlock_ttl_seconds=_env_int(
                "REGISTER_UNLOCK_TTL_SECONDS",
                defaults.register_unlock_ttl_seconds,
            ),
            passkey_registration_enabled=_env_bool(
                "PASSKEY_REGISTRATION_ENABLED",
                default=defaults.passkey_registration_enabled,
            ),
            passkey_home_auth_enabled=_env_bool(
                "PASSKEY_HOME_AUTH_ENABLED",
                default=defaults.passkey_home_auth_enabled,
            ),
            passkey_server_api_token=_env_str(
                "PASSKEY_SERVER_API_TOKEN",
                defaults.passkey_server_api_token,
            ),
            passkey_oauth_client_id=_env_str(
                "PASSKEY_OAUTH_CLIENT_ID",
                defaults.passkey_oauth_client_id,
            ),
            passkey_oauth_client_secret=_env_str(
                "PASSKEY_OAUTH_CLIENT_SECRET",
                defaults.passkey_oauth_client_secret,
            ),
            passkey_oauth_client_name=_env_str(
                "PASSKEY_OAUTH_CLIENT_NAME",
                defaults.passkey_oauth_client_name,
            ),
            passkey_oauth_redirect_uris=_env_str(
                "PASSKEY_OAUTH_REDIRECT_URIS",
                defaults.passkey_oauth_redirect_uris,
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
            passkey_trust_proxy_headers=_env_bool(
                "PASSKEY_TRUST_PROXY_HEADERS",
                default=defaults.passkey_trust_proxy_headers,
            ),
            passkey_proxy_fix_x_for=_env_int(
                "PASSKEY_PROXY_FIX_X_FOR",
                defaults.passkey_proxy_fix_x_for,
            ),
            passkey_proxy_fix_x_proto=_env_int(
                "PASSKEY_PROXY_FIX_X_PROTO",
                defaults.passkey_proxy_fix_x_proto,
            ),
            passkey_proxy_fix_x_host=_env_int(
                "PASSKEY_PROXY_FIX_X_HOST",
                defaults.passkey_proxy_fix_x_host,
            ),
            passkey_http3_alt_svc=_env_str(
                "PASSKEY_HTTP3_ALT_SVC",
                defaults.passkey_http3_alt_svc,
            ),
            passkey_security_headers_enabled=_env_bool(
                "PASSKEY_SECURITY_HEADERS_ENABLED",
                default=defaults.passkey_security_headers_enabled,
            ),
            passkey_hsts_max_age_seconds=_env_int(
                "PASSKEY_HSTS_MAX_AGE_SECONDS",
                defaults.passkey_hsts_max_age_seconds,
            ),
            passkey_hsts_include_subdomains=_env_bool(
                "PASSKEY_HSTS_INCLUDE_SUBDOMAINS",
                default=defaults.passkey_hsts_include_subdomains,
            ),
            passkey_hsts_preload=_env_bool(
                "PASSKEY_HSTS_PRELOAD",
                default=defaults.passkey_hsts_preload,
            ),
            passkey_secure_cookies=_env_optional_bool(
                "PASSKEY_SECURE_COOKIES",
                default=secure_cookies_default,
            ),
            passkey_server_timing_enabled=_env_bool(
                "PASSKEY_SERVER_TIMING_ENABLED",
                default=defaults.passkey_server_timing_enabled,
            ),
            passkey_telemetry_token_url=_env_str(
                "PASSKEY_TELEMETRY_TOKEN_URL",
                defaults.passkey_telemetry_token_url,
            ),
            passkey_telemetry_api_key=_env_str(
                "PASSKEY_TELEMETRY_API_KEY",
                defaults.passkey_telemetry_api_key,
            ),
            passkey_telemetry_timeout_seconds=_env_float(
                "PASSKEY_TELEMETRY_TIMEOUT_SECONDS",
                defaults.passkey_telemetry_timeout_seconds,
            ),
        )

    def flask_mapping(self) -> dict[str, object]:
        return {
            "PASSKEY_RP_ID": self.passkey_rp_id,
            "PASSKEY_RP_NAME": self.passkey_rp_name,
            "PASSKEY_ORIGIN": self.passkey_origin,
            "REGISTER_UNLOCK_TTL_SECONDS": self.register_unlock_ttl_seconds,
            "PASSKEY_REGISTRATION_ENABLED": self.passkey_registration_enabled,
            "PASSKEY_HOME_AUTH_ENABLED": self.passkey_home_auth_enabled,
            "PASSKEY_SERVER_API_TOKEN": self.passkey_server_api_token,
            "PASSKEY_OAUTH_CLIENT_ID": self.passkey_oauth_client_id,
            "PASSKEY_OAUTH_CLIENT_SECRET": self.passkey_oauth_client_secret,
            "PASSKEY_OAUTH_CLIENT_NAME": self.passkey_oauth_client_name,
            "PASSKEY_OAUTH_REDIRECT_URIS": self.passkey_oauth_redirect_uris,
            "PASSKEY_OAUTH_CODE_TTL_SECONDS": self.passkey_oauth_code_ttl_seconds,
            "PASSKEY_OAUTH_ACCESS_TOKEN_TTL_SECONDS": (
                self.passkey_oauth_access_token_ttl_seconds
            ),
            "PASSKEY_OAUTH_CHALLENGE_TTL_SECONDS": (
                self.passkey_oauth_challenge_ttl_seconds
            ),
            "PASSKEY_DATABASE": self.passkey_database,
            "PASSKEY_TRUST_PROXY_HEADERS": self.passkey_trust_proxy_headers,
            "PASSKEY_PROXY_FIX_X_FOR": self.passkey_proxy_fix_x_for,
            "PASSKEY_PROXY_FIX_X_PROTO": self.passkey_proxy_fix_x_proto,
            "PASSKEY_PROXY_FIX_X_HOST": self.passkey_proxy_fix_x_host,
            "PASSKEY_HTTP3_ALT_SVC": self.passkey_http3_alt_svc,
            "PASSKEY_SECURITY_HEADERS_ENABLED": self.passkey_security_headers_enabled,
            "PASSKEY_HSTS_MAX_AGE_SECONDS": self.passkey_hsts_max_age_seconds,
            "PASSKEY_HSTS_INCLUDE_SUBDOMAINS": self.passkey_hsts_include_subdomains,
            "PASSKEY_HSTS_PRELOAD": self.passkey_hsts_preload,
            "SESSION_COOKIE_HTTPONLY": True,
            "SESSION_COOKIE_SAMESITE": "Lax",
            "SESSION_COOKIE_SECURE": self.passkey_secure_cookies,
            "PASSKEY_SERVER_TIMING_ENABLED": self.passkey_server_timing_enabled,
            "PASSKEY_TELEMETRY_TOKEN_URL": self.passkey_telemetry_token_url,
            "PASSKEY_TELEMETRY_API_KEY": self.passkey_telemetry_api_key,
            "PASSKEY_TELEMETRY_TIMEOUT_SECONDS": (
                self.passkey_telemetry_timeout_seconds
            ),
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


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return float(value)


def _env_bool(name: str, *, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_optional_bool(name: str, *, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _origin_is_https(origin: str | None) -> bool:
    if not origin:
        return False
    return urlsplit(origin).scheme == "https"
