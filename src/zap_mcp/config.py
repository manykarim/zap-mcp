"""Configuration management for ZAP MCP server."""

from __future__ import annotations

from functools import lru_cache
from typing import List, Optional

from pydantic import Field, SecretStr, validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ZAPConfig(BaseSettings):
    """Settings controlling the OWASP ZAP connection."""

    proxy_url: str = Field(
        default="http://localhost:8080",
        description="Base URL of the running ZAP proxy",
    )
    api_key: Optional[SecretStr] = Field(
        default=None,
        description="API key used to authenticate with the ZAP daemon",
    )
    timeout_seconds: int = Field(
        default=120,
        description="Timeout used for outbound requests to ZAP",
    )
    max_spider_depth: int = Field(
        default=10,
        description="Maximum spider depth when crawling sites",
    )
    poll_interval_seconds: float = Field(
        default=2.0,
        description="Default interval between status polls for long running jobs",
    )


class ServerConfig(BaseSettings):
    """Configuration for the FastMCP server transport."""

    name: str = Field(default="ZAP Security Scanner", description="Name advertised to MCP clients")
    version: str = Field(default="0.1.0", description="Semantic version string")
    host: str = Field(default="0.0.0.0", description="Interface used for binding the MCP server")
    port: int = Field(default=8000, description="Port exposed by the MCP server")
    log_level: str = Field(default="INFO", description="Python logging level")
    enable_ui: bool = Field(default=True, description="Enable MCP-UI resources")
    allowed_domains: List[str] = Field(
        default_factory=lambda: ["*"],
        description="Hostnames that may be scanned",
    )

    @validator("log_level")
    def _validate_log_level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = value.upper()
        if upper not in allowed:
            raise ValueError(f"Unsupported log level: {value}")
        return upper


class FeatureFlags(BaseSettings):
    """Feature toggles for optional functionality."""

    authentication: bool = Field(default=False, description="Enable authentication helpers")
    compliance_checks: bool = Field(default=True, description="Enable OWASP compliance helpers")
    auto_reporting: bool = Field(default=True, description="Generate reports automatically")


class Settings(BaseSettings):
    """Top level strongly typed application configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ZAP_MCP_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    zap: ZAPConfig = Field(default_factory=ZAPConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)
    features: FeatureFlags = Field(default_factory=FeatureFlags)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached settings instance."""

    return Settings()


settings = get_settings()


def server_allowed_domains() -> List[str]:
    """Expose the configured allow list for validators."""

    return settings.server.allowed_domains
