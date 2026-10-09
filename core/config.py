"""
TwinGuard — Central Configuration
Loads from YAML + environment variable overrides.
"""

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "twinguard.yaml"  # retained for compatibility with existing deployments


class ContextIntegrityConfig(BaseModel):
    enabled: bool = True
    hash_algorithm: str = "sha256"
    check_interval_seconds: int = 30
    protected_instruction_tags: list[str] = [
        "system_prompt", "safety_rules", "user_policies", "tool_restrictions"
    ]
    alert_on_degradation_percent: int = 10


class ExecutionGatewayConfig(BaseModel):
    enabled: bool = True
    auto_approve_safe: bool = True
    veto_timeout_seconds: int = 300
    default_action: str = "block"
    claude_model: str = "claude-haiku-4-5-20251001"


class ThreatFadeOracleConfig(BaseModel):
    enabled: bool = True
    service_url: str = "http://threatfade:8401"
    poll_interval_seconds: int = 60
    severity_threshold: str = "medium"


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8400
    debug: bool = False
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "json"
    file: str = "logs/twinguard.log"


class BrandingConfig(BaseModel):
    name: str = "Auctaryn"
    company: str = "Tinlance Limited"
    version: str = "0.1.0-alpha"


class TwinGuardConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    context_integrity: ContextIntegrityConfig = Field(default_factory=ContextIntegrityConfig)
    execution_gateway: ExecutionGatewayConfig = Field(default_factory=ExecutionGatewayConfig)
    threatfade_oracle: ThreatFadeOracleConfig = Field(default_factory=ThreatFadeOracleConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    branding: BrandingConfig = Field(default_factory=BrandingConfig)


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base, recursively for nested dicts."""
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _apply_env_overrides(raw: dict) -> dict:
    """Override config values with environment variables where set."""
    env_map = {
        "AUCTARYN_HOST": ("server", "host"),
        "TWINGUARD_HOST": ("server", "host"),
        "AUCTARYN_PORT": ("server", "port"),
        "TWINGUARD_PORT": ("server", "port"),
        "AUCTARYN_DEBUG": ("server", "debug"),
        "TWINGUARD_DEBUG": ("server", "debug"),
        "AUCTARYN_DB_PATH": ("database", "path"),
        "TWINGUARD_DB_PATH": ("database", "path"),
        "THREATFADE_SERVICE_URL": ("modules", "threatfade_oracle", "service_url"),
        "LOG_LEVEL": ("logging", "level"),
    }

    for env_key, config_path in env_map.items():
        value = os.environ.get(env_key)
        if value is not None:
            current = raw
            for part in config_path[:-1]:
                current = current.setdefault(part, {})
            # Type coercion for known types
            final_key = config_path[-1]
            if final_key == "port":
                value = int(value)
            elif final_key == "debug":
                value = value.lower() in ("true", "1", "yes")
            current[final_key] = value

    return raw


def load_config(path: Path | None = None) -> TwinGuardConfig:
    """Load config from YAML file with env var overrides."""
    config_path = path or CONFIG_PATH

    if config_path.exists():
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
    else:
        raw = {}

    raw = _apply_env_overrides(raw)

    # Flatten nested module configs for Pydantic
    modules = raw.get("modules", {})
    flat = {
        "server": raw.get("server", {}),
        "context_integrity": modules.get("context_integrity", {}),
        "execution_gateway": modules.get("execution_gateway", {}),
        "threatfade_oracle": modules.get("threatfade_oracle", {}),
        "logging": raw.get("logging", {}),
        "branding": raw.get("branding", {}),
    }

    return TwinGuardConfig(**flat)


# Singleton instance
_config: TwinGuardConfig | None = None


def get_config() -> TwinGuardConfig:
    """Get the global config singleton."""
    global _config
    if _config is None:
        _config = load_config()
    return _config
