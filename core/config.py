"""
Faedra Pro - Configuration Loader
Author: Uras AKAS | urasakas.com
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field


class AppConfig(BaseModel):
    name: str = "Faedra Pro"
    version: str = "2.0.0"
    author: str = "Uras AKAS | urasakas.com"
    safe_mode: bool = True


class PathsConfig(BaseModel):
    data_dir: str = "data"
    assets_dir: str = "data/assets"
    reports_dir: str = "data/reports"
    logs_dir: str = "data/logs"
    db_path: str = "data/db/faedra.db"


class ScanConfig(BaseModel):
    timeout: int = 300
    max_concurrent: int = 10
    rate_limit_delay: float = 0.5
    user_agent: str = "FaedraPro/2.0 (+https://urasakas.com)"
    respect_robots: bool = True


class NotificationConfig(BaseModel):
    enabled: bool = False
    discord_webhook: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    slack_webhook: str = ""


class ApisConfig(BaseModel):
    shodan: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    securitytrails: str = ""
    openai_compatible: str = ""


class StealthConfig(BaseModel):
    enabled: bool = True
    randomize_ua: bool = True
    proxy: Optional[str] = None
    max_requests_per_second: float = 5.0


class FaedraConfig(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    paths: PathsConfig = Field(default_factory=PathsConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    modules: Dict[str, bool] = Field(default_factory=dict)
    profiles: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    notification: NotificationConfig = Field(default_factory=NotificationConfig)
    apis: ApisConfig = Field(default_factory=ApisConfig)
    stealth: StealthConfig = Field(default_factory=StealthConfig)


def load_config(path: str | Path = "config/default.yaml") -> FaedraConfig:
    path = Path(path)
    if not path.exists():
        return FaedraConfig()
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return FaedraConfig(**data)


def get_profile_modules(config: FaedraConfig, profile: str) -> List[str]:
    prof = config.profiles.get(profile, {})
    return list(prof.get("modules", []))
