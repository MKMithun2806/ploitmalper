"""Persistent state configuration manager."""

import json
import os
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

CONFIG_DIR = Path.home() / ".config" / "ploit_malper"
CONFIG_FILE = CONFIG_DIR / "config.json"


@dataclass
class MSFRPCConfig:
    host: str = "127.0.0.1"
    port: int = 55553
    username: str = "msf"
    password: str = ""
    ssl: bool = True
    workspace: str = "default"


@dataclass
class AppConfig:
    msfrpc: MSFRPCConfig = field(default_factory=MSFRPCConfig)
    report_dir: str = str(Path.home() / "ploit_malper_reports")
    last_scan_file: Optional[str] = None


class ConfigManager:
    def __init__(self) -> None:
        self.config: AppConfig = AppConfig()
        self._loaded = False

    def load(self) -> bool:
        if CONFIG_FILE.exists():
            try:
                raw = CONFIG_FILE.read_text(encoding="utf-8")
                data = json.loads(raw)
                msf_data = data.get("msfrpc", {})
                self.config = AppConfig(
                    msfrpc=MSFRPCConfig(**msf_data),
                    report_dir=data.get("report_dir", self.config.report_dir),
                    last_scan_file=data.get("last_scan_file"),
                )
                self._loaded = True
                return True
            except (json.JSONDecodeError, TypeError, KeyError):
                return False
        return False

    def save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        data = asdict(self.config)
        CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def reset(self) -> None:
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()
        self.config = AppConfig()
        self._loaded = False

    def is_configured(self) -> bool:
        return self._loaded and bool(self.config.msfrpc.password)

    def get_msfrpc_config(self) -> MSFRPCConfig:
        return self.config.msfrpc
