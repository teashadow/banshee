"""Shared config helpers."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

CONFIG_DIR = Path.home() / ".config" / "mad"
SECRETS_PATH = CONFIG_DIR / "secrets.env"
RECON_ROOT = Path.home() / ".local" / "share" / "mad" / "recon"


def ensure_config() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not SECRETS_PATH.exists():
        SECRETS_PATH.touch()
        os.chmod(SECRETS_PATH, 0o600)


def load_secrets() -> None:
    ensure_config()
    load_dotenv(SECRETS_PATH)


def get_secret(name: str) -> str | None:
    load_secrets()
    value = os.getenv(name, "").strip()
    return value or None
