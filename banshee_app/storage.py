"""Storage helpers for recon runs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import RECON_ROOT


def now_slug() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H-%M-%SZ")


def target_dir(target: str, stamp: str | None = None) -> Path:
    safe = target.replace("/", "_")
    root = RECON_ROOT / safe
    root.mkdir(parents=True, exist_ok=True)
    if stamp is None:
        return root
    run_dir = root / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def latest_run_dir(target: str) -> Path | None:
    root = target_dir(target)
    runs = sorted([path for path in root.iterdir() if path.is_dir()])
    return runs[-1] if runs else None


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))
