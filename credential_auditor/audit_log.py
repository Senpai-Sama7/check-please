"""Structured file-based audit logging.

Ported from ultimate_credential_auditor's AuditLogger concept.
Writes one line per event to a persistent log file.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class AuditLog:
    """Append-only structured audit log with size rotation."""

    MAX_SIZE = 10 * 1024 * 1024  # 10 MB

    def __init__(self, path: Path):
        self.path = path
        self._entries: list[dict] = []

    def log(
        self,
        event: str,
        provider: str = "",
        env_var: str = "",
        status: str = "",
        latency_ms: float = 0.0,
        detail: str = "",
    ) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
        }
        if provider:
            entry["provider"] = provider
        if env_var:
            entry["env_var"] = env_var
        if status:
            entry["status"] = status
        if latency_ms:
            entry["latency_ms"] = round(latency_ms, 2)
        if detail:
            entry["detail"] = detail
        self._entries.append(entry)

    def flush(self) -> None:
        """Append buffered entries to log file, rotating if oversized."""
        if not self._entries:
            return
        # Refuse to write through symlinks
        if self.path.is_symlink():
            self._entries.clear()
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Rotate if log exceeds max size
        if self.path.exists() and self.path.stat().st_size > self.MAX_SIZE:
            rotated = self.path.with_suffix(".log.1")
            if rotated.exists():
                rotated.unlink()
            self.path.rename(rotated)
        with self.path.open("a") as f:
            for entry in self._entries:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._entries.clear()

    @property
    def entry_count(self) -> int:
        return len(self._entries)
