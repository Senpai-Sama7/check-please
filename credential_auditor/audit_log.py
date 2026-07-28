"""Structured file-based audit logging with correlation IDs.

Ported from ultimate_credential_auditor's AuditLogger concept.
Writes one line per event to a persistent log file.
Enhanced for God-tier: JSON structured logs, correlation IDs, context propagation.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Correlation ID context variable — propagates across async/await without explicit threading
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")

# Structured logger for console/stdout (separate from file audit log)
_struct_logger = logging.getLogger("check_please.structured")
if not _struct_logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    _struct_logger.addHandler(handler)
    _struct_logger.setLevel(logging.INFO)


def get_correlation_id() -> str:
    """Return current correlation ID or generate a new one."""
    cid = _correlation_id.get()
    if not cid:
        import secrets

        cid = secrets.token_hex(8)
        _correlation_id.set(cid)
    return cid


def set_correlation_id(cid: str) -> None:
    """Set correlation ID for current context (used by HTTP handlers, CLI entrypoints)."""
    _correlation_id.set(cid)


class AuditLog:
    """Append-only structured audit log with size rotation and correlation IDs."""

    MAX_SIZE = 10 * 1024 * 1024  # 10 MB

    def __init__(self, path: Path):
        self.path = path
        self._entries: list[dict[str, Any]] = []

    def log(
        self,
        event: str,
        provider: str = "",
        env_var: str = "",
        status: str = "",
        latency_ms: float = 0.0,
        detail: str = "",
        extra: Optional[dict[str, Any]] = None,
    ) -> None:
        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
            "cid": get_correlation_id(),
        }
        if provider:
            entry["provider"] = provider
        if env_var:
            entry["env_var"] = env_var
        if status:
            entry["status"] = status
        if latency_ms:
            entry["latency_ms"] = round(latency_ms, 3)
        if detail:
            entry["detail"] = detail
        if extra:
            entry.update(extra)
        self._entries.append(entry)

        # Emit structured log line for observability (stdout)
        try:
            _struct_logger.info(json.dumps(entry, ensure_ascii=False))
        except (TypeError, ValueError, OSError):
            # Logging must never crash the program; swallow serialization errors
            pass

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
