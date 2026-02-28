"""Security utilities — redaction, file permission checks, logging suppression.

Design source: Claude/GPT dedicated security module.
Addresses: INV-4 (no raw key in any output stream).
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path


def suppress_credential_logging() -> None:
    """Prevent httpx/httpcore from logging raw credentials at DEBUG level."""
    for name in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)


def check_output_permissions(path: Path, force: bool = False) -> bool:
    """Return True if safe to write. Warns on world-readable files per spec."""
    if not path.exists():
        parent = path.parent
        if parent.exists():
            mode = os.stat(parent).st_mode
            if mode & stat.S_IROTH:
                if not force:
                    return False
        return True
    mode = os.stat(path).st_mode
    if mode & stat.S_IROTH:
        return force
    return True


def redact_key(key: str) -> str:
    """Return redacted form: first 4 + '...' + last 4 chars, or masked if too short."""
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}...{key[-4:]}"
