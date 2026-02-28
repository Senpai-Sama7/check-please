"""Security utilities — redaction, file permission checks, logging suppression.

Design source: Claude/GPT dedicated security module.
Addresses: INV-4 (no raw key in any output stream).

Enhanced with multi-level redaction ported from ultimate_credential_auditor.
"""

from __future__ import annotations

import hashlib
import logging
import os
import stat
from enum import Enum
from pathlib import Path
from typing import Optional


class RedactionLevel(Enum):
    """Redaction levels — controls how much of a key is visible."""
    PARTIAL = "partial"   # show prefix...suffix
    FULL = "full"         # [REDACTED]
    HASH = "hash"         # [sha256:abcd1234]


def suppress_credential_logging() -> None:
    """Prevent httpx/httpcore from logging raw credentials at DEBUG level."""
    for name in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)


def is_symlink_or_hardlink_attack(path: Path) -> bool:
    """Detect symlink/hardlink attacks on output paths."""
    if path.is_symlink():
        return True
    if path.exists():
        # Hardlink check: resolved path differs from the path itself
        try:
            if path.resolve(strict=True) != path.absolute():
                return True
        except OSError:
            return True
    return False


def check_output_permissions(path: Path, force: bool = False) -> bool:
    """Return True if safe to write. Refuses symlinks. Warns on world-readable."""
    if is_symlink_or_hardlink_attack(path):
        return False
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


def redact_key(key: str, level: RedactionLevel = RedactionLevel.PARTIAL) -> str:
    """Redact a key at the specified level."""
    if level == RedactionLevel.FULL:
        return "[REDACTED]"
    if level == RedactionLevel.HASH:
        h = hashlib.sha256(key.encode()).hexdigest()[:12]
        return f"[sha256:{h}]"
    # PARTIAL — default
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}...{key[-4:]}"
