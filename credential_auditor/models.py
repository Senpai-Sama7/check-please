"""Data models for credential audit results.

Design sources:
- Status as Literal (Qwen) — type-checker catches typos
- frozen dataclass (Claude/GPT) — immutable results
- Canonical field ordering via to_dict() (DeepSeek) — stable JSON (INV-5)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Literal, Optional

Status = Literal[
    "valid",
    "invalid_format",
    "auth_failed",
    "suspended_account",
    "quota_exhausted",
    "insufficient_scope",
    "network_error",
]

VALID_STATUSES: frozenset[str] = frozenset(Status.__args__)  # type: ignore[attr-defined]


@dataclass(frozen=True)
class KeyFingerprint:
    prefix: str
    suffix: str
    length: int

    @classmethod
    def from_key(cls, key: str) -> "KeyFingerprint":
        return cls(
            prefix=key[:4] if len(key) >= 4 else key,
            suffix=key[-4:] if len(key) >= 4 else "",
            length=len(key),
        )

    def to_dict(self) -> dict:
        return {"prefix": self.prefix, "suffix": self.suffix, "length": self.length}


@dataclass(frozen=True)
class RateLimitInfo:
    limit: int
    remaining: int
    reset_ts: int

    def to_dict(self) -> dict:
        return {"limit": self.limit, "remaining": self.remaining, "reset_ts": self.reset_ts}


@dataclass(frozen=True)
class KeyResult:
    """Immutable audit result with canonical 10-field ordering."""

    provider: str
    env_var: str
    key_fingerprint: KeyFingerprint
    status: Status
    account_info: Optional[str] = None
    scopes: Optional[list[str]] = field(default=None, hash=False)
    rate_limit: Optional[RateLimitInfo] = None
    usage_stats: Optional[dict] = field(default=None, hash=False)
    latency_ms: float = 0.0
    error_detail: Optional[str] = None

    def to_dict(self) -> dict:
        """Canonical field ordering per spec — INV-5."""
        return {
            "provider": self.provider,
            "env_var": self.env_var,
            "key_fingerprint": self.key_fingerprint.to_dict(),
            "status": self.status,
            "account_info": self.account_info,
            "scopes": self.scopes,
            "rate_limit": self.rate_limit.to_dict() if self.rate_limit else None,
            "usage_stats": self.usage_stats,
            "latency_ms": round(self.latency_ms, 2),
            "error_detail": self.error_detail,
        }
