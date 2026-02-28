"""Provider ABC with __init_subclass__ auto-registration.

Design sources:
- __init_subclass__ registry (Kimi/Qwen) — zero-touch provider addition (INV-6)
- ABC with @abstractmethod (all Tier 1-2 variants)
- Shared httpx.AsyncClient passed in (Claude)
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar, Optional

import httpx

from credential_auditor.models import (
    KeyFingerprint,
    KeyResult,
    RateLimitInfo,
    Status,
)


class Provider(ABC):
    """Base class for all credential providers.

    Subclasses auto-register by defining `name` as a class variable.
    Adding a new provider requires only creating a new file with a Provider
    subclass — no orchestration changes needed (INV-6).
    """

    _registry: ClassVar[dict[str, type["Provider"]]] = {}

    # Subclasses MUST define these
    name: ClassVar[str]
    env_patterns: ClassVar[list[re.Pattern]]
    key_format: ClassVar[re.Pattern]

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "name") and cls.name:
            Provider._registry[cls.name] = cls

    @classmethod
    def get_registry(cls) -> dict[str, type["Provider"]]:
        return dict(cls._registry)

    @classmethod
    def get_provider(cls, name: str) -> "Provider":
        if name not in cls._registry:
            raise ValueError(f"Unknown provider: {name}. Available: {list(cls._registry)}")
        return cls._registry[name]()

    def matches_env_var(self, env_var: str) -> bool:
        return any(p.match(env_var) for p in self.env_patterns)

    def check_format(self, key: str) -> tuple[bool, Optional[str]]:
        """Validate key format without network. Returns (ok, error_msg)."""
        if not self.key_format.match(key):
            return False, f"Key does not match expected {self.name} format"
        return True, None

    @abstractmethod
    async def validate(self, key: str, client: httpx.AsyncClient) -> tuple[
        Status, Optional[str], Optional[list[str]], Optional[RateLimitInfo],
        Optional[dict], Optional[str]
    ]:
        """Validate key via network. Returns (status, account_info, scopes, rate_limit, usage_stats, error_detail)."""
        ...

    async def check_key(self, env_var: str, key: str, client: httpx.AsyncClient) -> KeyResult:
        """Full check: format validation → network validation → KeyResult."""
        fingerprint = KeyFingerprint.from_key(key)
        fmt_ok, fmt_err = self.check_format(key)
        if not fmt_ok:
            return KeyResult(
                provider=self.name, env_var=env_var, key_fingerprint=fingerprint,
                status="invalid_format", error_detail=fmt_err,
            )
        start = time.monotonic()
        try:
            status, account, scopes, rate_limit, usage, error = await self.validate(key, client)
        except (httpx.HTTPError, OSError, Exception) as exc:
            latency = (time.monotonic() - start) * 1000
            return KeyResult(
                provider=self.name, env_var=env_var, key_fingerprint=fingerprint,
                status="network_error", latency_ms=latency,
                error_detail=f"{type(exc).__name__}: {exc}",
            )
        latency = (time.monotonic() - start) * 1000
        return KeyResult(
            provider=self.name, env_var=env_var, key_fingerprint=fingerprint,
            status=status, account_info=account, scopes=scopes,
            rate_limit=rate_limit, usage_stats=usage, latency_ms=latency,
            error_detail=error,
        )


def _extract_rate_limit(response: httpx.Response, prefix: str = "x-ratelimit") -> Optional[RateLimitInfo]:
    """Common rate-limit header extraction used by multiple providers."""
    try:
        limit = int(response.headers.get(f"{prefix}-limit", 0))
        remaining = int(response.headers.get(f"{prefix}-remaining", 0))
        reset = int(response.headers.get(f"{prefix}-reset", 0))
        if limit == 0 and remaining == 0:
            return None
        # Some providers return epoch, others return seconds-until-reset
        if reset < 1_000_000_000:
            reset = int(time.time()) + reset
        return RateLimitInfo(limit=limit, remaining=remaining, reset_ts=reset)
    except (TypeError, ValueError):
        return None


def discover_providers() -> None:
    """Import all provider modules in this package to trigger __init_subclass__ registration."""
    package_dir = Path(__file__).parent
    for info in pkgutil.iter_modules([str(package_dir)]):
        if info.name.startswith("_"):
            continue
        importlib.import_module(f"credential_auditor.providers.{info.name}")
