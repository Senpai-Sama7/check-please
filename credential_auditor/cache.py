"""TTL-based validation cache with hit/miss stats.

Ported from ultimate_credential_auditor's ValidationCache concept.
Prevents redundant API calls on repeated audit runs.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional

from credential_auditor.models import KeyResult


def _cache_key(provider: str, key: str) -> str:
    """Hash provider+key for cache lookup (never stores raw key)."""
    return hashlib.sha256(f"{provider}:{key}".encode()).hexdigest()[:16]


@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0

    @property
    def total(self) -> int:
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        return self.hits / self.total if self.total else 0.0

    def to_dict(self) -> dict:
        return {"hits": self.hits, "misses": self.misses, "hit_rate": round(self.hit_rate, 3)}


class ValidationCache:
    """In-memory TTL cache for KeyResult objects with size limit."""

    def __init__(self, ttl_seconds: int = 3600, max_size: int = 10_000):
        self.ttl = ttl_seconds
        self.max_size = max_size
        self._store: dict[str, tuple[KeyResult, float]] = {}
        self.stats = CacheStats()

    def get(self, provider: str, key: str) -> Optional[KeyResult]:
        ck = _cache_key(provider, key)
        entry = self._store.get(ck)
        if entry and (time.monotonic() - entry[1]) < self.ttl:
            self.stats.hits += 1
            return entry[0]
        if entry:
            del self._store[ck]
        self.stats.misses += 1
        return None

    def put(self, provider: str, key: str, result: KeyResult) -> None:
        if len(self._store) >= self.max_size:
            # Evict oldest entry
            oldest = min(self._store, key=lambda k: self._store[k][1])
            del self._store[oldest]
        self._store[_cache_key(provider, key)] = (result, time.monotonic())

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        return len(self._store)
