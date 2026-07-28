"""Property-based tests using hypothesis.

Falsifiable invariants verified across 100+ generated inputs.
Tests are gated behind `hypothesis` optional dev dep — skip if missing.
"""

from __future__ import annotations

import hashlib
import json

import pytest

# Skip entire module if hypothesis is not installed
hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings, strategies as st

from credential_auditor.cache import CacheStats, ValidationCache
from credential_auditor.models import (
    VALID_STATUSES,
    AuditSummary,
    KeyFingerprint,
    KeyResult,
    RateLimitInfo,
)
from credential_auditor.security import RedactionLevel, redact_key


# ── KeyFingerprint properties ──────────────────────────────────────────────


class TestKeyFingerprintProperties:
    @given(st.text(min_size=1, max_size=200))
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_length_matches_input(self, key: str) -> None:
        """INV: fingerprint.length == len(key) for any key."""
        fp = KeyFingerprint.from_key(key)
        assert fp.length == len(key)

    @given(st.text(min_size=4, max_size=200))
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_hash_is_stable(self, key: str) -> None:
        """INV: same key → same hash, never contains raw key."""
        fp1 = KeyFingerprint.from_key(key)
        fp2 = KeyFingerprint.from_key(key)
        assert fp1.key_hash == fp2.key_hash
        assert fp1.key_hash != ""
        # Hash should never leak the raw key
        assert key not in fp1.key_hash

    @given(st.text(min_size=4, max_size=200))
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_hash_matches_sha256_prefix(self, key: str) -> None:
        """INV: key_hash is first 16 hex chars of sha256(key)."""
        fp = KeyFingerprint.from_key(key)
        expected = hashlib.sha256(key.encode()).hexdigest()[:16]
        assert fp.key_hash == expected

    @given(st.text(min_size=8, max_size=200))
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_no_raw_key_in_any_redaction(self, key: str) -> None:
        """INV-4: for keys >= 8 chars, the full key never appears in any redaction."""
        fp = KeyFingerprint.from_key(key)
        for level in ("full", "hash"):
            d = fp.to_dict(level)
            serialized = json.dumps(d)
            assert key not in serialized, f"Raw key leaked in {level} redaction"

    @given(st.text(min_size=4, max_size=200))
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_partial_keeps_prefix_and_suffix(self, key: str) -> None:
        """INV: partial redaction preserves first 4 and last 4 chars."""
        fp = KeyFingerprint.from_key(key)
        d = fp.to_dict("partial")
        assert d["prefix"] == key[:4]
        assert d["suffix"] == key[-4:]

    @given(st.text(min_size=4, max_size=200))
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_full_redaction_never_leaks(self, key: str) -> None:
        """INV: full redaction returns [REDACTED] with only length."""
        fp = KeyFingerprint.from_key(key)
        d = fp.to_dict("full")
        assert d == {"redacted": "[REDACTED]", "length": len(key)}

    @given(st.text(min_size=4, max_size=200))
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_hash_redaction_uses_sha256_prefix(self, key: str) -> None:
        """INV: hash redaction uses 16-char sha256 prefix."""
        fp = KeyFingerprint.from_key(key)
        d = fp.to_dict("hash")
        expected_hash = hashlib.sha256(key.encode()).hexdigest()[:16]
        assert d == {"redacted": f"[sha256:{expected_hash}]", "length": len(key)}


# ── ValidationCache properties ─────────────────────────────────────────────


class TestValidationCacheProperties:
    @given(
        provider=st.text(min_size=1, max_size=32),
        key=st.text(min_size=1, max_size=64),
    )
    @settings(max_examples=100)
    def test_get_after_put_returns_same_result(self, provider: str, key: str) -> None:
        """INV: round-trip preserves result."""
        cache = ValidationCache()
        fp = KeyFingerprint.from_key(key)
        r = KeyResult(provider=provider, env_var="X", key_fingerprint=fp, status="valid")
        cache.put(provider, key, r)
        got = cache.get(provider, key)
        assert got is not None
        assert got.status == "valid"
        assert got.provider == provider

    @given(
        provider=st.text(min_size=1, max_size=32),
        key=st.text(min_size=1, max_size=64),
    )
    @settings(max_examples=100)
    def test_cache_stats_consistency(self, provider: str, key: str) -> None:
        """INV: hits + misses == total; hit_rate in [0, 1]."""
        cache = ValidationCache()
        cache.put(provider, key, KeyResult(
            provider=provider, env_var="X",
            key_fingerprint=KeyFingerprint.from_key(key), status="valid",
        ))
        # Miss first
        cache.get(provider, "different_key" + key)
        # Then hit
        cache.get(provider, key)
        s = cache.stats
        assert s.hits + s.misses == s.total
        assert 0.0 <= s.hit_rate <= 1.0

    @given(
        items=st.lists(
            st.tuples(
                st.text(min_size=1, max_size=8, alphabet=st.characters(max_codepoint=128, min_codepoint=33, categories=["Lu", "Ll", "Nd"])),
                st.text(min_size=1, max_size=32),
            ),
            min_size=1,
            max_size=50,
        ),
    )
    @settings(max_examples=50)
    def test_size_bounded_by_max_size(self, items: list) -> None:
        """INV: cache never exceeds max_size."""
        max_size = 5
        cache = ValidationCache(max_size=max_size)
        for i, (prov, key) in enumerate(items):
            cache.put(f"p{i % 3}", f"{key}_{i}", KeyResult(
                provider=f"p{i % 3}", env_var="X",
                key_fingerprint=KeyFingerprint.from_key(key), status="valid",
            ))
        assert len(cache) <= max_size

    def test_clear_resets_stats(self) -> None:
        """INV: clear() resets both store and stats."""
        cache = ValidationCache()
        cache.put("a", "b", KeyResult(
            provider="a", env_var="X",
            key_fingerprint=KeyFingerprint.from_key("b"), status="valid",
        ))
        cache.get("a", "b")
        assert cache.stats.hits >= 1
        cache.clear()
        assert len(cache) == 0
        assert cache.stats.hits == 0
        assert cache.stats.misses == 0


# ── RateLimitInfo properties ───────────────────────────────────────────────


class TestRateLimitInfoProperties:
    @given(
        limit=st.integers(min_value=0, max_value=1_000_000),
        remaining=st.integers(min_value=0, max_value=1_000_000),
        reset=st.integers(min_value=0, max_value=2_000_000_000),
    )
    def test_round_trip_preserves_values(self, limit: int, remaining: int, reset: int) -> None:
        rl = RateLimitInfo(limit=limit, remaining=remaining, reset_ts=reset)
        d = rl.to_dict()
        assert d == {"limit": limit, "remaining": remaining, "reset_ts": reset}
        # Round-trip via JSON
        j = json.dumps(d)
        d2 = json.loads(j)
        assert d2 == d


# ── KeyResult canonical ordering properties ─────────────────────────────────


class TestKeyResultCanonicalOrdering:
    @given(
        provider=st.text(min_size=1, max_size=16),
        env_var=st.text(min_size=1, max_size=64),
        status=st.sampled_from(list(VALID_STATUSES)),
    )
    @settings(max_examples=50)
    def test_to_dict_canonical_order(self, provider: str, env_var: str, status: str) -> None:
        """INV-5: field order is stable across calls."""
        fp = KeyFingerprint.from_key("sk-test")
        r = KeyResult(provider=provider, env_var=env_var, key_fingerprint=fp, status=status)
        expected_order = [
            "provider", "env_var", "key_fingerprint", "status", "account_info",
            "scopes", "rate_limit", "usage_stats", "latency_ms", "error_detail",
            "auto_detected",
        ]
        d1 = r.to_dict()
        d2 = r.to_dict()
        assert list(d1.keys()) == expected_order
        assert list(d2.keys()) == expected_order
        assert json.dumps(d1) == json.dumps(d2)


# ── AuditSummary properties ────────────────────────────────────────────────


class TestAuditSummaryProperties:
    @given(
        total=st.integers(min_value=0, max_value=10000),
        valid=st.integers(min_value=0, max_value=10000),
        failed=st.integers(min_value=0, max_value=10000),
        errors=st.integers(min_value=0, max_value=10000),
    )
    def test_avg_latency_zero_for_zero_keys(self, total: int, valid: int, failed: int, errors: int) -> None:
        s = AuditSummary(
            total_keys=total, valid=valid, failed=failed, errors=errors,
            providers_checked=0, providers_skipped=0,
            cache_hits=0, cache_misses=0, total_latency_ms=0.0, auto_detected=0,
        )
        d = s.to_dict()
        if total == 0:
            assert d["avg_latency_ms"] == 0


# ── redact_key properties ─────────────────────────────────────────────────


class TestRedactKeyProperties:
    @given(st.text(min_size=1, max_size=100))
    @settings(max_examples=200)
    def test_no_raw_key_in_redaction(self, key: str) -> None:
        """INV: raw key never appears in any redaction."""
        for level in RedactionLevel:
            redacted = redact_key(key, level)
            if len(key) > 8:  # only enforced for non-trivial keys
                # For partial: key prefix/suffix are visible — that's by design
                if level == RedactionLevel.PARTIAL:
                    # Only first 4 and last 4 are visible, not the full key
                    if len(key) > 12:
                        assert key[4:-4] not in redacted
                else:
                    assert key not in redacted

    @given(st.text(min_size=1, max_size=8))
    def test_short_keys_fully_masked_partial(self, key: str) -> None:
        """INV: keys <= 8 chars are fully masked in PARTIAL mode."""
        redacted = redact_key(key, RedactionLevel.PARTIAL)
        assert redacted == "*" * len(key)
