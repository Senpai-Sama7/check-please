"""Performance regression suite.

Establishes performance baselines and alerts on >20% regression.
Tests measure end-to-end operations on synthetic inputs — no real network.
"""

from __future__ import annotations

import hashlib
import re
import time

import pytest

from credential_auditor.cache import ValidationCache
from credential_auditor.models import (
    AuditSummary,
    KeyFingerprint,
    KeyResult,
)
from credential_auditor.orchestrator import (
    _circuit_breakers,
    _record_circuit_result,
    _should_allow_request,
)
from credential_auditor.providers import (
    Provider,
    _literal_prefix_len,
    detect_provider_by_key,
    discover_providers,
)
from credential_auditor.security import RedactionLevel, redact_key


# ── KeyFingerprint performance ─────────────────────────────────────────────


class TestKeyFingerprintPerformance:
    def test_fingerprint_throughput(self):
        """KeyFingerprint.from_key should handle >= 10k ops/sec."""
        keys = [f"sk-{hashlib.sha256(str(i).encode()).hexdigest()}" for i in range(1000)]
        t0 = time.perf_counter()
        for k in keys:
            KeyFingerprint.from_key(k)
        elapsed = time.perf_counter() - t0
        ops_per_sec = len(keys) / elapsed
        # Baseline: 10k ops/sec; allow 20% regression margin = 8k
        assert ops_per_sec >= 8000, (
            f"KeyFingerprint.from_key throughput {ops_per_sec:.0f} ops/sec "
            f"< 8000 baseline"
        )

    def test_redaction_throughput(self):
        """redact_key should handle >= 20k ops/sec."""
        keys = [f"sk-{hashlib.sha256(str(i).encode()).hexdigest()[:40]}" for i in range(2000)]
        t0 = time.perf_counter()
        for k in keys:
            redact_key(k, RedactionLevel.PARTIAL)
        elapsed = time.perf_counter() - t0
        ops_per_sec = len(keys) / elapsed
        assert ops_per_sec >= 20_000, (
            f"redact_key throughput {ops_per_sec:.0f} ops/sec < 20000 baseline"
        )


# ── Cache performance ─────────────────────────────────────────────────────


class TestCachePerformance:
    def test_cache_put_get_throughput(self):
        """Cache put+get cycle should handle >= 5k ops/sec."""
        cache = ValidationCache(max_size=10_000)
        keys = [f"k{i}" for i in range(1000)]
        fp = KeyFingerprint.from_key("sk-test")
        result = KeyResult(
            provider="test", env_var="X", key_fingerprint=fp, status="valid",
        )
        t0 = time.perf_counter()
        for k in keys:
            cache.put("test", k, result)
        for k in keys:
            cache.get("test", k)
        elapsed = time.perf_counter() - t0
        ops_per_sec = (len(keys) * 2) / elapsed
        assert ops_per_sec >= 5_000, (
            f"Cache put+get throughput {ops_per_sec:.0f} ops/sec < 5000 baseline"
        )


# ── Provider auto-detect performance ──────────────────────────────────────


class TestProviderDetectPerformance:
    def test_detect_throughput(self):
        """detect_provider_by_key should handle >= 1k keys/sec."""
        discover_providers()
        keys = [
            f"sk-{hashlib.sha256(str(i).encode()).hexdigest()[:48]}"
            for i in range(500)
        ]
        t0 = time.perf_counter()
        for k in keys:
            detect_provider_by_key(k)
        elapsed = time.perf_counter() - t0
        ops_per_sec = len(keys) / elapsed
        assert ops_per_sec >= 1_000, (
            f"detect_provider_by_key throughput {ops_per_sec:.0f} ops/sec "
            f"< 1000 baseline"
        )


# ── Circuit breaker performance ────────────────────────────────────────────


class TestCircuitBreakerPerformance:
    def test_circuit_breaker_lookup_overhead(self):
        """Circuit breaker lookup should be < 10μs per call (in-memory dict)."""
        _circuit_breakers.clear()
        # Pre-populate with 100 providers
        for i in range(100):
            _circuit_breakers[f"provider_{i}"] = (0, 0.0, "closed")
        t0 = time.perf_counter()
        for _ in range(1000):
            _should_allow_request("provider_50")
        elapsed = time.perf_counter() - t0
        per_call_us = (elapsed / 1000) * 1_000_000
        assert per_call_us < 10.0, (
            f"Circuit breaker lookup {per_call_us:.2f}μs/call >= 10μs baseline"
        )

    def test_circuit_breaker_record_overhead(self):
        """Recording circuit results should be < 20μs per call."""
        _circuit_breakers.clear()
        t0 = time.perf_counter()
        for i in range(1000):
            _record_circuit_result(f"provider_{i % 10}", i % 2 == 0)
        elapsed = time.perf_counter() - t0
        per_call_us = (elapsed / 1000) * 1_000_000
        assert per_call_us < 20.0, (
            f"Circuit breaker record {per_call_us:.2f}μs/call >= 20μs baseline"
        )


# ── Regex performance ─────────────────────────────────────────────────────


class TestRegexPerformance:
    def test_env_pattern_match_throughput(self):
        """Provider env pattern matching should handle >= 5k ops/sec."""
        discover_providers()
        provider = Provider.get_provider("openai")
        test_names = [f"OPENAI_API_KEY_{i}" for i in range(1000)]
        t0 = time.perf_counter()
        for name in test_names:
            provider.matches_env_var(name)
        elapsed = time.perf_counter() - t0
        ops_per_sec = len(test_names) / elapsed
        assert ops_per_sec >= 5_000, (
            f"env pattern match {ops_per_sec:.0f} ops/sec < 5000 baseline"
        )

    def test_literal_prefix_len_throughput(self):
        """_literal_prefix_len should handle >= 50k ops/sec."""
        patterns = [
            r"^sk-ant-[A-Za-z0-9_-]{20,}$",
            r"^ghp_[A-Za-z0-9]{36}$",
            r"^sk-or-v1-[a-f0-9]{64}$",
            r"^nvapi-[A-Za-z0-9_-]{40,}$",
            r"^AIza[A-Za-z0-9_-]{35,60}$",
        ]
        t0 = time.perf_counter()
        for _ in range(1000):
            for p in patterns:
                _literal_prefix_len(p)
        elapsed = time.perf_counter() - t0
        total = len(patterns) * 1000
        ops_per_sec = total / elapsed
        assert ops_per_sec >= 50_000, (
            f"_literal_prefix_len {ops_per_sec:.0f} ops/sec < 50000 baseline"
        )


# ── End-to-end audit performance (mock) ───────────────────────────────────


class TestEndToEndPerformance:
    @pytest.mark.asyncio
    async def test_audit_50_keys_under_2s(self, tmp_path):
        """Audit 50 keys with mock transport should complete in < 2s."""
        import asyncio

        import httpx

        from credential_auditor.orchestrator import audit
        from credential_auditor.self_test import MockTransport

        env = tmp_path / ".env"
        # Write 50 keys (use numbering that matches provider regex)
        lines = []
        for i in range(50):
            lines.append(f"OPENAI_API_KEY=sk-{hashlib.sha256(str(i).encode()).hexdigest()[:48]}")
        env.write_text("\n".join(lines))

        transport = MockTransport({
            "api.openai.com": (200, {"data": []}, None),
        })
        # Patch the orchestrator's httpx client creation via monkey-patch
        import credential_auditor.orchestrator as orch

        original = httpx.AsyncClient

        def _mock_client(*args, **kwargs):
            kwargs["transport"] = transport
            return original(*args, **kwargs)

        orch.httpx.AsyncClient = _mock_client

        t0 = time.perf_counter()
        results = await audit(env, providers=["openai"], timeout=10)
        elapsed = time.perf_counter() - t0

        # Restore
        orch.httpx.AsyncClient = original

        # All 50 keys have the same env var name → deduplicated to 1 task
        # but auto-detect will pick them up. At minimum 1 result returned.
        assert len(results) >= 1
        assert elapsed < 2.0, f"Audit took {elapsed:.2f}s >= 2s baseline"
