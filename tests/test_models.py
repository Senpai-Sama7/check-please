"""Tests for credential_auditor.models."""

import json

from credential_auditor.models import (
    AuditSummary,
    FAILING_STATUSES,
    KeyFingerprint,
    KeyResult,
    RateLimitInfo,
    VALID_STATUSES,
)


class TestKeyFingerprint:
    def test_from_key_normal(self):
        fp = KeyFingerprint.from_key("sk-abc123xyz")
        assert fp.prefix == "sk-a"
        assert fp.suffix == "3xyz"
        assert fp.length == 12

    def test_from_key_short(self):
        fp = KeyFingerprint.from_key("ab")
        assert fp.prefix == "ab"
        assert fp.suffix == ""
        assert fp.length == 2

    def test_from_key_exact_four(self):
        fp = KeyFingerprint.from_key("abcd")
        assert fp.prefix == "abcd"
        assert fp.suffix == "abcd"
        assert fp.length == 4

    def test_to_dict_partial(self):
        fp = KeyFingerprint(prefix="sk-a", suffix="xyz1", length=51)
        d = fp.to_dict("partial")
        assert d == {"prefix": "sk-a", "suffix": "xyz1", "length": 51}

    def test_to_dict_full_redaction(self):
        fp = KeyFingerprint(prefix="sk-a", suffix="xyz1", length=51)
        d = fp.to_dict("full")
        assert d == {"redacted": "[REDACTED]", "length": 51}
        assert "sk-a" not in str(d)

    def test_to_dict_hash_redaction(self):
        fp = KeyFingerprint(prefix="sk-a", suffix="xyz1", length=51)
        d = fp.to_dict("hash")
        assert d["redacted"].startswith("[sha256:")
        assert d["length"] == 51

    def test_frozen(self):
        fp = KeyFingerprint.from_key("test-key")
        try:
            fp.prefix = "x"  # type: ignore[misc]
            assert False, "Should be frozen"
        except AttributeError:
            pass


class TestKeyResult:
    def test_canonical_field_order(self):
        fp = KeyFingerprint(prefix="sk-t", suffix="xyz1", length=51)
        r = KeyResult(provider="openai", env_var="OPENAI_API_KEY",
                      key_fingerprint=fp, status="valid")
        keys = list(r.to_dict().keys())
        assert keys == [
            "provider", "env_var", "key_fingerprint", "status", "account_info",
            "scopes", "rate_limit", "usage_stats", "latency_ms", "error_detail",
            "auto_detected",
        ]

    def test_no_raw_key_in_output(self):
        raw = "sk-SUPERSECRETKEY1234567890abcdef"
        fp = KeyFingerprint.from_key(raw)
        r = KeyResult(provider="openai", env_var="OPENAI_API_KEY",
                      key_fingerprint=fp, status="valid")
        serialized = json.dumps(r.to_dict())
        assert raw not in serialized
        assert raw not in str(r)
        assert raw not in repr(r)

    def test_json_roundtrip_stable(self):
        fp = KeyFingerprint(prefix="sk-t", suffix="xyz1", length=51)
        r = KeyResult(provider="openai", env_var="K", key_fingerprint=fp,
                      status="valid", latency_ms=42.567)
        j1 = json.dumps(r.to_dict())
        j2 = json.dumps(r.to_dict())
        assert j1 == j2

    def test_latency_rounded(self):
        fp = KeyFingerprint(prefix="a", suffix="b", length=5)
        r = KeyResult(provider="x", env_var="Y", key_fingerprint=fp,
                      status="valid", latency_ms=1.23456789)
        assert r.to_dict()["latency_ms"] == 1.23


class TestAuditSummary:
    def test_avg_latency(self):
        s = AuditSummary(total_keys=4, valid=3, failed=1, errors=0,
                         providers_checked=2, providers_skipped=0,
                         cache_hits=1, cache_misses=3,
                         total_latency_ms=400.0, auto_detected=1)
        assert s.to_dict()["avg_latency_ms"] == 100.0

    def test_avg_latency_zero_keys(self):
        s = AuditSummary(total_keys=0, valid=0, failed=0, errors=0,
                         providers_checked=0, providers_skipped=0,
                         cache_hits=0, cache_misses=0,
                         total_latency_ms=0, auto_detected=0)
        assert s.to_dict()["avg_latency_ms"] == 0


class TestStatusSets:
    def test_valid_statuses_count(self):
        assert len(VALID_STATUSES) == 7

    def test_failing_subset(self):
        assert FAILING_STATUSES.issubset(VALID_STATUSES)

    def test_valid_not_in_failing(self):
        assert "valid" not in FAILING_STATUSES

    def test_expected_failing(self):
        assert FAILING_STATUSES == {
            "auth_failed", "suspended_account",
            "quota_exhausted", "insufficient_scope",
        }
