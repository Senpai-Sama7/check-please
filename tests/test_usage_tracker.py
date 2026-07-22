"""Regression tests for agent_api usage tracker and auth helpers."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from agent_api import _UsageTracker, _parse_duration, hmac


class TestUsageTrackerNoDeadlock:
    def test_summary_does_not_deadlock(self, tmp_path):
        tracker = _UsageTracker(tmp_path)
        tracker.record_request("OPENAI_API_KEY", agent="test")
        tracker.record_tokens("OPENAI_API_KEY", 42, agent="test", model="gpt-test")

        result = {}
        error = {}

        def run():
            try:
                result["s"] = tracker.summary("OPENAI_API_KEY")
                result["all"] = tracker.summary()
            except Exception as exc:  # pragma: no cover
                error["e"] = exc

        th = threading.Thread(target=run)
        th.start()
        th.join(timeout=2.0)
        assert not th.is_alive(), "summary() deadlocked (non-reentrant Lock)"
        assert "e" not in error
        assert result["s"]["tokens"] == 42
        assert result["s"]["requests"] == 1
        assert "OPENAI_API_KEY" in result["all"]

    def test_rpm_window(self, tmp_path):
        tracker = _UsageTracker(tmp_path)
        for _ in range(5):
            tracker.record_request("K")
        assert tracker.get_rpm("K") == 5
        assert tracker.check_rpm("K", 5) is not None
        assert tracker.check_rpm("K", 10) is None


class TestParseDurationEdge:
    def test_empty(self):
        assert _parse_duration("") == 0

    def test_garbage(self):
        assert _parse_duration("nope") == 0
        assert _parse_duration("12") == 0


class TestHmacCompareAvailable:
    def test_module_exports_hmac(self):
        # agent_api imports hmac for constant-time bearer compares
        a = "token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        b = "token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        assert hmac.compare_digest(a, a) is True
        assert hmac.compare_digest(a, b) is False
