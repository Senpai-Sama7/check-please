"""TUI helper function tests — non-interactive logic only."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

pytest.importorskip("textual")

from tui import (  # noqa: E402
    CIRCUIT_STYLES,
    STATUS_STYLES,
    CheckPleaseApp,
    ReportScreen,
    _load_audit_log_events,
)


class TestAppConfiguration:
    def test_all_screens_registered(self):
        """All 5 screens are registered in MODES."""
        expected = {"dashboard", "audit", "report", "metrics", "help"}
        assert expected.issubset(set(CheckPleaseApp.MODES.keys()))

    def test_default_mode_is_dashboard(self):
        assert CheckPleaseApp.DEFAULT_MODE == "dashboard"

    def test_all_statuses_have_styling(self):
        """All 7 valid statuses have TUI styling defined."""
        from credential_auditor.models import VALID_STATUSES

        for status in VALID_STATUSES:
            assert status in STATUS_STYLES, f"Missing TUI style for {status}"

    def test_circuit_states_have_styling(self):
        for state in ("closed", "open", "half_open"):
            assert state in CIRCUIT_STYLES


class TestActivityLogLoader:
    def test_missing_file_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr("tui.AUDIT_LOG_PATH", tmp_path / "nonexistent.log")
        assert _load_audit_log_events() == []

    def test_parses_valid_events(self, tmp_path, monkeypatch):
        log = tmp_path / "audit.log"
        events = [
            {"ts": "2026-01-01T00:00:00", "event": "audit_start"},
            {"ts": "2026-01-01T00:00:01", "event": "validate", "provider": "openai", "status": "valid"},
            {"ts": "2026-01-01T00:00:02", "event": "audit_end"},
        ]
        log.write_text("\n".join(json.dumps(e) for e in events))
        monkeypatch.setattr("tui.AUDIT_LOG_PATH", log)
        loaded = _load_audit_log_events()
        assert len(loaded) == 3
        # Most recent first
        assert loaded[0]["event"] == "audit_end"

    def test_skips_malformed_lines(self, tmp_path, monkeypatch):
        log = tmp_path / "audit.log"
        log.write_text('{"valid": true}\nnot json at all\n{"also": "valid"}\n')
        monkeypatch.setattr("tui.AUDIT_LOG_PATH", log)
        loaded = _load_audit_log_events()
        assert len(loaded) == 2

    def test_respects_limit(self, tmp_path, monkeypatch):
        log = tmp_path / "audit.log"
        events = [{"i": i} for i in range(100)]
        log.write_text("\n".join(json.dumps(e) for e in events))
        monkeypatch.setattr("tui.AUDIT_LOG_PATH", log)
        loaded = _load_audit_log_events(limit=10)
        assert len(loaded) == 10


class TestReportFilter:
    """Test the _filtered logic on ReportScreen (no UI needed)."""

    def _screen(self) -> ReportScreen:
        return ReportScreen()

    @pytest.fixture()
    def sample_data(self):
        return [
            {"provider": "openai", "env_var": "OPENAI_API_KEY", "status": "valid",
             "account_info": "5 models", "error_detail": None},
            {"provider": "github", "env_var": "GITHUB_TOKEN", "status": "auth_failed",
             "account_info": None, "error_detail": "Bad credentials"},
            {"provider": "openai", "env_var": "OPENAI_API_KEY_ALT1", "status": "network_error",
             "account_info": None, "error_detail": "timeout"},
            {"provider": "stripe", "env_var": "STRIPE_SECRET_KEY", "status": "valid",
             "account_info": "acct_123", "error_detail": None},
        ]

    def test_filter_by_search_query(self, sample_data):
        rs = self._screen()
        filtered = rs._filtered(sample_data, query="openai", filter_mode="all")
        assert len(filtered) == 2
        assert all(r["provider"] == "openai" for r in filtered)

    def test_filter_matches_account_info(self, sample_data):
        rs = self._screen()
        filtered = rs._filtered(sample_data, query="models", filter_mode="all")
        assert len(filtered) == 1
        assert filtered[0]["provider"] == "openai"

    def test_filter_matches_error_detail(self, sample_data):
        rs = self._screen()
        filtered = rs._filtered(sample_data, query="credentials", filter_mode="all")
        assert len(filtered) == 1
        assert filtered[0]["provider"] == "github"

    def test_filter_valid_only(self, sample_data):
        rs = self._screen()
        filtered = rs._filtered(sample_data, query="", filter_mode="valid")
        assert len(filtered) == 2
        assert all(r["status"] == "valid" for r in filtered)

    def test_filter_failed_only(self, sample_data):
        rs = self._screen()
        filtered = rs._filtered(sample_data, query="", filter_mode="failed")
        assert len(filtered) == 1
        assert filtered[0]["status"] == "auth_failed"

    def test_filter_errors_only(self, sample_data):
        rs = self._screen()
        filtered = rs._filtered(sample_data, query="", filter_mode="errors")
        assert len(filtered) == 1
        assert filtered[0]["status"] == "network_error"

    def test_filter_combined(self, sample_data):
        rs = self._screen()
        filtered = rs._filtered(sample_data, query="openai", filter_mode="valid")
        assert len(filtered) == 1
        assert filtered[0]["env_var"] == "OPENAI_API_KEY"

    def test_filter_empty_query_returns_all(self, sample_data):
        rs = self._screen()
        filtered = rs._filtered(sample_data, query="", filter_mode="all")
        assert len(filtered) == len(sample_data)

    def test_filter_no_matches(self, sample_data):
        rs = self._screen()
        filtered = rs._filtered(sample_data, query="zzz_nomatch", filter_mode="all")
        assert filtered == []
