"""Web GUI endpoint tests — focuses on the new metrics/stats/activity endpoints."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import urllib.request

import simple_web  # noqa: E402


class _WebServer:
    """Lightweight test harness for the simple_web server."""

    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.original_data_dir = simple_web.DATA_DIR
        simple_web.DATA_DIR = self.tmp
        self.server = simple_web.ThreadingHTTPServer(("127.0.0.1", 0), simple_web.Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.2)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def get(self, path: str) -> tuple[int, str, dict]:
        try:
            r = urllib.request.urlopen(self.url(path), timeout=3)
            body = r.read().decode("utf-8", errors="replace")
            return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace"), dict(e.headers)

    def post(self, path: str) -> tuple[int, str, dict]:
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(self.url(path), method="POST"),
                timeout=3,
            )
            return r.status, r.read().decode("utf-8", errors="replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace"), dict(e.headers)

    def stop(self):
        self.server.shutdown()
        simple_web.DATA_DIR = self.original_data_dir


@pytest.fixture()
def web():
    s = _WebServer()
    yield s
    s.stop()


class TestMetricsEndpoint:
    def test_returns_prometheus_content_type(self, web):
        status, _, headers = web.get("/api/metrics")
        assert status == 200
        ct = headers.get("Content-Type", "")
        assert "text/plain" in ct, f"Expected Prometheus text format, got {ct}"

    def test_returns_help_and_type_lines(self, web):
        status, body, _ = web.get("/api/metrics")
        assert status == 200
        # Prometheus exposition always starts with # HELP / # TYPE
        assert "# HELP" in body
        assert "# TYPE" in body

    def test_includes_request_counter(self, web):
        # Hit a few times
        for _ in range(3):
            web.get("/api/metrics")
        _, body, _ = web.get("/api/metrics")
        assert "check_please_http_requests_total" in body or "audit_valid_total" in body


class TestStatsEndpoint:
    def test_returns_cache_and_circuits(self, web):
        status, body, _ = web.get("/api/stats")
        assert status == 200
        data = json.loads(body)
        assert "cache" in data
        assert "circuits" in data
        assert "size" in data["cache"]
        assert "max_size" in data["cache"]
        assert "hits" in data["cache"]
        assert isinstance(data["circuits"], list)

    def test_cache_stats_are_zero_on_fresh(self, web):
        # Stats are process-global; reset before reading
        from credential_auditor.orchestrator import get_cache
        cache = get_cache()
        cache.stats.hits = 0
        cache.stats.misses = 0
        cache._store.clear()
        _, body, _ = web.get("/api/stats")
        data = json.loads(body)
        assert data["cache"]["size"] == 0
        assert data["cache"]["hits"] == 0
        assert data["cache"]["misses"] == 0


class TestActivityEndpoint:
    def test_returns_empty_when_no_log(self, web):
        status, body, _ = web.get("/api/activity")
        assert status == 200
        data = json.loads(body)
        assert "events" in data
        assert "count" in data
        assert data["count"] == 0
        assert data["events"] == []

    def test_reads_existing_log(self, web):
        log = web.tmp / "audit.log"
        log.write_text(
            json.dumps({"ts": "2026-01-01T00:00:00", "event": "audit_start"})
            + "\n"
            + json.dumps({"ts": "2026-01-01T00:00:01", "event": "audit_end"})
            + "\n"
        )
        _, body, _ = web.get("/api/activity")
        data = json.loads(body)
        assert data["count"] == 2
        # Newest first
        assert data["events"][0]["event"] == "audit_end"

    def test_skips_malformed_lines(self, web):
        log = web.tmp / "audit.log"
        log.write_text(
            json.dumps({"event": "a"})
            + "\nnot json\n"
            + json.dumps({"event": "b"})
            + "\n"
        )
        _, body, _ = web.get("/api/activity")
        data = json.loads(body)
        assert data["count"] == 2


class TestCachePurge:
    def test_purge_requires_auth(self, web):
        # Without session, should 401
        status, body, _ = web.post("/api/cache/purge")
        assert status == 401
        data = json.loads(body)
        assert "error" in data or "Unauthorized" in body or "token" in body.lower()


class TestExistingEndpoints:
    """Smoke test the other public endpoints still work after the enhancements."""

    def test_root_serves_html(self, web):
        status, body, headers = web.get("/")
        assert status == 200
        ct = headers.get("Content-Type", "")
        assert "html" in ct
        assert "Check Please" in body

    def test_account_status(self, web):
        status, body, _ = web.get("/api/account/status")
        assert status == 200
        data = json.loads(body)
        assert "exists" in data
        assert "users" in data

    def test_vault_strength(self, web):
        # /api/vault/strength is POST not GET
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(
                    web.url("/api/vault/strength"),
                    method="POST",
                    data=json.dumps({"password": "weak"}).encode(),
                    headers={"Content-Type": "application/json"},
                ),
                timeout=3,
            )
            status, body, _ = r.status, r.read().decode(), dict(r.headers)
        except urllib.error.HTTPError as e:
            status, body, _ = e.code, e.read().decode(), dict(e.headers)
        # Either success or auth-gated — both valid
        assert status in (200, 401)

    def test_self_test(self, web):
        # Self-test is session-gated; just confirm the route exists (not 404)
        status, _, _ = web.get("/api/self-test")
        assert status in (200, 401)
