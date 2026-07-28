"""Metrics tests — Prometheus exposition format and /metrics endpoint."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait(url: str, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=0.3)
            return True
        except urllib.error.HTTPError:
            return True
        except Exception:
            time.sleep(0.05)
    return False


class TestMetricsFormat:
    """Validate Prometheus text exposition format from metrics module."""

    def test_render_metrics_returns_text(self):
        from credential_auditor.metrics import render_metrics

        output = render_metrics()
        assert isinstance(output, str)
        assert output.endswith("\n")
        # Each metric should have HELP and TYPE lines
        assert "# HELP " in output
        assert "# TYPE " in output

    def test_counter_increments(self):
        from credential_auditor.metrics import REGISTRY

        c = REGISTRY.counter("test_counter_increment", "test")
        before = c.value
        c.inc()
        assert c.value == before + 1
        c.inc(5)
        assert c.value == before + 6

    def test_gauge_set_inc_dec(self):
        from credential_auditor.metrics import REGISTRY

        g = REGISTRY.gauge("test_gauge_ops", "test")
        g.set(10)
        assert g.value == 10
        g.inc(5)
        assert g.value == 15
        g.dec(3)
        assert g.value == 12

    def test_histogram_observe(self):
        from credential_auditor.metrics import REGISTRY

        h = REGISTRY.histogram("test_histogram_observe", "test")
        h.observe(0.1)
        h.observe(1.0)
        h.observe(100.0)
        assert h.count == 3
        # 100 > all buckets → only +Inf bucket
        assert h.cumulative_count(float("inf")) == 3
        # 0.1 ≤ 0.1, 0.1 ≤ 0.25, ..., 0.1 ≤ 10.0
        assert h.cumulative_count(10.0) == 2  # 0.1 and 1.0

    def test_render_includes_all_metric_types(self):
        from credential_auditor.metrics import (
            REGISTRY,
            render_metrics,
        )

        c = REGISTRY.counter("test_render_counter", "test")
        c.inc()
        g = REGISTRY.gauge("test_render_gauge", "test")
        g.set(42)
        h = REGISTRY.histogram("test_render_histogram", "test")
        h.observe(0.5)
        output = render_metrics()
        assert "test_render_counter " in output
        assert "test_render_gauge 42" in output
        assert "test_render_histogram_bucket" in output
        assert 'le="+Inf"' in output


class TestMetricsEndpoint:
    """Validate /metrics HTTP endpoint in agent_api."""

    @pytest.fixture()
    def server(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("OPENAI_API_KEY=sk-test\n")
        perms = tmp_path / ".check_please_agent_permissions.json"
        perms.write_text(json.dumps({"allowed": ["OPENAI_API_KEY"]}))
        port = _free_port()
        proc = subprocess.Popen(
            [sys.executable, str(REPO / "agent_api.py"), "--serve", "--quiet", str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(tmp_path),
        )
        url = f"http://127.0.0.1:{port}"
        if not _wait(url + "/health"):
            proc.kill()
            pytest.fail("Server did not start")
        token = (tmp_path / ".check_please_agent_token").read_text().strip()
        yield url, token
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    def test_metrics_endpoint_returns_prometheus_format(self, server):
        url, token = server
        req = urllib.request.Request(
            url + "/metrics",
            headers={"Authorization": f"Bearer {token}"},
        )
        resp = urllib.request.urlopen(req, timeout=5)
        assert resp.status == 200
        assert "text/plain" in resp.headers.get("Content-Type", "")
        body = resp.read().decode()
        assert "# HELP " in body
        assert "# TYPE " in body

    def test_metrics_endpoint_includes_core_metrics(self, server):
        url, token = server
        req = urllib.request.Request(
            url + "/metrics",
            headers={"Authorization": f"Bearer {token}"},
        )
        body = urllib.request.urlopen(req, timeout=5).read().decode()
        # Core metrics should be present
        assert "check_please_http_requests_total" in body
        assert "check_please_audits_total" in body

    def test_metrics_endpoint_requires_auth(self, server):
        url, _ = server
        req = urllib.request.Request(url + "/metrics")
        try:
            urllib.request.urlopen(req, timeout=5)
            pytest.fail("Expected 401 for unauthenticated /metrics")
        except urllib.error.HTTPError as e:
            assert e.code == 401
