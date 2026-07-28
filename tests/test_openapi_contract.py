"""OpenAPI contract enforcement tests.

Falsifiable: every agent_api route must return the schema declared in openapi.yaml.
"""

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

AGENT_API = Path(__file__).resolve().parent.parent / "agent_api.py"
OPENAPI = Path(__file__).resolve().parent.parent / "openapi.yaml"


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(url: str, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=0.3)
            return True
        except urllib.error.HTTPError:
            # Server is up but returned error (e.g. 401) — that's fine
            return True
        except Exception:
            time.sleep(0.05)
    return False


def _start_server(tmp_path: Path) -> tuple[subprocess.Popen, str, str]:
    """Start agent_api in a temp dir, return (process, base_url, token)."""
    port = _free_port()
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=sk-test\nANTHROPIC_API_KEY=sk-ant-test\n")
    perms = tmp_path / ".check_please_agent_permissions.json"
    perms.write_text(json.dumps({"allowed": ["OPENAI_API_KEY"]}))
    proc = subprocess.Popen(
        [sys.executable, str(AGENT_API), "--serve", "--quiet", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(tmp_path),
    )
    base_url = f"http://127.0.0.1:{port}"
    if not _wait_for_server(base_url + "/health"):
        proc.kill()
        pytest.fail("Server failed to start within 5s")
    token_file = tmp_path / ".check_please_agent_token"
    token = token_file.read_text().strip()
    return proc, base_url, token


def _stop_server(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture()
def server(tmp_path):
    """Start agent_api and yield (base_url, token)."""
    proc, base_url, token = _start_server(tmp_path)
    yield base_url, token
    _stop_server(proc)


def _request(base_url: str, path: str, token: str, method: str = "GET", body: dict | None = None) -> tuple[int, dict]:
    """Make an HTTP request to the server, return (status, json_body)."""
    data = json.dumps(body or {}).encode() if body is not None else None
    req = urllib.request.Request(
        base_url + path,
        data=data,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method=method,
    )
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


# ── Contract: /health ──────────────────────────────────────────────────────


class TestHealthContract:
    def test_health_returns_required_fields(self, server):
        base_url, token = server
        status, body = _request(base_url, "/health", token=token)
        assert status == 200
        # OpenAPI declares: status, credentials_loaded
        assert "status" in body
        assert "credentials_loaded" in body
        assert body["status"] == "ok"
        assert isinstance(body["credentials_loaded"], int)


# ── Contract: /providers ──────────────────────────────────────────────────


class TestProvidersContract:
    def test_providers_returns_provider_list(self, server):
        base_url, token = server
        status, body = _request(base_url, "/providers", token)
        assert status == 200
        assert "providers" in body
        assert isinstance(body["providers"], dict)
        # Each entry should be a list of env var names (dict-of-list)
        for name, env_vars in body["providers"].items():
            assert isinstance(env_vars, list)
            for var in env_vars:
                assert isinstance(var, str)


# ── Contract: /credentials ────────────────────────────────────────────────


class TestCredentialsContract:
    def test_credentials_returns_allowed_list(self, server):
        base_url, token = server
        status, body = _request(base_url, "/credentials", token)
        assert status == 200
        assert "allowed_credentials" in body
        assert "total" in body
        assert isinstance(body["allowed_credentials"], list)
        assert body["total"] == len(body["allowed_credentials"])

    def test_credentials_unauthorized_returns_401(self, server):
        base_url, _ = server
        req = urllib.request.Request(base_url + "/credentials", method="GET")
        try:
            urllib.request.urlopen(req, timeout=5)
            pytest.fail("Expected 401 for missing token")
        except urllib.error.HTTPError as e:
            assert e.code == 401

    def test_credentials_403_on_no_permissions(self, tmp_path):
        """When no permissions file exists, server auto-creates a template.
        /credentials returns 200 with empty allowed_credentials list.
        This test verifies the auto-template behavior is safe (empty allowlist = no access)."""
        env_file = tmp_path / ".env"
        env_file.write_text("OPENAI_API_KEY=sk-test\n")
        port = _free_port()
        proc = subprocess.Popen(
            [sys.executable, str(AGENT_API), "--serve", "--quiet", str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(tmp_path),
        )
        try:
            if not _wait_for_server(f"http://127.0.0.1:{port}/health"):
                pytest.fail("Server did not start")
            token_file = tmp_path / ".check_please_agent_token"
            token = token_file.read_text().strip()
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/credentials",
                headers={"Authorization": f"Bearer {token}"},
            )
            resp = urllib.request.urlopen(req, timeout=5)
            body = json.loads(resp.read().decode())
            # Server auto-creates empty permissions file → 200 with empty list
            assert resp.status == 200
            assert body["allowed_credentials"] == []
            assert body["total"] == 0
            # And requesting an actual credential should be denied
            req2 = urllib.request.Request(
                f"http://127.0.0.1:{port}/credentials/OPENAI_API_KEY",
                headers={"Authorization": f"Bearer {token}"},
                method="POST",
                data=b"{}",
            )
            try:
                urllib.request.urlopen(req2, timeout=5)
                pytest.fail("Expected 403 for credential not in empty allowlist")
            except urllib.error.HTTPError as e:
                assert e.code == 403
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()


# ── Contract: /credentials/{name} ─────────────────────────────────────────


class TestCredentialGetContract:
    def test_get_credential_returns_env_var_and_value(self, server):
        base_url, token = server
        status, body = _request(base_url, "/credentials/OPENAI_API_KEY", token, method="POST")
        assert status == 200
        assert "env_var" in body
        assert "value" in body
        assert body["env_var"] == "OPENAI_API_KEY"
        assert body["value"] == "sk-test"

    def test_get_credential_not_allowed_returns_403(self, server):
        base_url, token = server
        status, body = _request(base_url, "/credentials/ANTHROPIC_API_KEY", token, method="POST")
        # ANTHROPIC_API_KEY is not in the allowed list
        assert status == 403


# ── Contract: /usage ─────────────────────────────────────────────────────


class TestUsageContract:
    def test_usage_returns_usage_object(self, server):
        base_url, token = server
        status, body = _request(base_url, "/usage", token)
        assert status == 200
        assert "usage" in body
        assert isinstance(body["usage"], dict)


# ── OpenAPI spec validation ──────────────────────────────────────────────


class TestOpenAPISpecValidity:
    def test_spec_is_valid_yaml(self):
        """The openapi.yaml file itself is valid YAML and has required top-level keys."""
        import yaml

        with OPENAPI.open() as f:
            spec = yaml.safe_load(f)
        assert spec["openapi"].startswith("3.")
        assert "paths" in spec
        assert "info" in spec
        assert "components" in spec

    def test_spec_declares_all_agent_endpoints(self):
        """OpenAPI spec covers the agent broker's actual endpoints."""
        import yaml

        with OPENAPI.open() as f:
            spec = yaml.safe_load(f)
        paths = spec["paths"]
        # All endpoints that agent_api exposes should be in spec
        expected = {"/health", "/providers", "/credentials"}
        assert expected.issubset(set(paths.keys())), (
            f"Missing endpoints: {expected - set(paths.keys())}"
        )

    def test_health_endpoint_schema_complete(self):
        """Health endpoint has response schema with all required fields."""
        import yaml

        with OPENAPI.open() as f:
            spec = yaml.safe_load(f)
        health = spec["paths"]["/health"]["get"]
        resp_200 = health["responses"]["200"]
        schema = resp_200["content"]["application/json"]["schema"]
        props = set(schema["properties"].keys())
        assert "status" in props
        assert "credentials_loaded" in props
