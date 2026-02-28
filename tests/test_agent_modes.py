"""Integration tests for agent_api.py modes: --export, --env, --write-env, --mcp."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

AGENT_API = Path(__file__).resolve().parent.parent / "agent_api.py"
PYTHON = sys.executable


@pytest.fixture()
def env_dir(tmp_path):
    """Create a temp dir with .env and permissions file."""
    env_file = tmp_path / ".env"
    env_file.write_text("TEST_KEY_A=value_a\nTEST_KEY_B=value_b\nTEST_KEY_C=value_c\n")
    perms = tmp_path / ".check_please_agent_permissions.json"
    perms.write_text(json.dumps({"allowed": ["TEST_KEY_A", "TEST_KEY_B"]}))
    return tmp_path


def _run(args, env_dir, **kwargs):
    """Run agent_api.py with given args, cwd=env_dir."""
    return subprocess.run(
        [PYTHON, str(AGENT_API)] + args,
        capture_output=True, text=True, cwd=str(env_dir), timeout=10, **kwargs,
    )


# ── --export ──

class TestExport:
    def test_prints_allowed_only(self, env_dir):
        r = _run(["--export"], env_dir)
        assert r.returncode == 0
        lines = r.stdout.strip().splitlines()
        keys = [l.split("=")[0].replace("export ", "") for l in lines]
        assert sorted(keys) == ["TEST_KEY_A", "TEST_KEY_B"]
        assert "TEST_KEY_C" not in r.stdout

    def test_values_correct(self, env_dir):
        r = _run(["--export"], env_dir)
        assert "value_a" in r.stdout
        assert "value_b" in r.stdout
        assert "value_c" not in r.stdout


# ── --env ──

class TestEnv:
    def test_injects_into_subprocess(self, env_dir):
        r = _run(["--env", "env"], env_dir)
        assert r.returncode == 0
        env_lines = {l.split("=", 1)[0]: l.split("=", 1)[1]
                     for l in r.stdout.splitlines() if "=" in l}
        assert env_lines.get("TEST_KEY_A") == "value_a"
        assert env_lines.get("TEST_KEY_B") == "value_b"
        assert "TEST_KEY_C" not in env_lines

    def test_missing_command_exits_2(self, env_dir):
        r = _run(["--env"], env_dir)
        assert r.returncode == 2


# ── --write-env ──

class TestWriteEnv:
    def test_writes_file(self, env_dir):
        out = env_dir / "agent.env"
        r = _run(["--write-env", str(out)], env_dir)
        assert r.returncode == 0
        assert out.exists()
        content = out.read_text()
        assert "TEST_KEY_A=value_a\n" in content
        assert "TEST_KEY_B=value_b\n" in content
        assert "TEST_KEY_C" not in content

    def test_file_permissions(self, env_dir):
        out = env_dir / "agent.env"
        _run(["--write-env", str(out)], env_dir)
        assert oct(out.stat().st_mode & 0o777) == "0o600"

    def test_missing_path_exits_2(self, env_dir):
        r = _run(["--write-env"], env_dir)
        assert r.returncode == 2


# ── --mcp ──

class TestMCP:
    def _mcp_session(self, env_dir, messages):
        """Send a sequence of JSON-RPC messages, return responses."""
        proc = subprocess.Popen(
            [PYTHON, str(AGENT_API), "--mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=str(env_dir),
        )
        responses = []
        for msg in messages:
            body = json.dumps(msg)
            proc.stdin.write(f"Content-Length: {len(body)}\r\n\r\n{body}")
            proc.stdin.flush()
            header = proc.stdout.readline().strip()
            length = int(header.split(":")[1].strip())
            proc.stdout.readline()  # blank line
            responses.append(json.loads(proc.stdout.read(length)))
        proc.terminate()
        return responses

    def test_initialize(self, env_dir):
        r = self._mcp_session(env_dir, [
            {"jsonrpc": "2.0", "method": "initialize", "id": 1,
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "test"}}},
        ])
        assert r[0]["result"]["serverInfo"]["name"] == "check_please"

    def test_list_and_get(self, env_dir):
        init = {"jsonrpc": "2.0", "method": "initialize", "id": 1,
                "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                           "clientInfo": {"name": "test"}}}
        r = self._mcp_session(env_dir, [
            init,
            {"jsonrpc": "2.0", "method": "tools/list", "id": 2},
            {"jsonrpc": "2.0", "method": "tools/call", "id": 3,
             "params": {"name": "list_credentials", "arguments": {}}},
            {"jsonrpc": "2.0", "method": "tools/call", "id": 4,
             "params": {"name": "get_credential", "arguments": {"name": "TEST_KEY_A"}}},
            {"jsonrpc": "2.0", "method": "tools/call", "id": 5,
             "params": {"name": "get_credential", "arguments": {"name": "TEST_KEY_C"}}},
        ])
        # tools/list
        tool_names = [t["name"] for t in r[1]["result"]["tools"]]
        assert "get_credential" in tool_names
        assert "list_credentials" in tool_names
        # list_credentials
        creds = json.loads(r[2]["result"]["content"][0]["text"])
        assert sorted(creds) == ["TEST_KEY_A", "TEST_KEY_B"]
        # get allowed
        assert r[3]["result"]["content"][0]["text"] == "value_a"
        # get denied
        assert "denied" in r[4]["result"]["content"][0]["text"].lower()
