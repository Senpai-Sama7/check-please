"""CLI shell completion tests.

Falsifiable: --completion flag outputs valid shell completion scripts for bash/zsh/fish.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "credential_auditor", *args],
        capture_output=True,
        text=True,
        cwd=str(REPO),
        timeout=10,
    )


class TestShellCompletion:
    def test_bash_completion_outputs_script(self):
        """--completion bash outputs a valid bash completion script."""
        result = _run_cli("--completion", "bash")
        assert result.returncode == 0
        assert "_check_please()" in result.stdout
        assert "complete -F" in result.stdout
        assert "--env" in result.stdout
        assert "--provider" in result.stdout
        assert "--version" in result.stdout

    def test_zsh_completion_outputs_script(self):
        """--completion zsh outputs a valid zsh completion script."""
        result = _run_cli("--completion", "zsh")
        assert result.returncode == 0
        assert "#compdef" in result.stdout
        assert "_check_please" in result.stdout
        assert "--env" in result.stdout
        assert "--redaction-level" in result.stdout

    def test_fish_completion_outputs_script(self):
        """--completion fish outputs a valid fish completion script."""
        result = _run_cli("--completion", "fish")
        assert result.returncode == 0
        assert "complete -c check-please" in result.stdout
        # Fish uses -l long option format
        assert "-l env" in result.stdout
        assert "-l redaction-level" in result.stdout
        assert "bash zsh fish" in result.stdout

    def test_completion_all_shells_have_all_options(self):
        """All completion scripts document every CLI option."""
        for shell in ("bash", "zsh", "fish"):
            result = _run_cli("--completion", shell)
            for opt in ("--env", "--provider", "--output", "--json", "--quiet",
                        "--dry-run", "--list-providers", "--self-test", "--version"):
                # Fish uses -l long format
                search = opt.replace("--", "-l ") if shell == "fish" else opt
                assert search in result.stdout, f"{opt} missing from {shell} completion"

    def test_completion_exits_cleanly(self):
        """--completion exits with code 0 and no stderr output."""
        for shell in ("bash", "zsh", "fish"):
            result = _run_cli("--completion", shell)
            assert result.returncode == 0
            assert result.stderr == "", f"Unexpected stderr for {shell}: {result.stderr}"
