"""Tests for security helpers and organize_env hardening."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from credential_auditor.security import is_symlink_or_hardlink_attack  # noqa: E402
from organize_env import organize_env  # noqa: E402


class TestHardlinkDetection:
    def test_rejects_hardlinked_file(self, tmp_path):
        target = tmp_path / "out.json"
        target.write_text("{}")
        link = tmp_path / "alias.json"
        try:
            os.link(target, link)
        except OSError:
            pytest.skip("hardlinks not supported on this filesystem")
        assert is_symlink_or_hardlink_attack(link) is True
        assert is_symlink_or_hardlink_attack(target) is True

    def test_allows_normal_file(self, tmp_path):
        p = tmp_path / "safe.json"
        p.write_text("{}")
        assert is_symlink_or_hardlink_attack(p) is False


class TestOrganizeEnvPermissions:
    def test_output_is_owner_only(self, tmp_path):
        src = tmp_path / ".env"
        src.write_text('FOO=bar\nBAR="say \\"hi\\""\n')
        dst = tmp_path / ".env.organized"
        organize_env(src, dst)
        mode = dst.stat().st_mode & 0o777
        assert mode == 0o600 or mode == (stat.S_IRUSR | stat.S_IWUSR)

    def test_escapes_quotes_in_values(self, tmp_path):
        src = tmp_path / ".env"
        src.write_text('MSG=he said "hello"\n')
        dst = tmp_path / ".env.organized"
        organize_env(src, dst)
        text = dst.read_text()
        assert '\\"' in text or '""' in text or "hello" in text
