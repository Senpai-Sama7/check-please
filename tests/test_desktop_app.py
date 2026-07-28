"""Desktop app window state persistence tests."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import desktop_app  # noqa: E402


class TestWindowStateRoundTrip:
    def test_defaults_when_no_file(self, tmp_path):
        fake = tmp_path / "window.json"
        with patch.object(desktop_app, "_window_state_path", return_value=fake):
            s = desktop_app._load_window_state()
            assert s == {"width": 1100, "height": 800, "x": None, "y": None}

    def test_save_then_load(self, tmp_path):
        fake = tmp_path / "window.json"
        with patch.object(desktop_app, "_window_state_path", return_value=fake):
            desktop_app._save_window_state({"width": 1300, "height": 950, "x": 50, "y": 75})
            s = desktop_app._load_window_state()
            assert s == {"width": 1300, "height": 950, "x": 50, "y": 75}

    def test_out_of_bounds_resets(self, tmp_path):
        fake = tmp_path / "window.json"
        with patch.object(desktop_app, "_window_state_path", return_value=fake):
            fake.write_text(json.dumps({"width": 5, "height": 5, "x": 0, "y": 0}))
            s = desktop_app._load_window_state()
            assert s["width"] == 1100
            assert s["height"] == 800
            fake.write_text(json.dumps({"width": 99999, "height": 99999}))
            s = desktop_app._load_window_state()
            assert s["width"] == 1100
            assert s["height"] == 800

    def test_corrupt_json_returns_defaults(self, tmp_path):
        fake = tmp_path / "window.json"
        fake.write_text("not valid json {{{")
        with patch.object(desktop_app, "_window_state_path", return_value=fake):
            s = desktop_app._load_window_state()
            assert s == {"width": 1100, "height": 800, "x": None, "y": None}

    def test_non_dict_json_returns_defaults(self, tmp_path):
        fake = tmp_path / "window.json"
        fake.write_text('"a string"')
        with patch.object(desktop_app, "_window_state_path", return_value=fake):
            s = desktop_app._load_window_state()
            assert s == {"width": 1100, "height": 800, "x": None, "y": None}

    def test_save_swallows_oserror(self, tmp_path):
        ro = tmp_path / "ro"
        ro.mkdir()
        os.chmod(ro, 0o555)
        bad = ro / "subdir" / "window.json"
        with patch.object(desktop_app, "_window_state_path", return_value=bad):
            desktop_app._save_window_state({"width": 800, "height": 600, "x": 0, "y": 0})
        os.chmod(ro, 0o755)

    def test_save_sets_600_perms_when_possible(self, tmp_path):
        fake = tmp_path / "window.json"
        with patch.object(desktop_app, "_window_state_path", return_value=fake):
            desktop_app._save_window_state({"width": 1200, "height": 800, "x": None, "y": None})
            mode = fake.stat().st_mode & 0o777
            assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"


class TestVersion:
    def test_version_string(self):
        assert isinstance(desktop_app.__version__, str)
        assert desktop_app.__version__ == "1.1.1"
