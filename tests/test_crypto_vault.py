"""Tests for web vault crypto (v1/v2) and recovery key hardening."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import simple_web as sw  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_session(tmp_path, monkeypatch):
    """Point vault/account dirs at a temp location and clear session state."""
    monkeypatch.setattr(sw, "DATA_DIR", tmp_path)
    monkeypatch.setattr(sw, "ACCOUNTS_DIR", tmp_path / ".accounts")
    monkeypatch.setattr(sw, "VAULTS_DIR", tmp_path / ".vaults")
    sw._clear_session()
    yield
    sw._clear_session()


class TestCryptoV2:
    def test_roundtrip(self):
        blob = sw._encrypt("hello secret", "password123")
        assert blob["v"] == 2
        assert "nonce" in blob
        assert sw._decrypt(blob, "password123") == "hello secret"

    def test_wrong_password_fails(self):
        blob = sw._encrypt("hello secret", "password123")
        assert sw._decrypt(blob, "wrong-password") is None

    def test_tampered_ciphertext_fails(self):
        blob = sw._encrypt("hello secret", "password123")
        ct = bytearray(bytes.fromhex(blob["ct"]))
        ct[0] ^= 0xFF
        blob["ct"] = ct.hex()
        assert sw._decrypt(blob, "password123") is None

    def test_v1_legacy_still_decrypts(self):
        """Accounts encrypted with the old PBKDF2-stream construction must still open."""
        passkey = "legacy-pass"
        salt = b"\x01" * 16
        key = hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt, 200_000)
        pt = b"check_please_ok"
        stream = hashlib.pbkdf2_hmac("sha256", key, salt + b"stream", 1, dklen=len(pt))
        ct = bytes(a ^ b for a, b in zip(pt, stream))
        import hmac
        mac = hmac.new(key, ct, "sha256").hexdigest()
        blob = {"salt": salt.hex(), "ct": ct.hex(), "mac": mac, "v": 1}
        assert sw._decrypt(blob, passkey) == "check_please_ok"


class TestVaultAtRest:
    def test_plaintext_legacy_loads(self):
        sw._current_user = "alice"
        vf = sw._vault_path("alice")
        vf.parent.mkdir(parents=True, exist_ok=True)
        entries = [{"id": "1", "site": "example.com", "password": "p"}]
        vf.write_text(json.dumps(entries))
        assert sw._load_vault() == entries

    def test_encrypted_roundtrip(self):
        sw._current_user = "bob"
        sw._session_passkey = "supersecret"
        entries = [{"id": "abc", "site": "x.com", "password": "hunter2"}]
        sw._save_vault(entries)
        raw = json.loads(sw._vault_path("bob").read_text())
        assert "encrypted" in raw
        assert "hunter2" not in sw._vault_path("bob").read_text()
        assert sw._load_vault() == entries

    def test_encrypted_vault_inaccessible_without_session_key(self):
        sw._current_user = "carol"
        sw._session_passkey = "supersecret"
        sw._save_vault([{"id": "1", "password": "secret"}])
        sw._session_passkey = ""
        assert sw._load_vault() == []


class TestRecoveryKey:
    def test_entropy_at_least_128_bits(self):
        key = sw._make_recovery_key()
        parts = key.split("-")
        assert len(parts) == 4
        # 4 groups × 8 hex chars × 4 bits = 128 bits
        assert all(len(p) == 8 for p in parts)
        # hex alphabet only
        int(key.replace("-", ""), 16)

    def test_keys_are_unique(self):
        keys = {sw._make_recovery_key() for _ in range(20)}
        assert len(keys) == 20


class TestPasskeyMinimum:
    def test_min_length_constant(self):
        assert sw._MIN_PASSKEY_LEN >= 8


class TestUsernameValidation:
    def test_rejects_path_traversal(self):
        assert not sw._valid_username("../etc/passwd")
        assert not sw._valid_username("a/b")
        assert not sw._valid_username("a\\b")
        assert not sw._valid_username("")
        assert not sw._valid_username("x" * 65)

    def test_accepts_safe_names(self):
        assert sw._valid_username("alice")
        assert sw._valid_username("bob_1")
        assert sw._valid_username("user.name")


class TestVaultKeyWrap:
    def test_recovery_preserves_vault(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sw, "DATA_DIR", tmp_path)
        monkeypatch.setattr(sw, "ACCOUNTS_DIR", tmp_path / ".accounts")
        monkeypatch.setattr(sw, "VAULTS_DIR", tmp_path / ".vaults")
        sw._clear_session()

        username = "wrapuser"
        passkey = "password123"
        recovery = sw._make_recovery_key()
        vault_key = sw._new_vault_key()
        sw._current_user = username
        sw._session_passkey = vault_key
        sw._save_account({
            "name": username,
            "check": sw._encrypt("check_please_ok", passkey),
            "recovery_hash": __import__("hashlib").pbkdf2_hmac(
                "sha256", recovery.encode(), b"\x02" * 16, 200_000
            ).hex(),
            "recovery_salt": (b"\x02" * 16).hex(),
            "vault_key_wrap": sw._encrypt(vault_key, passkey),
            "vault_key_recovery_wrap": sw._encrypt(vault_key, recovery),
        })
        entries = [{"id": "1", "site": "ex.com", "password": "s3cret"}]
        sw._save_vault(entries)

        # Simulate recovery: unwrap with recovery key, re-wrap under new password
        acct = sw._load_account(username)
        assert acct is not None
        unwrapped = sw._unwrap_vault_key(acct, recovery, "vault_key_recovery_wrap")
        assert unwrapped == vault_key
        new_pw = "newpassword99"
        acct["check"] = sw._encrypt("check_please_ok", new_pw)
        acct["vault_key_wrap"] = sw._encrypt(unwrapped, new_pw)
        sw._save_account(acct, username)

        # Login with new password unlocks same vault
        sw._session_passkey = ""
        assert sw._verify_passkey(new_pw, username)
        vk2 = sw._unwrap_vault_key(sw._load_account(username) or {}, new_pw)
        sw._session_passkey = vk2 or ""
        assert sw._load_vault() == entries
