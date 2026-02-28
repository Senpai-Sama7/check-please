"""Tests for provider registry, matching, and format checking."""

import re

import pytest

from credential_auditor.providers import (
    Provider,
    detect_provider_by_key,
    discover_providers,
    _literal_prefix_len,
)


@pytest.fixture(autouse=True)
def _load_providers():
    discover_providers()


class TestRegistry:
    def test_16_providers_registered(self):
        assert len(Provider.get_registry()) == 16

    def test_known_providers_present(self):
        reg = Provider.get_registry()
        for name in ["openai", "github", "anthropic", "google", "stripe",
                      "slack", "sendgrid", "huggingface"]:
            assert name in reg, f"{name} missing from registry"

    def test_get_provider_returns_instance(self):
        p = Provider.get_provider("openai")
        assert p.name == "openai"

    def test_get_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown provider"):
            Provider.get_provider("nonexistent_provider_xyz")


class TestEnvVarMatching:
    @pytest.mark.parametrize("provider,env_var", [
        ("openai", "OPENAI_API_KEY"),
        ("openai", "OPENAI_API_KEY_ALT1"),
        ("github", "GITHUB_TOKEN"),
        ("github", "GH_TOKEN"),
        ("anthropic", "ANTHROPIC_API_KEY"),
        ("stripe", "STRIPE_SECRET_KEY"),
        ("slack", "SLACK_BOT_TOKEN"),
    ])
    def test_matches(self, provider, env_var):
        p = Provider.get_provider(provider)
        assert p.matches_env_var(env_var), f"{provider} should match {env_var}"

    @pytest.mark.parametrize("provider,env_var", [
        ("openai", "GITHUB_TOKEN"),
        ("github", "OPENAI_API_KEY"),
        ("anthropic", "RANDOM_KEY"),
        ("stripe", "OPENAI_API_KEY"),
    ])
    def test_no_match(self, provider, env_var):
        p = Provider.get_provider(provider)
        assert not p.matches_env_var(env_var)


class TestKeyFormatCheck:
    @pytest.mark.parametrize("provider,key", [
        ("openai", "sk-" + "a" * 48),
        ("github", "ghp_" + "A" * 36),
        ("github", "github_pat_" + "a" * 22),
        ("anthropic", "sk-ant-" + "a" * 40),
        ("groq", "gsk_" + "a" * 48),
        ("huggingface", "hf_" + "A" * 30),
    ])
    def test_valid_format(self, provider, key):
        p = Provider.get_provider(provider)
        ok, err = p.check_format(key)
        assert ok, f"{provider} should accept {key[:20]}... — {err}"

    @pytest.mark.parametrize("provider,key", [
        ("openai", "not-a-key"),
        ("github", "bad-token"),
        ("anthropic", "sk-wrong-prefix"),
        ("groq", "invalid"),
    ])
    def test_invalid_format(self, provider, key):
        p = Provider.get_provider(provider)
        ok, err = p.check_format(key)
        assert not ok
        assert err is not None


class TestAutoDetect:
    def test_detect_openai(self):
        # sk-proj prefix is unambiguously OpenAI (not deepseek hex pattern)
        p = detect_provider_by_key("sk-proj-" + "A" * 40)
        assert p is not None
        assert p.name == "openai"

    def test_detect_github(self):
        p = detect_provider_by_key("ghp_" + "A" * 36)
        assert p is not None
        assert p.name == "github"

    def test_detect_anthropic(self):
        p = detect_provider_by_key("sk-ant-" + "a" * 40)
        assert p is not None
        assert p.name == "anthropic"

    def test_no_match(self):
        assert detect_provider_by_key("totally-random-string") is None

    def test_specificity_prefers_anthropic_over_openai(self):
        """sk-ant-* should match anthropic, not openai (longer literal prefix)."""
        p = detect_provider_by_key("sk-ant-" + "a" * 40)
        assert p is not None
        assert p.name == "anthropic"


class TestLiteralPrefixLen:
    def test_simple(self):
        assert _literal_prefix_len("^sk-ant-") == 7

    def test_with_regex(self):
        assert _literal_prefix_len("^ghp_[A-Za-z0-9]") == 4

    def test_empty(self):
        assert _literal_prefix_len("^[a-z]") == 0

    def test_no_caret(self):
        assert _literal_prefix_len("sk-") == 3


class TestDynamicRegistration:
    def test_new_provider_auto_registers(self):
        before = set(Provider.get_registry().keys())

        class _TestProvider(Provider):
            name = "_test_dynamic"
            env_patterns = [re.compile(r"^_TEST_KEY$")]
            key_format = re.compile(r"^_td-[a-z]+$")

            async def validate(self, key, client):
                return "valid", None, None, None, None, None

        assert "_test_dynamic" in Provider.get_registry()
        assert "_test_dynamic" not in before
        Provider._registry.pop("_test_dynamic", None)
