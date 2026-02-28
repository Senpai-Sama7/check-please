"""Self-test suite — validates INV-1..INV-6 with mock httpx transport.

Design source: Claude reference implementation.
All tests are deterministic — no network calls, no real credentials.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Optional

import httpx
from rich.console import Console

from credential_auditor.models import KeyFingerprint, KeyResult, RateLimitInfo, VALID_STATUSES
from credential_auditor.providers import Provider, discover_providers


class MockTransport(httpx.AsyncBaseTransport):
    """Deterministic mock transport for self-test fixtures."""

    def __init__(self, responses: dict[str, tuple[int, dict, Optional[dict]]]):
        # url_pattern -> (status_code, json_body, headers)
        self._responses = responses

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        for pattern, (code, body, hdrs) in self._responses.items():
            if pattern in url:
                return httpx.Response(
                    status_code=code,
                    json=body,
                    headers=hdrs or {},
                    request=request,
                )
        return httpx.Response(status_code=500, json={"error": "no mock"}, request=request)


def _make_client(responses: dict) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=MockTransport(responses))


async def _test_inv1(console: Console) -> bool:
    """INV-1: Empty provider list requires zero orchestration changes."""
    discover_providers()
    # With no matching env vars, audit should return empty list without error
    from credential_auditor.orchestrator import audit
    from pathlib import Path
    import tempfile, os

    with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
        f.write("UNRELATED_VAR=some_value\n")
        tmp = f.name
    try:
        results = await audit(Path(tmp), providers=[], console=Console(quiet=True))
        # Empty provider list should be handled gracefully
        ok = isinstance(results, list)
    except Exception:
        ok = False
    finally:
        os.unlink(tmp)
    console.print(f"  INV-1 (empty providers → no crash): {'[green]PASS[/green]' if ok else '[red]FAIL[/red]'}")
    return ok


async def _test_inv2(console: Console) -> bool:
    """INV-2: invalid_format returns in <5ms with no network call."""
    discover_providers()
    provider = Provider.get_provider("openai")
    # Use a key that fails format check
    bad_key = "not-a-valid-key"
    start = time.monotonic()
    # check_key should return invalid_format without making any network call
    # We pass a client that would fail if called
    boom_transport = MockTransport({})  # no routes → 500 if called
    async with httpx.AsyncClient(transport=boom_transport) as client:
        result = await provider.check_key("OPENAI_API_KEY", bad_key, client)
    elapsed_ms = (time.monotonic() - start) * 1000
    ok = result.status == "invalid_format" and elapsed_ms < 5.0
    console.print(
        f"  INV-2 (invalid_format <5ms, no network): "
        f"{'[green]PASS[/green]' if ok else '[red]FAIL[/red]'} ({elapsed_ms:.1f}ms)"
    )
    return ok


async def _test_inv3(console: Console) -> bool:
    """INV-3: Network error in one provider doesn't affect others."""
    discover_providers()
    openai_p = Provider.get_provider("openai")
    github_p = Provider.get_provider("github")

    responses = {
        "api.openai.com": (200, {"data": [{"id": "gpt-4"}]}, {"x-ratelimit-limit": "100", "x-ratelimit-remaining": "99", "x-ratelimit-reset": "0"}),
        # github will timeout/error — no route
    }
    async with _make_client(responses) as client:
        results = await asyncio.gather(
            openai_p.check_key("OPENAI_API_KEY", "sk-" + "a" * 48, client),
            github_p.check_key("GITHUB_TOKEN", "ghp_" + "b" * 36, client),
            return_exceptions=True,
        )

    openai_ok = not isinstance(results[0], BaseException) and results[0].status == "valid"
    github_err = not isinstance(results[1], BaseException) and results[1].status == "network_error"
    ok = openai_ok and github_err
    console.print(f"  INV-3 (network isolation): {'[green]PASS[/green]' if ok else '[red]FAIL[/red]'}")
    return ok


async def _test_inv4(console: Console) -> bool:
    """INV-4: No raw key appears in any output representation."""
    discover_providers()
    test_key = "sk-" + "SECRETKEY1234567890abcdef" * 2
    fp = KeyFingerprint.from_key(test_key)
    result = KeyResult(
        provider="openai", env_var="OPENAI_API_KEY",
        key_fingerprint=fp, status="valid",
    )
    serialized = json.dumps(result.to_dict())
    as_str = str(result)
    as_repr = repr(result)
    ok = test_key not in serialized and test_key not in as_str and test_key not in as_repr
    console.print(f"  INV-4 (no raw key in output): {'[green]PASS[/green]' if ok else '[red]FAIL[/red]'}")
    return ok


async def _test_inv5(console: Console) -> bool:
    """INV-5: Canonical JSON field ordering is stable across runs."""
    fp = KeyFingerprint(prefix="sk-t", suffix="xyz1", length=51)
    rl = RateLimitInfo(limit=100, remaining=99, reset_ts=1700000000)
    result = KeyResult(
        provider="openai", env_var="OPENAI_API_KEY",
        key_fingerprint=fp, status="valid",
        account_info="test", scopes=["read"], rate_limit=rl,
        usage_stats={"calls": 1}, latency_ms=42.5, error_detail=None,
    )
    d = result.to_dict()
    expected_order = [
        "provider", "env_var", "key_fingerprint", "status", "account_info",
        "scopes", "rate_limit", "usage_stats", "latency_ms", "error_detail",
    ]
    actual_order = list(d.keys())
    # Run twice to confirm stability
    d2 = result.to_dict()
    ok = actual_order == expected_order and list(d2.keys()) == expected_order
    # Also verify JSON round-trip preserves order
    j1 = json.dumps(d)
    j2 = json.dumps(d2)
    ok = ok and j1 == j2
    console.print(f"  INV-5 (canonical field order): {'[green]PASS[/green]' if ok else '[red]FAIL[/red]'}")
    return ok


async def _test_inv6(console: Console) -> bool:
    """INV-6: Adding a provider requires only one new class — no orchestration changes."""
    discover_providers()
    registry_before = set(Provider.get_registry().keys())

    # Dynamically define a new provider
    import re

    class TestDummyProvider(Provider):
        name = "test_dummy"
        env_patterns = [re.compile(r"^TEST_DUMMY_KEY$")]
        key_format = re.compile(r"^td-[a-z]{10,}$")

        async def validate(self, key, client):
            return "valid", "dummy", None, None, None, None

    registry_after = set(Provider.get_registry().keys())
    ok = "test_dummy" in registry_after and "test_dummy" not in registry_before
    # Clean up
    Provider._registry.pop("test_dummy", None)
    console.print(f"  INV-6 (zero-touch provider addition): {'[green]PASS[/green]' if ok else '[red]FAIL[/red]'}")
    return ok


async def _test_all_statuses_reachable(console: Console) -> bool:
    """Verify all 7 status values are reachable via mock fixtures."""
    discover_providers()
    provider = Provider.get_provider("openai")
    valid_key = "sk-" + "a" * 48

    fixtures = {
        "valid": (200, {"data": [{"id": "m"}]}, {"x-ratelimit-limit": "10", "x-ratelimit-remaining": "9", "x-ratelimit-reset": "0"}),
        "auth_failed": (401, {"error": {"message": "bad"}}, None),
        "quota_exhausted": (429, {}, None),
        "insufficient_scope": (403, {"error": {"code": "no_access"}}, None),
        "suspended_account": (403, {"error": {"code": "account_deactivated"}}, None),
    }

    seen: set[str] = set()

    # invalid_format — bad key, no network
    async with _make_client({}) as client:
        r = await provider.check_key("OPENAI_API_KEY", "bad", client)
        seen.add(r.status)

    # network_error — no matching route
    async with _make_client({}) as client:
        r = await provider.check_key("OPENAI_API_KEY", valid_key, client)
        seen.add(r.status)

    for status_name, (code, body, hdrs) in fixtures.items():
        responses = {"api.openai.com": (code, body, hdrs)}
        async with _make_client(responses) as client:
            r = await provider.check_key("OPENAI_API_KEY", valid_key, client)
            seen.add(r.status)

    ok = seen == VALID_STATUSES
    missing = VALID_STATUSES - seen
    console.print(
        f"  All 7 statuses reachable: {'[green]PASS[/green]' if ok else f'[red]FAIL — missing: {missing}[/red]'}"
    )
    return ok


async def run_self_test(console: Optional[Console] = None) -> bool:
    """Run all invariant tests. Returns True if all pass."""
    console = console or Console()
    console.print("\n[bold]Running self-test suite (INV-1..INV-6 + status coverage)...[/bold]\n")

    tests = [
        _test_inv1, _test_inv2, _test_inv3, _test_inv4, _test_inv5, _test_inv6,
        _test_all_statuses_reachable,
    ]
    results = []
    for test in tests:
        results.append(await test(console))

    passed = sum(results)
    total = len(results)
    console.print(f"\n[bold]Results: {passed}/{total} passed[/bold]")
    return all(results)
