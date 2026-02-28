"""Async orchestration engine with cache, audit log, auto-detect, and failed-provider bail.

Design sources:
- asyncio.gather(return_exceptions=True) (all Tier 1-2 variants)
- Two-layer error defense: gather catches + per-provider try/except in check_key (Claude)
- Context manager for httpx client lifecycle (Claude)
- Sort results for stable output (DeepSeek)

Enhanced with features ported from ultimate_credential_auditor:
- Validation cache (skip re-validation within TTL)
- Structured audit log file
- Auto-detect provider from key pattern (not just env var name)
- Failed-provider bail (skip provider after N consecutive auth failures)
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from pathlib import Path
from typing import Optional

import httpx
from dotenv import dotenv_values
from rich.console import Console

from credential_auditor.audit_log import AuditLog
from credential_auditor.cache import ValidationCache
from credential_auditor.models import (
    AuditSummary,
    FAILING_STATUSES,
    KeyFingerprint,
    KeyResult,
)
from credential_auditor.providers import Provider, detect_provider_by_key, discover_providers
from credential_auditor.security import suppress_credential_logging

# Module-level cache persists across audit runs within the same process
_cache = ValidationCache(ttl_seconds=3600)

# Failed-provider tracking: bail after this many consecutive failures
_FAIL_BAIL_THRESHOLD = 3

# Limit concurrent outbound requests to avoid triggering provider rate limits
_CONCURRENCY_LIMIT = 10


class AuditResults(list):
    """list subclass that carries an AuditSummary attribute."""
    summary: AuditSummary = None  # type: ignore[assignment]
    _config_error: bool = False


async def audit(
    env_path: Path,
    providers: Optional[list[str]] = None,
    timeout: float = 30.0,
    console: Optional[Console] = None,
    audit_log_path: Optional[Path] = None,
) -> list[KeyResult]:
    """Run credential audit. Returns list of KeyResult in stable order."""
    suppress_credential_logging()
    discover_providers()
    console = console or Console(stderr=True)
    registry = Provider.get_registry()

    # Audit log
    alog = AuditLog(audit_log_path or env_path.parent / "audit.log")
    alog.log("audit_start", detail=str(env_path))

    if providers:
        for p in providers:
            if p not in registry:
                console.print(f"[red]Unknown provider: {p}. Available: {list(registry)}[/red]")
                r = AuditResults()
                r.summary = AuditSummary(0, 0, 0, 0, 0, 0, 0, 0, 0.0, 0)
                r._config_error = True
                return r
        active = {name: registry[name]() for name in providers}
    else:
        active = {name: cls() for name, cls in registry.items()}

    env_vars = dotenv_values(env_path)

    # Expose non-secret companion vars (e.g. TWILIO_ACCOUNT_SID) so providers can read them
    # Track injected vars for cleanup
    _injected_env: list[str] = []
    for var, value in env_vars.items():
        if var and value and not any(s in var.upper() for s in ("SECRET", "TOKEN", "PASSWORD", "KEY", "AUTH")):
            if var not in os.environ:
                os.environ[var] = value
                _injected_env.append(var)
    for var in ("TWILIO_ACCOUNT_SID",):
        if var in env_vars and env_vars[var]:
            os.environ[var] = env_vars[var]
            _injected_env.append(var)

    # Match env vars to providers — with auto-detection fallback
    tasks: list[tuple[str, str, Provider]] = []
    auto_detected_count = 0
    auto_detected_vars: set[str] = set()
    for var, value in env_vars.items():
        if not var or not value:
            continue
        matched = False
        for name, inst in active.items():
            if inst.matches_env_var(var):
                tasks.append((var, str(value), inst))
                matched = True
                break
        # Auto-detect by key pattern if no env var match
        if not matched:
            detected = detect_provider_by_key(str(value))
            if detected and detected.name in active:
                tasks.append((var, str(value), detected))
                auto_detected_count += 1
                auto_detected_vars.add(var)
                alog.log("auto_detect", provider=detected.name, env_var=var)

    if not tasks:
        console.print("[yellow]No matching credentials found for enabled providers.[/yellow]")
        alog.log("audit_end", detail="no credentials found")
        alog.flush()
        r = AuditResults()
        r.summary = AuditSummary(0, 0, 0, 0, 0, 0, 0, 0, 0.0, 0)
        return r

    # Check cache first, separate cached vs uncached
    cached_results: list[KeyResult] = []
    uncached_tasks: list[tuple[str, str, Provider]] = []
    for var, key, inst in tasks:
        hit = _cache.get(inst.name, key)
        if hit:
            if var in auto_detected_vars:
                hit = replace(hit, auto_detected=True)
            cached_results.append(hit)
            alog.log("cache_hit", provider=inst.name, env_var=var, status=hit.status)
        else:
            uncached_tasks.append((var, key, inst))

    # Failed-provider tracking
    fail_counts: dict[str, int] = {}
    skipped_providers: set[str] = set()

    sem = asyncio.Semaphore(_CONCURRENCY_LIMIT)

    async def _throttled_check(inst: Provider, var: str, key: str, client: httpx.AsyncClient) -> KeyResult:
        async with sem:
            return await inst.check_key(var, key, client)

    async with httpx.AsyncClient(timeout=timeout, max_redirects=0) as client:
        coros = [_throttled_check(inst, var, key, client) for var, key, inst in uncached_tasks]
        raw = await asyncio.gather(*coros, return_exceptions=True)

    results: list[KeyResult] = list(cached_results)
    for i, r in enumerate(raw):
        var, key, inst = uncached_tasks[i]
        if isinstance(r, BaseException):
            result = KeyResult(
                provider=inst.name, env_var=var,
                key_fingerprint=KeyFingerprint.from_key(key),
                status="network_error",
                error_detail=f"{type(r).__name__}: {r}",
            )
        else:
            result = r

        # Cache the result
        _cache.put(inst.name, key, result)

        # Track consecutive failures per provider
        if result.status in FAILING_STATUSES:
            fail_counts[inst.name] = fail_counts.get(inst.name, 0) + 1
            if fail_counts[inst.name] >= _FAIL_BAIL_THRESHOLD:
                skipped_providers.add(inst.name)
                alog.log("provider_bail", provider=inst.name,
                         detail=f"skipped after {_FAIL_BAIL_THRESHOLD} consecutive failures")
        else:
            fail_counts[inst.name] = 0

        if var in auto_detected_vars:
            result = replace(result, auto_detected=True)
        alog.log("validate", provider=result.provider, env_var=result.env_var,
                 status=result.status, latency_ms=result.latency_ms)
        results.append(result)

    results.sort(key=lambda r: (r.provider, r.env_var))

    # Build summary
    valid_count = sum(1 for r in results if r.status == "valid")
    fail_count = sum(1 for r in results if r.status in FAILING_STATUSES)
    error_count = sum(1 for r in results if r.status == "network_error")
    total_latency = sum(r.latency_ms for r in results)

    summary = AuditSummary(
        total_keys=len(results),
        valid=valid_count,
        failed=fail_count,
        errors=error_count,
        providers_checked=len(active) - len(skipped_providers),
        providers_skipped=len(skipped_providers),
        cache_hits=_cache.stats.hits,
        cache_misses=_cache.stats.misses,
        total_latency_ms=total_latency,
        auto_detected=auto_detected_count,
    )

    alog.log("audit_end", detail=f"{len(results)} keys, {valid_count} valid, "
             f"{len(skipped_providers)} providers bailed")
    alog.flush()

    # Clean up injected env vars to prevent pollution
    for var in _injected_env:
        os.environ.pop(var, None)

    out = AuditResults(results)
    out.summary = summary
    return out


def get_cache() -> ValidationCache:
    """Expose module-level cache for stats display."""
    return _cache
