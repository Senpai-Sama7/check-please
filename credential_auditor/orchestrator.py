"""Async orchestration engine.

Design sources:
- asyncio.gather(return_exceptions=True) (all Tier 1-2 variants)
- Two-layer error defense: gather catches + per-provider try/except in check_key (Claude)
- Context manager for httpx client lifecycle (Claude)
- Sort results for stable output (DeepSeek)
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import httpx
from dotenv import dotenv_values
from rich.console import Console

from credential_auditor.models import KeyResult
from credential_auditor.providers import Provider, discover_providers
from credential_auditor.security import suppress_credential_logging


async def audit(
    env_path: Path,
    providers: Optional[list[str]] = None,
    timeout: float = 30.0,
    console: Optional[Console] = None,
) -> list[KeyResult]:
    """Run credential audit. Returns list of KeyResult in stable order."""
    suppress_credential_logging()
    discover_providers()
    console = console or Console(stderr=True)
    registry = Provider.get_registry()

    if providers:
        for p in providers:
            if p not in registry:
                console.print(f"[red]Unknown provider: {p}. Available: {list(registry)}[/red]")
                return []
        active = {name: registry[name]() for name in providers}
    else:
        active = {name: cls() for name, cls in registry.items()}

    env_vars = dotenv_values(env_path)

    # Expose non-secret companion vars (e.g. TWILIO_ACCOUNT_SID) so providers can read them
    import os
    for var, value in env_vars.items():
        if var and value and not any(s in var.upper() for s in ("SECRET", "TOKEN", "PASSWORD", "KEY", "AUTH")):
            os.environ.setdefault(var, value)
    # Also expose SIDs/IDs that providers need for auth
    for var in ("TWILIO_ACCOUNT_SID",):
        if var in env_vars and env_vars[var]:
            os.environ[var] = env_vars[var]

    tasks: list[tuple[str, str, Provider]] = []
    for var, value in env_vars.items():
        if not var or not value:
            continue
        for name, inst in active.items():
            if inst.matches_env_var(var):
                tasks.append((var, str(value), inst))
                break

    if not tasks:
        console.print("[yellow]No matching credentials found for enabled providers.[/yellow]")
        return []

    async with httpx.AsyncClient(timeout=timeout) as client:
        coros = [inst.check_key(var, key, client) for var, key, inst in tasks]
        raw = await asyncio.gather(*coros, return_exceptions=True)

    results: list[KeyResult] = []
    for i, r in enumerate(raw):
        if isinstance(r, BaseException):
            var, key, inst = tasks[i]
            from credential_auditor.models import KeyFingerprint
            results.append(KeyResult(
                provider=inst.name, env_var=var,
                key_fingerprint=KeyFingerprint.from_key(key),
                status="network_error",
                error_detail=f"{type(r).__name__}: {r}",
            ))
        else:
            results.append(r)

    results.sort(key=lambda r: (r.provider, r.env_var))
    return results
