"""CLI entry point — python -m credential_auditor.

Usage:
    python -m credential_auditor --env .env
    python -m credential_auditor --env .env --provider openai --provider github
    python -m credential_auditor --env .env --output report.json
    python -m credential_auditor --self-test
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console

from credential_auditor.providers import Provider, discover_providers


def _build_parser() -> argparse.ArgumentParser:
    discover_providers()
    available = list(Provider.get_registry().keys())

    p = argparse.ArgumentParser(
        prog="credential_auditor",
        description="Credential auditing tool — validates API keys, tokens, and credentials.",
    )
    p.add_argument("--env", type=Path, help="Path to .env file")
    p.add_argument(
        "--provider", action="append", dest="providers", metavar="NAME",
        help=f"Provider to check (repeatable). Available: {', '.join(available)}",
    )
    p.add_argument("--output", type=Path, help="Write JSON results to file")
    p.add_argument("--force-insecure-output", action="store_true", help="Skip file permission check")
    p.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds (default: 30)")
    p.add_argument("--self-test", action="store_true", help="Run invariant self-test suite")
    return p


def main() -> int:
    args = _build_parser().parse_args()
    console = Console()

    if args.self_test:
        from credential_auditor.self_test import run_self_test
        ok = asyncio.run(run_self_test(console))
        return 0 if ok else 1

    if not args.env:
        console.print("[red]--env is required (or use --self-test)[/red]")
        return 2

    if not args.env.exists():
        console.print(f"[red]File not found: {args.env}[/red]")
        return 2

    from credential_auditor.orchestrator import audit
    from credential_auditor.output import render_table, write_json

    results = asyncio.run(audit(
        env_path=args.env,
        providers=args.providers,
        timeout=args.timeout,
        console=Console(stderr=True),
    ))

    if not results:
        return 0

    render_table(results, console)

    if args.output:
        summary = getattr(results, "summary", None)
        if not write_json(results, args.output, force_insecure=args.force_insecure_output, console=console, summary=summary):
            return 2

    has_issues = any(r.status != "valid" for r in results)
    return 1 if has_issues else 0


if __name__ == "__main__":
    sys.exit(main())
