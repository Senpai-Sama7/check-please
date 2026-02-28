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
    available = sorted(Provider.get_registry().keys())

    p = argparse.ArgumentParser(
        prog="credential_auditor",
        description="Credential auditing tool — validates API keys against live provider endpoints.",
    )
    p.add_argument("--env", type=Path, help="Path to .env file")
    p.add_argument(
        "--provider", action="append", dest="providers", metavar="NAME",
        help=f"Provider to check (repeatable). Available: {', '.join(available)}",
    )
    p.add_argument("--output", type=Path, help="Write JSON results to file")
    p.add_argument("--json", action="store_true", help="Print JSON results to stdout")
    p.add_argument("--quiet", "-q", action="store_true", help="Suppress table output, only exit code")
    p.add_argument("--dry-run", action="store_true", help="Show what would be audited without making API calls")
    p.add_argument("--list-providers", action="store_true", help="List available providers and exit")
    p.add_argument("--redaction-level", choices=["partial", "full", "hash"], default="partial",
                   help="Key redaction level in output (default: partial)")
    p.add_argument("--force-insecure-output", action="store_true", help="Skip file permission check")
    p.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds (default: 30)")
    p.add_argument("--self-test", action="store_true", help="Run invariant self-test suite")
    p.add_argument("--version", action="store_true", help="Show version and exit")
    return p


def main() -> int:
    args = _build_parser().parse_args()
    console = Console(quiet=args.quiet) if hasattr(args, 'quiet') and args.quiet else Console()

    if args.version:
        from credential_auditor import __version__
        console.print(f"credential_auditor {__version__}")
        return 0

    if args.list_providers:
        discover_providers()
        reg = Provider.get_registry()
        from rich.table import Table
        t = Table(title=f"Available Providers ({len(reg)})", show_lines=True)
        t.add_column("Provider", style="cyan")
        t.add_column("Key Pattern")
        t.add_column("Env Patterns")
        for name, cls in sorted(reg.items()):
            kf = cls.key_format.pattern if cls.key_format else "—"
            eps = ", ".join(p.pattern for p in cls.env_patterns) if cls.env_patterns else "—"
            t.add_row(name, kf, eps)
        console.print(t)
        return 0

    if args.self_test:
        from credential_auditor.self_test import run_self_test
        ok = asyncio.run(run_self_test(console))
        return 0 if ok else 1

    if not args.env:
        console.print("[red]--env is required (or use --self-test / --list-providers)[/red]")
        return 2

    if not args.env.exists():
        console.print(f"[red]File not found: {args.env}[/red]")
        return 2

    # Dry run — show matched credentials without API calls
    if args.dry_run:
        from dotenv import dotenv_values
        from credential_auditor.providers import detect_provider_by_key
        discover_providers()
        reg = Provider.get_registry()
        active = {n: cls() for n, cls in reg.items()} if not args.providers else {n: reg[n]() for n in args.providers if n in reg}
        env_vars = dotenv_values(args.env)
        from rich.table import Table
        t = Table(title="Dry Run — Credentials to Audit", show_lines=True)
        t.add_column("Env Var", style="cyan")
        t.add_column("Provider")
        t.add_column("Match Type")
        t.add_column("Key Fingerprint")
        count = 0
        for var, val in env_vars.items():
            if not var or not val: continue
            matched = None
            for name, inst in active.items():
                if inst.matches_env_var(var):
                    matched = (name, "env_var")
                    break
            if not matched:
                det = detect_provider_by_key(str(val))
                if det and det.name in active:
                    matched = (det.name, "key_pattern")
            if matched:
                from credential_auditor.models import KeyFingerprint
                fp = KeyFingerprint.from_key(str(val))
                t.add_row(var, matched[0], matched[1], f"{fp.prefix}...{fp.suffix} ({fp.length})")
                count += 1
        console.print(t)
        console.print(f"\n[bold]{count}[/bold] credentials would be audited.")
        return 0

    from credential_auditor.orchestrator import audit
    from credential_auditor.output import render_table, write_json

    results = asyncio.run(audit(
        env_path=args.env,
        providers=args.providers,
        timeout=args.timeout,
        console=Console(stderr=True, quiet=True) if args.quiet else Console(stderr=True),
    ))

    if not results:
        if not args.quiet:
            console.print("[yellow]No matching credentials found.[/yellow]")
        return 0

    # Table output
    if not args.quiet and not args.json:
        render_table(results, console)

    # Summary stats after table
    summary = getattr(results, "summary", None)
    if summary and not args.quiet and not args.json:
        console.print()
        valid_c = f"[green]{summary.valid}[/green]" if summary.valid else "0"
        failed_c = f"[red]{summary.failed}[/red]" if summary.failed else "0"
        error_c = f"[yellow]{summary.errors}[/yellow]" if summary.errors else "0"
        console.print(f"  [bold]Summary:[/bold] {summary.total_keys} keys — {valid_c} valid, {failed_c} failed, {error_c} errors")
        parts = []
        if summary.cache_hits: parts.append(f"cache {summary.cache_hits}/{summary.cache_hits + summary.cache_misses}")
        if summary.auto_detected: parts.append(f"{summary.auto_detected} auto-detected")
        if summary.providers_skipped: parts.append(f"{summary.providers_skipped} providers bailed")
        avg = round(summary.total_latency_ms / summary.total_keys, 0) if summary.total_keys else 0
        parts.append(f"avg {avg:.0f}ms")
        console.print(f"  [dim]{' · '.join(parts)}[/dim]")
        console.print()

    # JSON to stdout
    if args.json:
        import json
        payload = [r.to_dict() for r in results]
        if summary:
            payload = {"summary": summary.to_dict(), "results": payload}
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    # JSON to file
    if args.output:
        if not write_json(results, args.output, force_insecure=args.force_insecure_output, console=console, summary=summary):
            return 2

    has_issues = any(r.status != "valid" for r in results)
    return 1 if has_issues else 0


if __name__ == "__main__":
    sys.exit(main())
