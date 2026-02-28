"""Output formatting — canonical JSON serialization + Rich table rendering.

Design sources:
- Canonical field ordering via to_dict() (DeepSeek — INV-5)
- Rich table with status coloring (Claude, Kimi)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from credential_auditor.models import AuditSummary, KeyResult
from credential_auditor.security import check_output_permissions, redact_key

_STATUS_COLORS = {
    "valid": "green",
    "invalid_format": "yellow",
    "auth_failed": "red",
    "suspended_account": "red bold",
    "quota_exhausted": "yellow",
    "insufficient_scope": "magenta",
    "network_error": "dim red",
}


def render_table(results: list[KeyResult], console: Optional[Console] = None, redaction_level: str = "partial") -> None:
    """Print a Rich table summary to the console."""
    console = console or Console()
    table = Table(title="Credential Audit Results", show_lines=True)
    table.add_column("Provider", style="cyan")
    table.add_column("Env Var")
    table.add_column("Fingerprint")
    table.add_column("Status")
    table.add_column("Account / Error")

    for r in results:
        fpd = r.key_fingerprint.to_dict(redaction_level)
        raw_fp = fpd.get("redacted") or f"{fpd['prefix']}...{fpd['suffix']} ({fpd['length']})"
        from rich.text import Text
        fp = Text(raw_fp)
        color = _STATUS_COLORS.get(r.status, "white")
        detail = r.account_info or r.error_detail or ""
        table.add_row(r.provider, r.env_var, fp, f"[{color}]{r.status}[/{color}]", detail)

    console.print(table)


def write_json(
    results: list[KeyResult],
    path: Path,
    force_insecure: bool = False,
    console: Optional[Console] = None,
    summary: Optional[AuditSummary] = None,
    redaction_level: str = "partial",
) -> bool:
    """Write canonical JSON output. Returns True on success."""
    console = console or Console(stderr=True)
    if not check_output_permissions(path, force=force_insecure):
        console.print(
            f"[red]Refusing to write to {path} — world-readable. "
            f"Use --force-insecure-output to override.[/red]"
        )
        return False
    payload: dict | list = [r.to_dict(redaction_level) for r in results]
    if summary:
        payload = {"summary": summary.to_dict(), "results": payload}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    console.print(f"[green]Results written to {path}[/green]")
    return True
