#!/usr/bin/env python3
"""check_please — Credential Audit TUI.

A premium Textual-based terminal UI for the credential audit pipeline.
Launch: python tui.py  (or ./check_please)
"""

from __future__ import annotations

import asyncio
import io
import json
import time
from pathlib import Path
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    Log,
    RichLog,
    ProgressBar,
    Rule,
    Static,
    TabbedContent,
    TabPane,
)

# ── Paths ──────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent
ENV_PATH = ROOT / ".env"
ENV_ORG_PATH = ROOT / ".env.organized"
REPORT_PATH = ROOT / "audit_report.json"

# ── Status styling ─────────────────────────────────────────────────────────
STATUS_STYLES = {
    "valid": ("✓", "green"),
    "invalid_format": ("⚠", "yellow"),
    "auth_failed": ("✗", "red"),
    "suspended_account": ("⊘", "red"),
    "quota_exhausted": ("◔", "yellow"),
    "insufficient_scope": ("⊖", "magenta"),
    "network_error": ("⚡", "dim red"),
}


# ═══════════════════════════════════════════════════════════════════════════
#  Stat Card widget
# ═══════════════════════════════════════════════════════════════════════════
class StatCard(Static):
    """A single metric card with label and value."""

    def __init__(self, label: str, value: str = "—", card_id: str = "", classes: str = "") -> None:
        super().__init__(classes=f"stat-card {classes}", id=card_id)
        self._label = label
        self._value = value

    def compose(self) -> ComposeResult:
        yield Label(self._value, id=f"{self.id}-val", classes="stat-value")
        yield Label(self._label, classes="stat-label")

    def update_value(self, value: str) -> None:
        try:
            self.query_one(f"#{self.id}-val", Label).update(value)
        except NoMatches:
            pass


def _load_report_data() -> tuple[list, dict | None]:
    """Load report, return (results_list, summary_or_None)."""
    if not REPORT_PATH.exists():
        return [], None
    try:
        raw = json.loads(REPORT_PATH.read_text())
    except Exception:
        return [], None
    if isinstance(raw, dict):
        return raw.get("results", []), raw.get("summary")
    return raw, None


# ═══════════════════════════════════════════════════════════════════════════
#  Dashboard Screen
# ═══════════════════════════════════════════════════════════════════════════
class DashboardScreen(Screen):
    BINDINGS = [
        Binding("a", "app.go_audit", "Run Audit"),
        Binding("o", "organize", "Organize .env"),
        Binding("r", "refresh_dashboard", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="dashboard-scroll"):
            yield Label("  Dashboard", classes="screen-title")
            with Horizontal(id="stat-row"):
                yield StatCard("TOTAL KEYS", card_id="stat-entries")
                yield StatCard("PROVIDERS", card_id="stat-providers")
                yield StatCard("VALID", card_id="stat-valid", classes="card-green")
                yield StatCard("DEAD", card_id="stat-dead", classes="card-red")
            with Horizontal(id="stat-row-2"):
                yield StatCard("AUTO-DETECT", card_id="stat-autodetect", classes="card-blue")
                yield StatCard("CACHE HIT%", card_id="stat-cache")
                yield StatCard("AVG LATENCY", card_id="stat-latency")
                yield StatCard("LAST AUDIT", card_id="stat-last")
            yield Rule()
            yield Label("  Audit Results", classes="section-title")
            yield DataTable(id="results-table")
            yield Rule()
            with Horizontal(id="action-row"):
                yield Button("Run Audit  [a]", id="btn-audit", variant="primary")
                yield Button("Organize .env  [o]", id="btn-organize", variant="default")
                yield Button("Refresh  [r]", id="btn-refresh", variant="default")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#results-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Provider", "Env Var", "Fingerprint", "Status", "Detail")
        self.action_refresh_dashboard()

    def on_screen_resume(self) -> None:
        self.action_refresh_dashboard()

    def action_refresh_dashboard(self) -> None:
        self._load_stats()
        self._load_results()

    def _load_stats(self) -> None:
        data, summary = _load_report_data()

        # From summary if available
        if summary:
            self.query_one("#stat-entries", StatCard).update_value(str(summary.get("total_keys", len(data))))
            self.query_one("#stat-valid", StatCard).update_value(str(summary.get("valid", 0)))
            self.query_one("#stat-autodetect", StatCard).update_value(str(summary.get("auto_detected", 0)))
            avg = summary.get("avg_latency_ms", 0)
            self.query_one("#stat-latency", StatCard).update_value(f"{avg:.0f}ms" if avg else "—")
        else:
            total = len(data)
            valid = sum(1 for r in data if r.get("status") == "valid")
            self.query_one("#stat-entries", StatCard).update_value(str(total) if total else "—")
            self.query_one("#stat-valid", StatCard).update_value(str(valid))
            self.query_one("#stat-autodetect", StatCard).update_value("—")
            self.query_one("#stat-latency", StatCard).update_value("—")

        dead = sum(1 for r in data if r.get("status") in ("auth_failed", "suspended_account"))
        self.query_one("#stat-dead", StatCard).update_value(str(dead))

        # Providers
        from credential_auditor.providers import Provider, discover_providers
        discover_providers()
        self.query_one("#stat-providers", StatCard).update_value(str(len(Provider.get_registry())))

        # Last audit time
        last = "never"
        if REPORT_PATH.exists():
            try:
                import datetime
                last = datetime.datetime.fromtimestamp(REPORT_PATH.stat().st_mtime).strftime("%b %d %H:%M")
            except Exception:
                pass
        self.query_one("#stat-last", StatCard).update_value(last)

        # Cache stats
        try:
            from credential_auditor.orchestrator import get_cache
            stats = get_cache().stats
            rate = f"{stats.hit_rate:.0%}" if stats.total else "—"
            self.query_one("#stat-cache", StatCard).update_value(rate)
        except Exception:
            self.query_one("#stat-cache", StatCard).update_value("—")

    def _load_results(self) -> None:
        table = self.query_one("#results-table", DataTable)
        table.clear()
        data, _ = _load_report_data()
        for r in data:
            fp = r.get("key_fingerprint", {})
            fp_str = f"{fp.get('prefix', '?')}...{fp.get('suffix', '?')} ({fp.get('length', '?')})"
            status = r.get("status", "?")
            icon, color = STATUS_STYLES.get(status, ("?", "white"))
            status_text = Text(f"{icon} {status}", style=color)
            detail = r.get("account_info") or r.get("error_detail") or ""
            table.add_row(r.get("provider", "?"), r.get("env_var", "?"), fp_str, status_text, detail)

    @on(Button.Pressed, "#btn-audit")
    def on_audit_pressed(self) -> None:
        self.app.switch_mode("audit")

    @on(Button.Pressed, "#btn-organize")
    def on_organize_pressed(self) -> None:
        self.action_organize()

    @on(Button.Pressed, "#btn-refresh")
    def on_refresh_pressed(self) -> None:
        self.action_refresh_dashboard()

    def action_organize(self) -> None:
        self.app.push_screen(OrganizeScreen())


# ═══════════════════════════════════════════════════════════════════════════
#  Audit Screen — live async audit with color-coded output
# ═══════════════════════════════════════════════════════════════════════════
class AuditScreen(Screen):
    BINDINGS = [
        Binding("escape", "go_back", "Back", priority=True),
    ]

    is_running: reactive[bool] = reactive(False)

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="audit-scroll"):
            yield Label("  Run Audit", classes="screen-title")
            with Horizontal(id="audit-controls"):
                yield Button("Start Audit", id="btn-start", variant="primary")
                yield Button("Back", id="btn-back", variant="default")
            yield Rule()
            yield Label("", id="audit-status", classes="audit-status")
            yield ProgressBar(id="audit-progress", total=100, show_eta=False)
            yield Rule()
            yield Label("  Live Output", classes="section-title")
            yield RichLog(id="audit-log", auto_scroll=True, markup=True)
        yield Footer()

    def on_screen_resume(self) -> None:
        # Reset UI state on re-entry (but keep log if audit ran)
        if not self.is_running:
            self.query_one("#btn-start", Button).disabled = False

    @on(Button.Pressed, "#btn-start")
    def on_start(self) -> None:
        if not self.is_running:
            self.run_audit()

    def action_go_back(self) -> None:
        if not self.is_running:
            self.app.switch_mode("dashboard")

    @on(Button.Pressed, "#btn-back")
    def on_back(self) -> None:
        self.action_go_back()

    @work(exclusive=True)
    async def run_audit(self) -> None:
        self.is_running = True
        self.query_one("#btn-start", Button).disabled = True
        log = self.query_one("#audit-log", RichLog)
        progress = self.query_one("#audit-progress", ProgressBar)
        status_label = self.query_one("#audit-status", Label)
        log.clear()
        progress.progress = 0
        status_label.update("")
        t0 = time.monotonic()

        try:
            from rich.console import Console as RichConsole
            quiet = RichConsole(file=io.StringIO())

            # Step 1: Organize
            status_label.update("⏳ Organizing .env...")
            progress.progress = 5
            log.write_line("[bold cyan]── Organizing .env ──[/]")
            if ENV_PATH.exists():
                import organize_env
                result = await asyncio.to_thread(organize_env.organize, ENV_PATH, ENV_ORG_PATH)
                log.write_line(f"[green]✓[/] Organized {result['total']} entries → {result['categories']} categories")
                if result.get("unparseable", 0):
                    log.write_line(f"[yellow]⚠[/] {result['unparseable']} unparseable lines appended as comments")
            else:
                log.write_line("[yellow]⚠ No .env file found[/]")
            progress.progress = 15

            # Step 2: Self-test
            status_label.update("⏳ Running self-test...")
            log.write_line("\n[bold cyan]── Self-test ──[/]")
            from credential_auditor.self_test import run_self_test
            ok = await run_self_test(console=quiet)
            log.write_line(f"[green]✓[/] Self-test: {'all passed' if ok else '[red]FAILURES[/]'}")
            progress.progress = 25

            # Step 3: Audit
            status_label.update("⏳ Auditing credentials...")
            log.write_line("\n[bold cyan]── Credential Audit ──[/]")
            audit_path = ENV_ORG_PATH if ENV_ORG_PATH.exists() else ENV_PATH
            from credential_auditor.orchestrator import audit
            results = await audit(audit_path, console=quiet)
            progress.progress = 85

            # Color-coded results
            valid = sum(1 for r in results if r.status == "valid")
            dead = sum(1 for r in results if r.status in ("auth_failed", "suspended_account"))
            for r in results:
                icon, color = STATUS_STYLES.get(r.status, ("?", "white"))
                fp = f"{r.key_fingerprint.prefix}...{r.key_fingerprint.suffix}"
                detail = r.account_info or r.error_detail or ""
                log.write_line(f"  [{color}]{icon}[/] {r.provider:12s} {r.env_var:28s} [{color}]{r.status:16s}[/] {detail}")

            log.write_line(f"\n[bold green]✓[/] {len(results)} keys audited — [green]{valid} valid[/], [red]{dead} dead[/]")

            # Summary stats
            summary = getattr(results, "summary", None)
            if summary:
                parts = []
                if summary.cache_hits:
                    parts.append(f"⚡ cache {summary.cache_hits}/{summary.cache_hits + summary.cache_misses}")
                if summary.auto_detected:
                    parts.append(f"🔍 {summary.auto_detected} auto-detected")
                if summary.providers_skipped:
                    parts.append(f"⏭ {summary.providers_skipped} bailed")
                avg = round(summary.total_latency_ms / summary.total_keys, 0) if summary.total_keys else 0
                parts.append(f"⏱ avg {avg:.0f}ms")
                log.write_line(f"  [dim]{' · '.join(parts)}[/]")

            # Step 4: Write report
            status_label.update("⏳ Writing report...")
            from credential_auditor.output import write_json
            summary = getattr(results, "summary", None)
            await asyncio.to_thread(write_json, results, REPORT_PATH, False, quiet, summary)
            log.write_line(f"[green]✓[/] Report → {REPORT_PATH.name}")
            progress.progress = 95

            # Step 5: Prune dead keys
            dead_vars = [r.env_var for r in results if r.status in ("auth_failed", "invalid_format")]
            if dead_vars and ENV_ORG_PATH.exists():
                lines = ENV_ORG_PATH.read_text().splitlines(keepends=True)
                out = [l for l in lines if not any(l.startswith(v + "=") for v in dead_vars)]
                if len(out) < len(lines):
                    ENV_ORG_PATH.write_text("".join(out))
                    log.write_line(f"[green]✓[/] Pruned {len(lines) - len(out)} dead keys from .env.organized")

            elapsed = time.monotonic() - t0
            progress.progress = 100
            status_label.update(f"✅ Complete — {valid} valid, {dead} dead, {len(results)} total ({elapsed:.1f}s)")
            log.write_line(f"\n[bold cyan]── Done ({elapsed:.1f}s) ──[/]")

            # Toast notification
            self.app.notify(
                f"{valid} valid, {dead} dead, {len(results)} total",
                title="Audit Complete",
                timeout=8,
            )

        except Exception as e:
            status_label.update(f"❌ Error: {e}")
            log.write_line(f"\n[bold red]❌ {type(e).__name__}: {e}[/]")
        finally:
            self.is_running = False
            self.query_one("#btn-start", Button).disabled = False


# ═══════════════════════════════════════════════════════════════════════════
#  Organize Screen
# ═══════════════════════════════════════════════════════════════════════════
class OrganizeScreen(Screen):
    BINDINGS = [Binding("escape", "go_back", "Back", priority=True)]

    def action_go_back(self) -> None:
        self.app.pop_screen()

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll():
            yield Label("  Organize .env", classes="screen-title")
            yield Log(id="org-log", auto_scroll=True)
        yield Footer()

    def on_mount(self) -> None:
        self.run_organize()

    @work(exclusive=True)
    async def run_organize(self) -> None:
        log = self.query_one("#org-log", Log)
        try:
            if not ENV_PATH.exists():
                log.write_line("❌ No .env file found")
                return
            import organize_env
            log.write_line("⏳ Organizing .env...")
            result = await asyncio.to_thread(organize_env.organize, ENV_PATH, ENV_ORG_PATH)
            log.write_line(f"✓ Organized {result['total']} entries into {result['categories']} categories")
            log.write_line(f"✓ Output → {ENV_ORG_PATH.name}")
            if result.get("unparseable", 0):
                log.write_line(f"⚠ {result['unparseable']} unparseable lines appended as comments")
            log.write_line("\nDone. Press [Escape] to go back.")
        except Exception as e:
            log.write_line(f"❌ {type(e).__name__}: {e}")


# ═══════════════════════════════════════════════════════════════════════════
#  Report Screen — drill into audit_report.json with Summary tab
# ═══════════════════════════════════════════════════════════════════════════
class ReportScreen(Screen):
    BINDINGS = [Binding("escape", "go_back", "Back", priority=True)]

    def action_go_back(self) -> None:
        self.app.switch_mode("dashboard")

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="report-scroll"):
            yield Label("  Audit Report Detail", classes="screen-title")
            with TabbedContent():
                with TabPane("Summary", id="tab-summary"):
                    yield Static(id="report-summary")
                with TabPane("By Provider", id="tab-provider"):
                    yield DataTable(id="report-provider-table")
                with TabPane("By Status", id="tab-status"):
                    yield DataTable(id="report-status-table")
                with TabPane("Raw JSON", id="tab-json"):
                    yield Log(id="report-json", auto_scroll=True)
        yield Footer()

    def on_mount(self) -> None:
        pt = self.query_one("#report-provider-table", DataTable)
        pt.cursor_type = "row"
        pt.add_columns("Provider", "Total", "Valid", "Failed", "Errors")
        st = self.query_one("#report-status-table", DataTable)
        st.cursor_type = "row"
        st.add_columns("Status", "Count", "Providers")
        self._load_report()

    def on_screen_resume(self) -> None:
        self._load_report()

    def _load_report(self) -> None:
        data, summary = _load_report_data()

        # Summary tab
        sw = self.query_one("#report-summary", Static)
        if summary:
            valid = summary.get("valid", 0)
            failed = summary.get("failed", 0)
            errors = summary.get("errors", 0)
            total = summary.get("total_keys", 0)
            pct = f"{valid/total*100:.0f}%" if total else "—"
            lines = [
                "",
                f"  [bold]Audit Summary[/]",
                f"  {'─' * 40}",
                f"  Total keys audited:    [bold]{total}[/]",
                f"  Valid:                 [green]{valid}[/]  ({pct})",
                f"  Failed:               [red]{failed}[/]",
                f"  Errors:               [yellow]{errors}[/]",
                f"  {'─' * 40}",
                f"  Providers checked:     {summary.get('providers_checked', '—')}",
                f"  Providers skipped:     {summary.get('providers_skipped', 0)}",
                f"  Cache hits:            {summary.get('cache_hits', 0)}",
                f"  Cache misses:          {summary.get('cache_misses', 0)}",
                f"  Auto-detected:         {summary.get('auto_detected', 0)}",
                f"  Avg latency:           {summary.get('avg_latency_ms', 0):.0f}ms",
                "",
            ]
            sw.update("\n".join(lines))
        elif data:
            valid = sum(1 for r in data if r.get("status") == "valid")
            sw.update(f"\n  [dim]No summary available (legacy format). {len(data)} results, {valid} valid.[/]\n")
        else:
            sw.update("\n  [dim]No report found. Run an audit first.[/]\n")

        # Provider table
        pt = self.query_one("#report-provider-table", DataTable)
        pt.clear()
        st = self.query_one("#report-status-table", DataTable)
        st.clear()
        jlog = self.query_one("#report-json", Log)
        jlog.clear()

        if not data:
            return

        from collections import Counter
        providers: dict[str, Counter] = {}
        for r in data:
            p = r.get("provider", "?")
            providers.setdefault(p, Counter())[r.get("status", "?")] += 1
        for p, counts in sorted(providers.items()):
            total = sum(counts.values())
            v = counts.get("valid", 0)
            f = counts.get("auth_failed", 0) + counts.get("suspended_account", 0)
            e = counts.get("network_error", 0)
            pt.add_row(p, str(total), str(v), str(f), str(e))

        # Status table
        status_groups: dict[str, list[str]] = {}
        for r in data:
            s = r.get("status", "?")
            status_groups.setdefault(s, []).append(r.get("provider", "?"))
        for s, provs in sorted(status_groups.items()):
            unique = sorted(set(provs))
            st.add_row(s, str(len(provs)), ", ".join(unique))

        # Raw JSON
        try:
            raw = json.loads(REPORT_PATH.read_text())
            jlog.write(json.dumps(raw, indent=2))
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════════
#  Help Screen
# ═══════════════════════════════════════════════════════════════════════════
class HelpScreen(Screen):
    BINDINGS = [
        Binding("escape", "go_back", "Back", priority=True),
        Binding("question_mark", "go_back", "Back", priority=True),
    ]

    def action_go_back(self) -> None:
        self.app.switch_mode("dashboard")

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="help-scroll"):
            yield Static(
                "\n"
                "  [bold cyan]check_please — Keybindings[/]\n"
                "  ─────────────────────────────────────\n"
                "\n"
                "  [bold]Navigation[/]\n"
                "  [cyan]d[/]         Dashboard\n"
                "  [cyan]a[/]         Run Audit\n"
                "  [cyan]p[/]         Report\n"
                "  [cyan]?[/]         This help screen\n"
                "  [cyan]q[/]         Quit\n"
                "  [cyan]Escape[/]    Back / close\n"
                "\n"
                "  [bold]Dashboard[/]\n"
                "  [cyan]o[/]         Organize .env\n"
                "  [cyan]r[/]         Refresh stats\n"
                "\n"
                "  [bold]Audit Screen[/]\n"
                "  Click [bold]Start Audit[/] to run the full pipeline:\n"
                "  organize → self-test → audit → report → prune\n"
                "\n"
                "  [bold]Report Screen[/]\n"
                "  [cyan]Tab[/]       Switch between Summary / Provider / Status / JSON\n"
                "\n"
                "  [bold]CLI Equivalents[/]\n"
                "  [dim]python -m credential_auditor --env .env[/]\n"
                "  [dim]python -m credential_auditor --list-providers[/]\n"
                "  [dim]python -m credential_auditor --dry-run --env .env[/]\n"
                "  [dim]python -m credential_auditor --json --env .env[/]\n"
                "\n",
                id="help-content",
            )
        yield Footer()


# ═══════════════════════════════════════════════════════════════════════════
#  Main App
# ═══════════════════════════════════════════════════════════════════════════
class CheckPleaseApp(App):
    """check_please — Credential Audit Pipeline."""

    TITLE = "check_please"
    SUB_TITLE = "credential audit pipeline"
    CSS_PATH = "tui.tcss"

    MODES = {
        "dashboard": DashboardScreen,
        "audit": AuditScreen,
        "report": ReportScreen,
        "help": HelpScreen,
    }
    DEFAULT_MODE = "dashboard"

    BINDINGS = [
        Binding("d", "switch_mode('dashboard')", "Dashboard", show=True),
        Binding("a", "switch_mode('audit')", "Audit", show=True),
        Binding("p", "switch_mode('report')", "Report", show=True),
        Binding("question_mark", "switch_mode('help')", "Help", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]


if __name__ == "__main__":
    CheckPleaseApp().run()
