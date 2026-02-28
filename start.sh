#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# start.sh — Install, verify, and run the full credential pipeline
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

VENV="$DIR/.venv"
ENV_FILE="$DIR/.env"
ORGANIZED="$DIR/.env.organized"
REPORT="$DIR/audit_report.json"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

MODE=""
DRY_RUN=false
SHOW_HELP=false
EXTRA_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --tui|-t) MODE="tui" ;;
        --easy|-e) MODE="easy" ;;
        --simple|-s) MODE="simple" ;;
        --web|-w) MODE="web" ;;
        --guide) MODE="guide" ;;
        --agent-api|-a) MODE="agent-api" ;;
        --agent-env) MODE="agent-env" ;;
        --agent-export) MODE="agent-export" ;;
        --agent-mcp) MODE="agent-mcp" ;;
        --dry-run) DRY_RUN=true ;;
        --help|-h) SHOW_HELP=true ;;
        *) EXTRA_ARGS+=("$arg") ;;
    esac
done

# Default mode: first run → guide, subsequent → easy
if [[ -z "$MODE" && ${#EXTRA_ARGS[@]} -eq 0 && "$DRY_RUN" == "false" && "$SHOW_HELP" == "false" ]]; then
    if [[ ! -f "$DIR/.check_please_seen" ]]; then
        MODE="guide"
    else
        MODE="easy"
    fi
fi

if $SHOW_HELP; then
    printf "${BOLD}check_please${NC} — credential audit pipeline\n\n"
    printf "${BOLD}Usage:${NC}\n"
    printf "  ./start.sh              Easy mode (guided, recommended)\n"
    printf "  ./start.sh --easy       Easy mode — step-by-step wizard\n"
    printf "  ./start.sh --simple     Simple menu — numbered options\n"
    printf "  ./start.sh --web        Web browser — visual interface\n"
    printf "  ./start.sh --tui        Terminal UI — rich visual interface\n"
    printf "  ./start.sh --guide      Quick start — first-time tutorial\n"
    printf "  ./start.sh --agent-api   Credential broker for AI agents\n"
    printf "  ./start.sh --agent-env   Launch agent with credentials as env vars\n"
    printf "  ./start.sh --agent-export Print export statements for eval/source\n"
    printf "  ./start.sh --agent-mcp   MCP server for Claude Code, Copilot, etc.\n"
    printf "  ./start.sh --dry-run    Preview what would be audited\n"
    printf "  ./start.sh --help       Show this help\n"
    printf "\n${BOLD}For beginners:${NC}\n"
    printf "  Just run ${CYAN}./start.sh${NC} — it will guide you through everything.\n"
    printf "\n${BOLD}Full pipeline (advanced):${NC}\n"
    printf "  Pass extra flags to run the full CLI pipeline:\n"
    printf "  ./start.sh --json       Print JSON to stdout\n"
    printf "  ./start.sh --quiet      Suppress table output\n"
    printf "  ./start.sh --env FILE   Use a specific .env file\n"
    exit 0
fi

step=0
fail() { printf '\n\033[0;31m✗ FAILED at step %d: %s\033[0m\n' "$step" "$1" >&2; exit 1; }
info() { printf '\033[0;36m▸ %s\033[0m\n' "$1"; }
ok()   { printf '\033[0;32m✓ %s\033[0m\n' "$1"; }
warn() { printf '\033[1;33m⚠ %s\033[0m\n' "$1"; }

# ── Step 1: Verify Python ─────────────────────────────────────
step=$((step+1))
info "Making sure everything is ready..."
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c 'import sys; print(sys.version_info[:2])' 2>/dev/null) || continue
        major=$("$cmd" -c 'import sys; print(sys.version_info[0])')
        minor=$("$cmd" -c 'import sys; print(sys.version_info[1])')
        if (( major == 3 && minor >= 10 )); then
            PYTHON="$cmd"
            break
        fi
    fi
done
[[ -z "$PYTHON" ]] && fail "Python 3.10+ required but not found"
ok "Found $PYTHON ($($PYTHON --version 2>&1))"

# ── Step 2: Create / verify venv ──────────────────────────────
step=$((step+1))
info "Setting things up (one-time setup)..."
if [[ ! -d "$VENV" ]]; then
    "$PYTHON" -m venv "$VENV" || fail "Could not create venv at $VENV"
    ok "Created venv"
elif [[ ! -f "$VENV/bin/activate" ]]; then
    warn "Corrupt venv detected — recreating"
    rm -rf "$VENV"
    "$PYTHON" -m venv "$VENV" || fail "Could not recreate venv"
    ok "Recreated venv"
else
    ok "Venv exists"
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate" || fail "Could not activate venv"

# ── Step 3: Install dependencies ──────────────────────────────
step=$((step+1))
info "Installing what we need..."
pip install --quiet --upgrade pip 2>/dev/null || true

REQS="$DIR/credential_auditor/requirements.txt"
if [[ -f "$REQS" ]]; then
    pip install --quiet -r "$REQS" 2>&1 | tail -3 || fail "pip install failed for $REQS"
else
    warn "No requirements.txt found — installing defaults"
    pip install --quiet httpx rich python-dotenv || fail "pip install failed"
fi
if [[ "$MODE" == "tui" ]]; then
    pip install --quiet textual 2>/dev/null || fail "pip install textual failed"
fi
ok "Dependencies installed"

# ── Step 4: Verify .env exists ────────────────────────────────
step=$((step+1))
info "Looking for your API keys..."
if [[ ! -f "$ENV_FILE" ]]; then
    fail "No .env file found — put your API keys in a file called .env in this folder"
fi
line_count=$(wc -l < "$ENV_FILE")
ok "Found your .env file ($line_count lines)"

# Mark first run complete
touch "$DIR/.check_please_seen"

# ── Mode dispatch: easy/simple/web/tui/guide ──────────────────
case "$MODE" in
    easy)
        echo ""
        python "$DIR/easy_mode.py"
        exit 0
        ;;
    simple)
        echo ""
        python "$DIR/simple_cli.py"
        exit 0
        ;;
    web)
        echo ""
        python "$DIR/simple_web.py"
        exit 0
        ;;
    tui)
        echo ""
        python "$DIR/tui.py"
        exit 0
        ;;
    guide)
        echo ""
        python "$DIR/quick_start_guide.py"
        exit 0
        ;;
    agent-api)
        echo ""
        python "$DIR/agent_api.py" --serve
        exit 0
        ;;
    agent-env)
        echo ""
        if [ ${#EXTRA_ARGS[@]} -eq 0 ]; then
            printf "${RED}✗ Usage: ./start.sh --agent-env COMMAND [ARGS...]${NC}\n"
            printf "  Example: ./start.sh --agent-env codex\n"
            exit 2
        fi
        python "$DIR/agent_api.py" --env "${EXTRA_ARGS[@]}"
        exit $?
        ;;
    agent-export)
        python "$DIR/agent_api.py" --export
        exit 0
        ;;
    agent-mcp)
        python "$DIR/agent_api.py" --mcp
        exit 0
        ;;
esac

# ── Dry run: show what would be audited ───────────────────────
if $DRY_RUN; then
    python -m credential_auditor --dry-run --env "$ENV_FILE"
    exit 0
fi

# ── Step 5: File permissions check ────────────────────────────
step=$((step+1))
info "Checking .env permissions..."
perms=$(stat -c '%a' "$ENV_FILE" 2>/dev/null || stat -f '%Lp' "$ENV_FILE" 2>/dev/null)
if [[ "$perms" =~ [0-7]*[4-7]$ ]]; then
    warn ".env is world-readable (mode $perms) — consider: chmod 640 .env"
else
    ok ".env permissions OK (mode $perms)"
fi

# ── Step 6: Organize .env ─────────────────────────────────────
step=$((step+1))
info "Organizing .env → .env.organized..."
if [[ ! -f "$DIR/organize_env.py" ]]; then
    warn "organize_env.py not found — skipping organization step"
else
    python organize_env.py "$ENV_FILE" "$ORGANIZED" || fail "organize_env.py failed"
    ok "Organized env written to .env.organized"
fi

# ── Step 7: Credential auditor self-test ──────────────────────
step=$((step+1))
info "Running credential auditor self-test..."
if ! python -m credential_auditor --self-test; then
    fail "Self-test failed — auditor may be broken"
fi
ok "Self-test passed"

# ── Step 8: Audit credentials ─────────────────────────────────
step=$((step+1))
AUDIT_INPUT="$ENV_FILE"
if [[ -f "$ORGANIZED" ]]; then
    AUDIT_INPUT="$ORGANIZED"
    info "Auditing credentials in .env.organized (clean file)..."
else
    info "Auditing credentials in .env..."
fi
echo ""
audit_exit=0
python -m credential_auditor --env "$AUDIT_INPUT" --output "$REPORT" --force-insecure-output --timeout 30 || audit_exit=$?

echo ""
case $audit_exit in
    0) ok "All credentials valid" ;;
    1) warn "Some credentials have issues — review output above" ;;
    2) fail "Auditor configuration error" ;;
    *) fail "Unexpected exit code: $audit_exit" ;;
esac

if [[ -f "$REPORT" ]]; then
    ok "JSON report saved to $REPORT"
fi

# ── Step 9: Prune dead keys from organized file ──────────────
step=$((step+1))
if [[ -f "$REPORT" && -f "$ORGANIZED" ]]; then
    info "Pruning dead keys (auth_failed) from .env.organized..."
    pruned=$(python3 -c "
import json, re
raw = json.load(open('$REPORT'))
report = raw.get('results', raw) if isinstance(raw, dict) else raw
dead = [r['env_var'] for r in report if r['status'] in ('auth_failed', 'invalid_format')]
if not dead:
    print('0')
else:
    lines = open('$ORGANIZED').readlines()
    out = [l for l in lines if not any(l.startswith(k + '=') for k in dead)]
    open('$ORGANIZED', 'w').writelines(out)
    print(len(dead))
" 2>/dev/null)
    if [[ "$pruned" == "0" ]]; then
        ok "No dead keys to prune"
    else
        ok "Pruned $pruned dead keys from .env.organized"
    fi
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
printf '\033[1m═══════════════════════════════════════════════\033[0m\n'
printf '\033[1m Pipeline complete\033[0m\n'
printf '\033[1m═══════════════════════════════════════════════\033[0m\n'
printf '  .env.organized : %s\n' "$ORGANIZED"
printf '  Audit report   : %s\n' "$REPORT"
printf '  Venv           : %s\n' "$VENV"
echo ""
warn "If any credentials failed validation, rotate them immediately."
