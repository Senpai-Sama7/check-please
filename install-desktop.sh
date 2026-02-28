#!/usr/bin/env bash
# One-click desktop installer for check_please
set -euo pipefail

APP_NAME="check-please"
INSTALL_DIR="$HOME/.local/share/$APP_NAME"
BIN_DIR="$HOME/.local/bin"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
DESKTOP_DIR="$HOME/.local/share/applications"
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

info()  { printf "${CYAN}▸${NC} %s\n" "$1"; }
ok()    { printf "${GREEN}✓${NC} %s\n" "$1"; }
fail()  { printf "${RED}✗${NC} %s\n" "$1"; exit 1; }

# ── Preflight ──
command -v python3 >/dev/null 2>&1 || fail "python3 not found"
PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null \
    || fail "Python 3.10+ required (found $PYVER)"

# ── Handle uninstall ──
if [ "${1:-}" = "--uninstall" ]; then
    info "Uninstalling $APP_NAME..."
    rm -rf "$INSTALL_DIR"
    rm -f "$BIN_DIR/$APP_NAME-desktop"
    rm -f "$DESKTOP_DIR/$APP_NAME.desktop"
    rm -f "$ICON_DIR/$APP_NAME.svg"
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
    ok "Uninstalled"
    exit 0
fi

# ── Install ──
info "Installing check_please to $INSTALL_DIR"

mkdir -p "$INSTALL_DIR" "$BIN_DIR" "$ICON_DIR" "$DESKTOP_DIR"

# Sync project files (exclude dev/runtime artifacts)
rsync -a --delete \
    --exclude '.venv' --exclude '__pycache__' --exclude '.git' \
    --exclude '.env' --exclude '.env.*' --exclude '*.pyc' \
    --exclude '.mypy_cache' --exclude '.pytest_cache' \
    --exclude 'audit.log' --exclude 'agent_access.log' \
    --exclude 'audit_report.json' --exclude 'dist' --exclude 'build' \
    --exclude '*.egg-info' \
    "$SOURCE_DIR/" "$INSTALL_DIR/"
ok "Copied project files"

# Set up venv + deps
info "Setting up Python environment..."
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install --quiet "$INSTALL_DIR"
ok "Dependencies installed"

# ── Desktop launcher script ──
cat > "$BIN_DIR/$APP_NAME-desktop" << 'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail
APP_DIR="$HOME/.local/share/check-please"
PYTHON="$APP_DIR/.venv/bin/python"
URL="http://127.0.0.1:8457"

# Kill any existing instance on our port
fuser -k 8457/tcp 2>/dev/null || true
sleep 0.2

# Start web server in background
cd "$APP_DIR"
"$PYTHON" simple_web.py &
SERVER_PID=$!

# Wait for server to be ready
for i in $(seq 1 30); do
    if curl -s -o /dev/null "$URL" 2>/dev/null; then break; fi
    sleep 0.1
done

# Open in app mode (chromium/chrome) or fall back to default browser
open_app_window() {
    for browser in chromium chromium-browser google-chrome google-chrome-stable; do
        if command -v "$browser" >/dev/null 2>&1; then
            "$browser" --app="$URL" --new-window 2>/dev/null &
            return 0
        fi
    done
    return 1
}

open_app_window || xdg-open "$URL" 2>/dev/null || "$PYTHON" -m webbrowser "$URL"

# Keep running until server exits
wait $SERVER_PID 2>/dev/null
LAUNCHER
chmod +x "$BIN_DIR/$APP_NAME-desktop"
ok "Created launcher at $BIN_DIR/$APP_NAME-desktop"

# ── Icon ──
cp "$SOURCE_DIR/desktop/check-please.svg" "$ICON_DIR/$APP_NAME.svg"
ok "Installed icon"

# ── Desktop entry ──
sed "s|Exec=.*|Exec=$BIN_DIR/$APP_NAME-desktop|" \
    "$SOURCE_DIR/desktop/check-please.desktop" > "$DESKTOP_DIR/$APP_NAME.desktop"
chmod +x "$DESKTOP_DIR/$APP_NAME.desktop"
update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
ok "Installed desktop entry"

echo ""
printf "${GREEN}✓ Installed!${NC}\n"
echo ""
echo "  Launch from:  App menu → 'Check Please'"
echo "  Or terminal:  $APP_NAME-desktop"
echo "  Uninstall:    $0 --uninstall"
echo ""
