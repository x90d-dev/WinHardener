set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[WinHardener] Verifying Python 3.9+ runtime environment..."
if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] Python 3 was not found in PATH. Install Python 3.9+ before running WinHardener."
    exit 1
fi

if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"; then
    echo "[ERROR] WinHardener requires Python 3.9 or newer. Detected: $(python3 --version)"
    exit 1
fi

if [ ! -d ".venv" ]; then
    echo "[WinHardener] Creating virtual environment (.venv)..."
    python3 -m venv .venv
fi

# shellcheck disable=SC1091
source ".venv/bin/activate"

if [ ! -f ".venv/installed_marker.txt" ] && [ -f "requirements.txt" ]; then
    echo "[WinHardener] Installing dependencies from requirements.txt..."
    python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
    pip install -r requirements.txt
    date -u +"%Y-%m-%dT%H:%M:%SZ" > ".venv/installed_marker.txt"
fi

echo "[WinHardener] Executing host security posture audit..."
if [ $# -eq 0 ]; then
    python3 winhardener.py --audit-all
else
    python3 winhardener.py "$@"
fi
