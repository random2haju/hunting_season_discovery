#!/bin/bash
set -e

echo "============================================================"
echo " Threat Hunt Dashboard — Setup"
echo "============================================================"
echo

# ── Python dependencies ──────────────────────────────────────
echo "[1/3] Installing Python dependencies..."
pip install -r web/requirements.txt
echo

# ── Node.js check ────────────────────────────────────────────
echo "[2/3] Checking for Node.js..."
if ! command -v node &>/dev/null; then
  echo "[ERROR] Node.js not found."
  echo "        Install via Homebrew:  brew install node"
  echo "        Or download from:      https://nodejs.org"
  exit 1
fi
node --version
echo

# ── Frontend build ───────────────────────────────────────────
echo "[3/3] Installing and building the React frontend..."
cd web/frontend
npm install
npm run build
cd ../..

echo
echo "============================================================"
echo " Setup complete.  Start the dashboard with:"
echo "   python web/app.py"
echo "============================================================"
