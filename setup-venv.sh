#!/usr/bin/env bash
set -euo pipefail

PYTHON=${PYTHON:-python3}
VENV_DIR=".venv"

echo "[1/3] creating venv..."
"$PYTHON" -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip

echo "[2/3] installing project dependencies..."
"$VENV_DIR/bin/pip" install --quiet -r requirements.txt

echo "[3/3] verifying..."
"$VENV_DIR/bin/pip" check && echo "  pip check: ok"
"$VENV_DIR/bin/python" -c "
import paramiko
print('  paramiko          ', paramiko.__version__)
print('all ok')
"

echo ""
echo "setup complete. activate with: source $VENV_DIR/bin/activate"
