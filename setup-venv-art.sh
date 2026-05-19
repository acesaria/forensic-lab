#!/bin/bash
set -e

VENV_DIR=".venv-art"
PYTHON_VERSION=$(python3 -c 'import sys; print(sys.version_info.minor)')
MODELS_PATH="${VENV_DIR}/lib/python3.${PYTHON_VERSION}/site-packages/atomic_operator/models.py"
MARKER_FILE="${VENV_DIR}/.patch-applied"

if [ -d "$VENV_DIR" ] && [ -f "$MARKER_FILE" ]; then
    echo "[*] .venv-art already ready"
    exit 0
fi

if [ -z "$1" ]; then
    echo "Usage: $0 <path-to-atomic-operator-repo>"
    exit 1
fi

ATOMIC_OP_PATH="$1"
if [ ! -d "$ATOMIC_OP_PATH" ]; then
    echo "[!] atomic-operator path not found: $ATOMIC_OP_PATH"
    exit 1
fi

echo "[+] Creating venv..."
python3 -m venv "$VENV_DIR"

echo "[+] Installing atomic-operator..."
"${VENV_DIR}/bin/pip" install --quiet "$ATOMIC_OP_PATH"

echo "[+] Applying models.py patch..."
if [ ! -f "$MODELS_PATH" ]; then
    echo "[!] models.py not found: $MODELS_PATH"
    exit 1
fi

sed -i 's/Base\.get_abs_path(value)/os.path.abspath(os.path.expanduser(os.path.expandvars(value)))/' "$MODELS_PATH"

touch "$MARKER_FILE"
echo "[+] .venv-art ready"
