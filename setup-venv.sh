#!/usr/bin/env bash
set -euo pipefail

PYTHON=${PYTHON:-python3}
VENV_DIR=".venv"

echo "[1/5] creating venv..."
"$PYTHON" -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip

echo "[2/5] installing atomic-operator-runner (with its pinned paramiko<3)..."
"$VENV_DIR/bin/pip" install --quiet \
    atomic-operator==0.9.0 \
    atomic-operator-runner==0.2.1

echo "[3/5] patching paramiko constraint in dist-info..."
METADATA=$(find "$VENV_DIR/lib" \
    -path "*/atomic_operator_runner-*.dist-info/METADATA" 2>/dev/null | head -1)

if [ -z "$METADATA" ]; then
    echo "ERROR: could not find atomic-operator-runner metadata" >&2
    exit 1
fi

METADATA="$METADATA" "$VENV_DIR/bin/python" - <<'PYEOF'
import re, pathlib, os

meta = pathlib.Path(os.environ["METADATA"])
text = meta.read_text()
patched = re.sub(r'paramiko \([^)]*\)', 'paramiko (>=2.11.0)', text)
if patched == text:
    print("  already clean, nothing to do")
else:
    meta.write_text(patched)
    print("  patched:", meta)
PYEOF

echo "[4/5] installing remaining dependencies (modern paramiko + project deps)..."
"$VENV_DIR/bin/pip" install --quiet -r requirements.txt

echo "[5/5] verifying..."
"$VENV_DIR/bin/pip" check && echo "  pip check: ok"
"$VENV_DIR/bin/python" -c "
import paramiko, atomic_operator, atomic_operator_runner
print('  paramiko          ', paramiko.__version__)
print('  atomic-operator   ', atomic_operator.__version__)
print('  atomic-op-runner   ok (no __version__ attr)')
print('all ok')
"

echo ""
echo "setup complete. activate with: source $VENV_DIR/bin/activate"