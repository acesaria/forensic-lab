#!/usr/bin/env bash
# Build bad-bpf eBPF programs on the builder VM.
# Usage: build.sh <archive> <outdir> <xcrypto-source>
#
#   archive         path to the vendored bad-bpf tar.gz archive
#   outdir          scratch directory for extraction + build
#   xcrypto-source  path to the lab-owned XCrypto source
set -euo pipefail

ARCHIVE="$1"
OUTDIR="$2"
XCRYPTO_SOURCE="$3"

kernel=$(uname -r)

# ---------------------------------------------------------------------------
# Install build dependencies
# ---------------------------------------------------------------------------
needed="gcc clang llvm libelf-dev zlib1g-dev pkg-config make linux-headers-${kernel}"
tools_pkg="linux-tools-${kernel} linux-tools-common linux-tools-generic"
echo "STEP installing build dependencies..."
dpkg -s $needed $tools_pkg >/dev/null 2>&1 || {
    sudo apt-get update -q
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y $needed $tools_pkg
}
echo "STEP dependencies ready"

# Locate system bpftool (bad-bpf uses it to generate BPF skeletons)
BPFTOOL_BIN=""
for candidate in \
    "/usr/lib/linux-tools/${kernel}/bpftool" \
    $(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1) \
    "$(command -v bpftool 2>/dev/null)"
do
    if [[ -x "${candidate:-}" ]]; then
        BPFTOOL_BIN="$candidate"
        break
    fi
done
[[ -n "${BPFTOOL_BIN}" ]] || { echo "bpftool not found" >&2; exit 1; }
echo "Using bpftool: ${BPFTOOL_BIN}"

# ---------------------------------------------------------------------------
# Extract source archive
# ---------------------------------------------------------------------------
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"
tar -xzf "$ARCHIVE" -C "$OUTDIR"

SRC_DIR="$(ls -d "$OUTDIR"/bad-bpf-*/src 2>/dev/null | head -1)"
[[ -n "$SRC_DIR" ]] || { echo "bad-bpf src/ not found after extraction" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Regenerate vmlinux.h for the running kernel (CO-RE, ensures accuracy)
# ---------------------------------------------------------------------------
[[ -r /sys/kernel/btf/vmlinux ]] || {
    echo "/sys/kernel/btf/vmlinux missing — kernel BTF is required" >&2
    exit 1
}
echo "STEP regenerating vmlinux.h for kernel ${kernel}..."
arch=$(uname -m | sed 's/x86_64/x86/')
"$BPFTOOL_BIN" btf dump file /sys/kernel/btf/vmlinux format c \
    > "$(dirname "$SRC_DIR")/vmlinux/${arch}/vmlinux.h"
echo "STEP vmlinux.h regenerated"

# ---------------------------------------------------------------------------
# Build pidhide and exechijack
# ---------------------------------------------------------------------------
cd "$SRC_DIR"

echo "STEP building bad-bpf programs..."
make BPFTOOL="$BPFTOOL_BIN" pidhide exechijack 2>&1
echo "STEP bad-bpf programs built"

# ---------------------------------------------------------------------------
# Collect artifacts
# ---------------------------------------------------------------------------
ART_DIR="$OUTDIR/artifacts"
mkdir -p "$ART_DIR"
cp pidhide    "$ART_DIR/"
cp exechijack "$ART_DIR/"
gcc -Wall -Wextra -Werror -O2 "$XCRYPTO_SOURCE" -o "$ART_DIR/xcrypto"
chmod +x "$ART_DIR/"*

echo "FACT arch=$(uname -m)"
echo "FACT kernel=${kernel}"
packages=$(dpkg-query -W -f='${Package}=${Version} ' gcc clang libelf-dev "linux-tools-${kernel}" 2>/dev/null || true)
echo "FACT packages=${packages}"
