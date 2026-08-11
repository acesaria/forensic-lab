#!/usr/bin/env bash
# Build Father's rk.so on the builder VM.
# Usage: build.sh <archive> <outdir> <hidden_prefix>
set -euo pipefail

dpkg -s gcc make libpam0g-dev libgcrypt20-dev >/dev/null 2>&1 || {
  sudo apt-get update
  sudo apt-get install -y gcc make libpam0g-dev libgcrypt20-dev
}

rm -rf "$2"
mkdir -p "$2"
tar -xf "$1" -C "$2"
cd "$2"/Father-*

sed -i "s|^#define STRING .*|#define STRING \"$3\"|" src/config.h
make father

echo "FACT arch=$(uname -m)"
packages=$(dpkg-query -W -f='${Package}=${Version} ' libc6 gcc make libpam0g-dev libgcrypt20-dev)
echo "FACT packages=$packages"
