#!/usr/bin/env bash
# Build ptrace_fa binaries on the builder VM.
# Usage: build.sh <source_dir> <outdir> <target_hex>
set -euo pipefail

dpkg -s gcc >/dev/null 2>&1 || {
  sudo apt-get update
  sudo apt-get install -y gcc
}

rm -rf "$2"
mkdir -p "$2"
cp -a "$1"/. "$2"/
cd "$2"

old_target='0xc0, 0xa8, 0x64, 0x01, 0x66, 0x68, 0x11, 0x5c'
sed -i "s/$old_target/$3/" src/shellcode_inject_fa.c
grep -Fq "$3" src/shellcode_inject_fa.c

gcc -Wall -Wextra -o shellcode_inject_fa \
  src/shellcode_inject_fa.c common/ptrace_utils.c common/utils.c
gcc -o victim src/victim.c

echo "FACT arch=$(uname -m)"
packages=$(dpkg-query -W -f='${Package}=${Version} ' libc6 gcc)
echo "FACT packages=$packages"
