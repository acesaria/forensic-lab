#!/usr/bin/env bash
# Build Diamorphine for the builder VM's running kernel.
# Usage: build.sh <archive> <compatibility-patch> <outdir>
set -euo pipefail

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

kernel=$(uname -r)
headers="linux-headers-$kernel"
dpkg -s gcc make kmod patch "$headers" >/dev/null 2>&1 || {
  sudo apt-get update
  sudo apt-get install -y gcc make kmod patch "$headers"
}

symbols=/proc/kallsyms
[[ -r "$symbols" ]] || { echo "missing $symbols" >&2; exit 1; }

rm -rf "$3"
mkdir -p "$3"
tar -xf "$1" -C "$3"
cd "$3"/Diamorphine-*
patch -p1 < "$2"
if grep -qw x64_sys_call "$symbols"; then
  syscall_dispatch=x64_sys_call
  make KCFLAGS=-DDIAMORPHINE_X64_DISPATCH
elif grep -qw sys_call_table "$symbols"; then
  syscall_dispatch=sys_call_table
  make
else
  echo "unsupported syscall dispatch in $symbols" >&2
  exit 1
fi

echo "FACT arch=$(uname -m)"
echo "FACT kernel=$kernel"
echo "FACT vermagic=$(modinfo -F vermagic diamorphine.ko)"
echo "FACT syscall_dispatch=$syscall_dispatch"
packages=$(dpkg-query -W -f='${Package}=${Version} ' gcc make kmod patch "$headers")
echo "FACT packages=$packages"
