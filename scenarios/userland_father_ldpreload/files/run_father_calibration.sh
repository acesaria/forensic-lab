#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "$#" -ne 6 ]]; then
    echo "usage: $0 ROOT INSTALLED_LIBRARY PRELOAD_CONFIG BACKUP ABSENT_MARKER DURATION" >&2
    exit 2
fi

root=$1
installed_library=$2
preload_config=$3
preload_backup=$4
preload_absent_marker=$5
process_duration=$6

source_dir="$root/source"
father_source_tree="$source_dir/Father-4eb2712caf612a7dc55fd4f34ff5c72b74c7c332"
father_archive="$source_dir/father-upstream-4eb2712.tar"
father_config="$father_source_tree/src/config.h"
father_library="$father_source_tree/rk.so"
activation_helper="$source_dir/activate_system_preload.py"
probe_dir="$root/probe"
marker="$probe_dir/__malicious_file"
before_output="$probe_dir/before.txt"
after_output="$probe_dir/after.txt"

# Baseline prerequisites remain offline and explicit.
command -v gcc >/dev/null 2>&1
command -v make >/dev/null 2>&1
test -f /usr/include/security/pam_appl.h
test -f /usr/include/gcrypt.h
ldconfig -p | grep -q 'libgcrypt\.so'

# Extract and configure only the run-local Father source tree.
rm -rf "$father_source_tree"
mkdir -p "$source_dir" "$probe_dir"
tar -xf "$father_archive" -C "$source_dir"
test -f "$father_config"
test -f "$activation_helper"
sed -i \
    -e 's|^#define STRING .*|#define STRING "__malicious_"|' \
    -e 's|^#define PRELOAD .*|#define PRELOAD "father_calibration_nohide"|' \
    -e "s|^#define INSTALL_LOCATION .*|#define INSTALL_LOCATION \"$installed_library\"|" \
    "$father_config"
grep -Fqx '#define STRING "__malicious_"' "$father_config"
grep -Fqx '#define PRELOAD "father_calibration_nohide"' "$father_config"
grep -Fqx "#define INSTALL_LOCATION \"$installed_library\"" "$father_config"
sha256sum "$father_config"

# Build the pinned source and retain the output for acquisition.
(
    cd "$father_source_tree"
    make clean >/dev/null 2>&1 || true
    make father
)
test -f "$father_library"
sha256sum "$father_library"

# Prove the marker is visible before activation.
touch "$marker"
ls -l -- "$marker" > "$before_output" 2>&1

# The helper owns the privileged transaction, mapping checks, and rollback.
helper_json="$(
    sudo -n /usr/bin/python3 "$activation_helper" \
        --built-library "$father_library" \
        --installed-library "$installed_library" \
        --preload-config "$preload_config" \
        --backup-path "$preload_backup" \
        --absent-marker "$preload_absent_marker" \
        --duration "$process_duration"
)"
/usr/bin/python3 -c \
    'import json, sys; facts=json.loads(sys.stdin.read()); assert facts["validation_result"]["status"] == "passed"; assert len(facts["affected_pids"]) == 3' \
    <<< "$helper_json"

# A new ls is preloaded and cannot see the marker; this Bash predates activation.
after_status=0
ls -l -- "$marker" > "$after_output" 2>&1 || after_status=$?
[[ "$after_status" -ne 0 ]]
[[ -e "$marker" ]]

# Preserve the helper's existing JSON as the final structured output line.
printf '%s\n' "$helper_json"
