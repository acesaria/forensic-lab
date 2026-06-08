from __future__ import annotations

from typing import Any

# Artifact specs declare WHAT to look for (type + category + query), not HOW
# (tool). The detector resolves tools from artifact_type:
#   disk     -> Sleuth Kit  (_detect_disk_artifact)
#   memory   -> Volatility3 (_detect_memory_artifact, category -> plugin list)
#   timeline -> Plaso       (_detect_timeline_artifact)
#
# phase: "attack" specs describe evidence planted by the attack itself.
# phase: "cleanup" specs describe evidence left by the cleanup action — either
# deletion records for the attack artifacts or new artifacts (bash history,
# journal entries) created by the cleanup commands themselves.
#
# The evaluator processes all steps present in ground_truth regardless of phase.
# When run_cleanup=False, the cleanup step will not appear in ground_truth, so
# cleanup-phase specs are simply skipped. Both phases can coexist in this file.


ARTIFACT_SPECS_SCENARIO_01: list[dict[str, Any]] = [
    # ── Attack phase: LD_PRELOAD hook ──────────────────────────────────────────
    #
    # ART T1574.006 drops /tmp/T1574006.so and registers it in
    # /etc/ld.so.preload. The hook takes effect on the next process launch;
    # the trigger step loads a test binary to prove the hook is live.
    {
        "id": "ldpreload_config",
        "step": "ldpreload",
        "phase": "attack",
        "technique": "T1574.006",
        "artifact_type": "disk",
        "artifact_category": "config_file",
        "primary": True,
        "base_weight": 0.9,
        "query": {
            "path_equals": "/etc/ld.so.preload",
            "content_contains": "/tmp/T1574006.so",
            # After cleanup the file may be present but emptied, or deleted.
            # Treat a recovered deleted copy as found; a bare tombstone is not
            # enough — we need to confirm the hook path was in there.
            "treat_deleted_recovered_as_found": True,
            "treat_deleted_entry_as_found": False,
        },
    },
    {
        "id": "ldpreload_so_disk",
        "step": "ldpreload",
        "phase": "attack",
        "technique": "T1574.006",
        "artifact_type": "disk",
        "artifact_category": "shared_library",
        "primary": False,
        "base_weight": 0.8,
        "query": {
            "path_equals": "/tmp/T1574006.so",
            "treat_deleted_recovered_as_found": True,
            "treat_deleted_entry_as_found": False,
        },
    },
    {
        "id": "ldpreload_so_memory",
        "step": "ldpreload_trigger",
        "phase": "attack",
        "technique": "T1574.006",
        "artifact_type": "memory",
        "artifact_category": "shared_library",
        "primary": True,
        "base_weight": 1.0,
        # Routes to linux.proc.Maps via MEMORY_CATEGORY_PLUGINS["shared_library"].
        # Survives ART cleanup: the .so stays mapped in any process launched while
        # the hook was live, until that process exits or is killed.
        "query": {
            "path_substring": "T1574006.so",
        },
    },
    # ── Attack phase: reverse shell ────────────────────────────────────────────
    #
    # The scenario launches a netcat reverse shell over the LD_PRELOAD hook to
    # show the hook produces a real execution primitive, not just a library load.
    {
        "id": "reverse_shell_socket",
        "step": "reverse_shell",
        "phase": "attack",
        "technique": "T1059.004",
        "artifact_type": "memory",
        "artifact_category": "network_socket",
        "primary": True,
        "base_weight": 0.9,
        # Routes to linux.sockstat via MEMORY_CATEGORY_PLUGINS["network_socket"].
        "query": {
            "port": 4444,
            "process_names": ["nc", "sh"],
        },
    },
    {
        "id": "reverse_shell_fifo",
        "step": "reverse_shell",
        "phase": "attack",
        "technique": "T1059.004",
        "artifact_type": "disk",
        "artifact_category": "pipe",
        "primary": False,
        "base_weight": 0.7,
        "query": {
            "path_equals": "/tmp/.rs_fifo",
            "treat_deleted_recovered_as_found": True,
            "treat_deleted_entry_as_found": False,
        },
    },
    {
        "id": "reverse_shell_history",
        "step": "reverse_shell",
        "phase": "attack",
        "technique": "T1059.004",
        "artifact_type": "timeline",
        "artifact_category": "shell_history",
        "primary": True,
        "base_weight": 0.9,
        "query": {
            "message_contains_any": [
                "mkfifo /tmp/.rs_fifo",
                "nc ",
                "/tmp/.rs_fifo",
            ],
        },
    },
    # ── Cleanup phase: ART-style evasion ──────────────────────────────────────
    #
    # ART cleanup for T1574.006 runs:
    #   sed -i '/T1574006.so/d' /etc/ld.so.preload
    #   rm -f /tmp/T1574006.so
    #
    # This step is only present in ground_truth when run_cleanup=True.
    # The specs below measure two things:
    #   (a) Deletion records for the attack artifacts — evidence the attack
    #       happened even after the attacker tried to erase it.
    #   (b) New artifacts created by the cleanup commands themselves — the
    #       cleanup action is itself an IoC.
    #
    # Note: the attack-phase disk specs (ldpreload_config, ldpreload_so_disk)
    # still run in cleanup mode and will detect recovered/tombstone states via
    # treat_deleted_recovered_as_found. The specs below add the cleanup-specific
    # evidence on top.
    {
        "id": "cleanup_so_deletion_record",
        "step": "cleanup",
        "phase": "cleanup",
        "technique": "T1070.004",
        "artifact_type": "disk",
        "artifact_category": "deleted_file",
        "primary": True,
        "base_weight": 0.7,
        # treat_deleted_entry_as_found: True — here the tombstone IS the point.
        # Even if the content is gone, the directory entry proves the file existed
        # and was removed. This is the most commonly recoverable cleanup artifact.
        "query": {
            "path_equals": "/tmp/T1574006.so",
            "treat_deleted_recovered_as_found": True,
            "treat_deleted_entry_as_found": True,
        },
    },
    {
        "id": "cleanup_rm_history",
        "step": "cleanup",
        "phase": "cleanup",
        "technique": "T1070.004",
        "artifact_type": "timeline",
        "artifact_category": "shell_history",
        "primary": True,
        "base_weight": 0.8,
        # Bash history surviving in ~/.bash_history or recovered from ext4
        # journal. This is the most reliable cleanup IoC: ART's rm command
        # is executed as the lab user, so it lands in bash history unless the
        # attacker ran 'history -c' or set HISTFILE=/dev/null first.
        "query": {
            "message_contains_any": [
                "rm -f /tmp/T1574006.so",
                "rm /tmp/T1574006.so",
            ],
        },
    },
    {
        "id": "cleanup_sed_history",
        "step": "cleanup",
        "phase": "cleanup",
        "technique": "T1070.004",
        "artifact_type": "timeline",
        "artifact_category": "shell_history",
        "primary": False,
        "base_weight": 0.6,
        "query": {
            "message_contains_any": [
                "sed -i",
                "ld.so.preload",
            ],
        },
    },
    {
        "id": "cleanup_bash_memory",
        "step": "cleanup",
        "phase": "cleanup",
        "technique": "T1070.004",
        "artifact_type": "memory",
        "artifact_category": "credential_artifact",
        "primary": False,
        "base_weight": 0.6,
        # vol3 linux.bash reads bash history directly from the bash process's
        # in-memory history buffer — survives even if ~/.bash_history was cleared
        # on disk, as long as the bash session is still alive in the dump.
        # Routes to linux.bash via MEMORY_CATEGORY_PLUGINS["credential_artifact"].
        "query": {
            "path_substring": "T1574006.so",
        },
    },
]


def get_specs_for_scenario(scenario_id: str) -> list[dict[str, Any]]:
    if scenario_id == "scenario_01_ldpreload":
        return ARTIFACT_SPECS_SCENARIO_01
    return []
