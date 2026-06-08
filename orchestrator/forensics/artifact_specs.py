from __future__ import annotations

from typing import Any

# Artifact specs declare WHAT to look for (type + category + query), not HOW
# (tool). The detector resolves tools from artifact_type:
#   disk     -> Sleuth Kit  (_detect_disk_artifact)
#   memory   -> Volatility3 (_detect_memory_artifact, category -> plugin list)
#   timeline -> Plaso       (_detect_timeline_artifact)
#
# artifact_category is a routing key for memory (it must be a key in
# MEMORY_CATEGORY_PLUGINS or the spec routes to no plugin) but a free-text label
# for disk and timeline.
#
# phase: "attack" specs describe evidence planted by the attack itself.
# phase: "cleanup" specs describe evidence left by the cleanup action. The
# evaluator scores one report step per ground_truth step, so cleanup specs bind
# to the "cleanup" step the scenario emits when run_cleanup=True; with
# run_cleanup=False that step is absent and these specs are simply skipped.


ARTIFACT_SPECS_SCENARIO_01: list[dict[str, Any]] = [
    # ── Attack: LD_PRELOAD hook (step "ldpreload", T1574.006) ──────────────
    # ART executor: sudo sh -c 'echo /tmp/T1574006.so > /etc/ld.so.preload'.
    # The .so is gcc-compiled to /tmp/T1574006.so by the prereq.
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
            # Cleanup empties this line in place (sed -i 's#...##'); only the
            # unlinked pre-edit inode still carries the path.
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
        # Promoted to primary: ART cleanup never rm's the .so, so this is the
        # disk artifact most likely to survive fully intact (status=present).
        "primary": True,
        "base_weight": 0.8,
        "query": {
            "path_equals": "/tmp/T1574006.so",
            "treat_deleted_recovered_as_found": True,
            "treat_deleted_entry_as_found": False,
        },
    },
    {
        "id": "ldpreload_so_timeline",
        "step": "ldpreload",
        "phase": "attack",
        "technique": "T1574.006",
        "artifact_type": "timeline",
        "artifact_category": "filesystem_event",
        # The reliable timeline anchor: Plaso filestat emits MACB rows for the
        # dropped .so and modified config whether or not anything reached shell
        # history (this scenario runs non-interactively). If your psort
        # json_line message omits the path, switch to filename_substring.
        "primary": True,
        "base_weight": 0.7,
        "query": {
            "message_contains_any": ["T1574006.so", "ld.so.preload"],
        },
    },
    # ── Attack: hook trigger (step "ldpreload_trigger") ────────────────────
    {
        "id": "ldpreload_so_memory",
        "step": "ldpreload_trigger",
        "phase": "attack",
        "technique": "T1574.006",
        "artifact_type": "memory",
        "artifact_category": "shared_library",  # -> linux.proc.Maps
        # RQ2 keystone: memory recovers the injection after disk cleanup hides it.
        "primary": True,
        "base_weight": 1.0,
        "query": {
            "path_substring": "T1574006.so",
        },
    },
    # ── Attack: reverse shell (step "reverse_shell", T1059.004) ────────────
    {
        "id": "reverse_shell_socket",
        "step": "reverse_shell",
        "phase": "attack",
        "technique": "T1059.004",
        "artifact_type": "memory",
        "artifact_category": "network_socket",  # -> linux.sockstat/sockscan
        "primary": True,
        "base_weight": 0.9,
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
        "artifact_category": "fifo",
        "primary": False,
        "base_weight": 0.7,
        "query": {
            "path_equals": "/tmp/.rs_fifo",
            # A FIFO has no body, so icat recovers nothing: the directory entry
            # is the whole artifact.
            "treat_deleted_recovered_as_found": True,
            "treat_deleted_entry_as_found": True,
        },
    },
    {
        "id": "reverse_shell_history",
        "step": "reverse_shell",
        "phase": "attack",
        "technique": "T1059.004",
        "artifact_type": "timeline",
        "artifact_category": "command_history",
        # Demoted: nc runs non-interactively with no PTY, so it rarely reaches
        # bash history. Best-effort corroborator only.
        "primary": False,
        "base_weight": 0.5,
        "query": {
            "message_contains_any": ["/tmp/.rs_fifo", "mkfifo", " nc "],
        },
    },
    # ── Cleanup (step "cleanup") ───────────────────────────────────────────
    # Cleanup runs each executed ART test's cleanup_command:
    #   T1082    -> rm /tmp/T1082.txt                              (deletes discovery output)
    #   T1574.006 -> sed -i 's#/tmp/T1574006.so##' /etc/ld.so.preload (unhooks; no rm)
    # The .so is NOT removed and the preload edit is largely recoverable, so the
    # only clean NEW cleanup artifact is the deleted discovery output.
    {
        "id": "cleanup_discovery_output_deleted",
        "step": "cleanup",
        "phase": "cleanup",
        "technique": "T1070.004",
        "artifact_type": "disk",
        "artifact_category": "deleted_file",
        "primary": True,
        "base_weight": 0.7,
        # The file demonstrably existed (discovery wrote it) and cleanup removed
        # it, so a bare tombstone is sufficient evidence of file deletion.
        "query": {
            "path_equals": "/tmp/T1082.txt",
            "treat_deleted_recovered_as_found": True,
            "treat_deleted_entry_as_found": True,
        },
    },
    {
        "id": "cleanup_payload_persists",
        "step": "cleanup",
        "phase": "cleanup",
        "technique": "T1574.006",
        "artifact_type": "disk",
        "artifact_category": "shared_library",
        # RQ3 contrast: ART cleanup only unhooks the config, never deletes the
        # payload, so the .so persisting is the signature of an incomplete
        # cleanup. Non-primary: it restates ldpreload_so_disk under the cleanup
        # lens rather than detecting something new.
        "primary": False,
        "base_weight": 0.6,
        "query": {
            "path_equals": "/tmp/T1574006.so",
            "treat_deleted_recovered_as_found": True,
            "treat_deleted_entry_as_found": False,
        },
    },
]


def get_specs_for_scenario(scenario_id: str) -> list[dict[str, Any]]:
    if scenario_id == "scenario_01_ldpreload":
        return ARTIFACT_SPECS_SCENARIO_01
    return []
