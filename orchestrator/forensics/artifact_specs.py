from __future__ import annotations

from typing import Any

ARTIFACT_SPECS_SCENARIO_01: list[dict[str, Any]] = [
    {
        "id": "ldpreload_file",
        "step": "ldpreload",
        "technique": "T1574.006",
        "artifact_type": "disk",
        "artifact_category": "config_file",
        "tool": "sleuth",
        "primary": True,
        "base_weight": 0.9,
        "query": {
            "path_equals": "/etc/ld.so.preload",
            "content_contains": "/tmp/T1574006.so",
            "treat_deleted_recovered_as_found": True,
            "treat_deleted_entry_as_found": False,
        },
    },
    {
        "id": "ldpreload_so_on_disk",
        "step": "ldpreload",
        "technique": "T1574.006",
        "artifact_type": "disk",
        "artifact_category": "shared_library",
        "tool": "sleuth",
        "primary": False,
        "base_weight": 0.8,
        "query": {
            "path_equals": "/tmp/T1574006.so",
            "treat_deleted_recovered_as_found": True,
            "treat_deleted_entry_as_found": False,
        },
    },
    {
        "id": "ldpreload_so_in_memory",
        "step": "ldpreload_trigger",
        "technique": "T1574.006",
        "artifact_type": "memory",
        "artifact_category": "shared_library",
        "tool": "vol3",
        "primary": True,
        "base_weight": 1.0,
        "query": {
            "path_substring": "T1574006.so",
        },
    },
    {
        "id": "reverse_shell_socket",
        "step": "reverse_shell",
        "technique": "T1059.004",
        "artifact_type": "memory",
        "artifact_category": "network_socket",
        "tool": "vol3",
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
        "technique": "T1059.004",
        "artifact_type": "disk",
        "artifact_category": "file",
        "tool": "sleuth",
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
        "technique": "T1059.004",
        "artifact_type": "timeline",
        "artifact_category": "timeline_event",
        "tool": "plaso",
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
]


def get_specs_for_scenario(scenario_id: str) -> list[dict[str, Any]]:
    if scenario_id == "scenario_01_ldpreload":
        return ARTIFACT_SPECS_SCENARIO_01
    return []
