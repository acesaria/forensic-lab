# orchestrator/forensics/artifact_specs.py
#
# Data-driven IOC specifications. An ArtifactSpec is a plain dict describing
# one observable artifact a scenario leaves behind, plus how to look for it.
# New scenarios should add data here, not new detection code.
#
# ArtifactSpec keys:
#   id: str                 unique within a scenario
#   step: str               matches a ground_truth step["step"] name
#   technique: str          ATT&CK technique id (informational)
#   artifact_type: str      "disk" | "memory" | "timeline"
#   tool: str               "sleuth" | "vol3" | "plaso"
#   primary: bool           primary artifacts drive step "recovered" + confidence
#   base_weight: float      contribution to confidence when found (0.0 - 1.0)
#   query: dict[str, Any]   tool-specific match criteria (see ioc_detector)

from __future__ import annotations

from typing import Any

# One flat list per scenario. Order is presentation only; detection groups by
# step at evaluation time.
ARTIFACT_SPECS_SCENARIO_01: list[dict[str, Any]] = [
    {
        "id": "ldpreload_file",
        "step": "ldpreload",
        "technique": "T1574.006",
        "artifact_type": "disk",
        "tool": "sleuth",
        "primary": True,
        "base_weight": 0.9,
        "query": {
            "path_equals": "/etc/ld.so.preload",
            "content_contains": "/tmp/T1574006.so",
        },
    },
    {
        "id": "ldpreload_so_on_disk",
        "step": "ldpreload",
        "technique": "T1574.006",
        "artifact_type": "disk",
        "tool": "sleuth",
        "primary": False,
        "base_weight": 0.8,
        "query": {
            "path_equals": "/tmp/T1574006.so",
        },
    },
    {
        "id": "ldpreload_so_in_proc_maps",
        "step": "ldpreload_trigger",
        "technique": "T1574.006",
        "artifact_type": "memory",
        "tool": "vol3",
        "primary": True,
        "base_weight": 1.0,
        "query": {
            "plugin": "linux.proc_maps",
            "path_substring": "T1574006.so",
        },
    },
    {
        "id": "reverse_shell_netstat",
        "step": "reverse_shell",
        "technique": "T1059.004",
        "artifact_type": "memory",
        "tool": "vol3",
        "primary": True,
        "base_weight": 0.9,
        "query": {
            "plugin": "linux.netstat",
            "port": 4444,
            "process_names": ["nc", "/bin/sh"],
        },
    },
    {
        "id": "reverse_shell_fifo",
        "step": "reverse_shell",
        "technique": "T1059.004",
        "artifact_type": "disk",
        "tool": "sleuth",
        "primary": False,
        "base_weight": 0.7,
        "query": {
            "path_equals": "/tmp/.rs_fifo",
        },
    },
    {
        "id": "reverse_shell_history",
        "step": "reverse_shell",
        "technique": "T1059.004",
        "artifact_type": "timeline",
        "tool": "plaso",
        "primary": True,
        "base_weight": 0.9,
        "query": {
            "message_contains_any": ["mkfifo /tmp/.rs_fifo", "nc ", "/tmp/.rs_fifo"],
        },
    },
    {
        "id": "bash_history_present",
        "step": "cleanup",
        "technique": "T1070.003",
        "artifact_type": "disk",
        "tool": "sleuth",
        "primary": True,
        "base_weight": 0.8,
        "query": {
            "path_suffix": "/.bash_history",
        },
    },
    {
        "id": "bash_history_contains_reverse_shell",
        "step": "cleanup",
        "technique": "T1070.003",
        "artifact_type": "timeline",
        "tool": "plaso",
        "primary": True,
        "base_weight": 0.9,
        "query": {
            "message_contains_any": ["mkfifo /tmp/.rs_fifo", "nc "],
        },
    },
]


def get_specs_for_scenario(scenario_id: str) -> list[dict[str, Any]]:
    # Lookup table rather than a registry: scenarios are few and adding one
    # is a single branch plus a new constant list.
    if scenario_id == "scenario_01_ldpreload":
        return ARTIFACT_SPECS_SCENARIO_01
    return []
