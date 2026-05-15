"""
Very simple Atomic-style scenario based on ATT&CK T1059.004 (Bash).
The goal is to:
- spawn a long-lived process with a recognizable command line;
- create a marker file on disk;
- return ground truth for those IOCs.
"""

from __future__ import annotations

from typing import Any

# This is intentionally very close to an Atomic "atomic_test", but simplified.
SCENARIO: dict[str, Any] = {
    "id": "atomic-T1059.004-simple-bash",
    "mitre": {
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1059",
        "sub_technique_id": "004",
        "technique_name": "Command and Scripting Interpreter: Bash",
    },
    "steps": [
        {
            "id": "step-1-start-marker-process",
            "description": "Start a long-lived bash loop as a marker process.",
            "command": (
                "nohup bash -c '"
                'while true; do echo "atomic_t1059_marker" >/tmp/atomic_t1059_marker.log; '
                "sleep 60; "
                "done"
                "' >/tmp/atomic_t1059_nohup.out 2>&1 &"
            ),
            "mitre": {
                "tactic_id": "TA0002",
                "technique_id": "T1059",
                "sub_technique_id": "004",
            },
        },
        {
            "id": "step-2-create-marker-file",
            "description": "Create a static marker file on disk.",
            "command": "echo 'atomic_t1059_file_marker' > /tmp/atomic_t1059_file.txt",
            "mitre": {
                "tactic_id": "TA0002",
                "technique_id": "T1059",
                "sub_technique_id": "004",
            },
        },
    ],
}

SCENARIO_2: dict[str, Any] = {
    "scenario_id": "debian-13_atomic_t1059_simple_bash_20260515-153000",
    "scenario": {
        "id": "atomic-T1059.004-simple-bash",
        "mitre": {
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059",
            "sub_technique_id": "004",
            "technique_name": "Command and Scripting Interpreter: Bash",
        },
    },
    "iocs": [
        {
            "id": "atomic_t1059_marker_process",
            "type": "process",
            "attributes": {
                "name_contains": "bash",
                "cmdline_contains": "atomic_t1059_marker",
            },
            "source_step": "step-1-start-marker-process",
        },
        {
            "id": "atomic_t1059_marker_file",
            "type": "file",
            "attributes": {
                "path": "/tmp/atomic_t1059_file.txt",
                "content_contains": "atomic_t1059_file_marker",
            },
            "source_step": "step-2-create-marker-file",
        },
    ],
}


def run(ssh, scenario_id: str) -> dict[str, Any]:
    """
    Execute the scenario steps over SSH and return ground truth.

    Ground truth is minimal but structured so it can be matched later
    against Volatility3 and Sleuth Kit output.
    """
    for step in SCENARIO["steps"]:
        ssh.run_checked(step["command"])

    # We do not resolve PIDs here; that will be done from memory later.
    ground_truth: dict[str, Any] = {
        "scenario_id": scenario_id,
        "scenario": {
            "id": SCENARIO["id"],
            "mitre": SCENARIO["mitre"],
        },
        "iocs": [
            {
                "id": "atomic_t1059_marker_process",
                "type": "process",
                "attributes": {
                    "name_contains": "bash",
                    "cmdline_contains": "atomic_t1059_marker",
                },
                "source_step": "step-1-start-marker-process",
            },
            {
                "id": "atomic_t1059_marker_file",
                "type": "file",
                "attributes": {
                    "path": "/tmp/atomic_t1059_file.txt",
                    "content_contains": "atomic_t1059_file_marker",
                },
                "source_step": "step-2-create-marker-file",
            },
            {
                "id": "atomic_t1059_log_file",
                "type": "file",
                "attributes": {
                    "path": "/tmp/atomic_t1059_marker.log",
                },
                "source_step": "step-1-start-marker-process",
            },
        ],
    }
    return ground_truth
