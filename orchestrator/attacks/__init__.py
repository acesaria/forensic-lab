"""Attack registry used for dynamic module loading."""

from typing import Any, Dict

# Non-ART scenarios keep explicit modules.
ATTACK_MODULES: Dict[str, str] = {
    "ptrace": "orchestrator.attacks.attack_01_ptrace",
    "metasploit": "orchestrator.attacks.attack_05_metasploit",
    "kernel": "orchestrator.attacks.attack_06_kernel",
}

# ART scenarios are configured here and handled by attack_art.py.
ART_SCENARIOS: Dict[str, dict[str, Any]] = {
    "atomic_t1059_simple_bash": {
        "technique_id": "T1059.004",
        "run_cleanup": False,
        "scenario": {
            "id": "atomic-T1059.004-bash",
            "mitre": {
                "tactic_id": "TA0002",
                "tactic_name": "Execution",
                "technique_id": "T1059",
                "sub_technique_id": "004",
                "technique_name": "Command and Scripting Interpreter: Bash",
            },
        },
    },
    "art-t1070-003": {
        "technique_id": "T1070.003",
        "test_guids": ["cbf506a5-dd78-43e5-be7e-a46b7c7a0a11"],
        "run_cleanup": False,
        "scenario": {
            "id": "art-T1070.003-clear-bash-history-echo",
            "mitre": {
                "tactic_id": "TA0005",
                "tactic_name": "Defense Evasion",
                "technique_id": "T1070",
                "sub_technique_id": "003",
                "technique_name": "Indicator Removal on Host: Clear Command History",
            },
        },
    },
}

ALL_SCENARIOS = tuple(sorted((*ATTACK_MODULES.keys(), *ART_SCENARIOS.keys())))

__all__ = ("ATTACK_MODULES", "ART_SCENARIOS", "ALL_SCENARIOS")
