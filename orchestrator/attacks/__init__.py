"""Attack registry used for dynamic module loading."""

from typing import Dict

# Centralized mapping of attack keys to their module paths.
# Moved here so attacker.py and orchestrator.py can import the same source.
ATTACK_MODULES: Dict[str, str] = {
    "ptrace": "orchestrator.attacks.attack_01_ptrace",
    "metasploit": "orchestrator.attacks.attack_05_metasploit",
    "kernel": "orchestrator.attacks.attack_06_kernel",
    "atomic_t1059_simple_bash": "orchestrator.attacks.attack_10_atomic_t1059",
    "art-t1070-003": "orchestrator.attacks.attack_20_art_t1070",
}

__all__ = ("ATTACK_MODULES",)
