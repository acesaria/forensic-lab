"""
cli.py — forensic-lab command line interface

All commands are thin wrappers around ForensicOrchestrator.
No logic here, just argument parsing and output.
"""

import argparse
import sys
from pathlib import Path

from orchestrator.core.orchestrator import ForensicOrchestrator


def cmd_setup(args, orch: ForensicOrchestrator) -> None:
    """Create libvirt network and storage pool."""
    orch.setup()
    print("[+] Setup complete")


def cmd_prepare(args, orch: ForensicOrchestrator) -> None:
    """Download image, create VM, take baseline snapshot."""
    orch.prepare(args.distro)


def cmd_acquire(args, orch: ForensicOrchestrator) -> None:
    """Revert to baseline and acquire RAM + disk (no attack)."""
    manifest = orch.acquire_baseline(args.distro)
    print(f"[+] Acquisition complete: {manifest}")


def cmd_run(args, orch: ForensicOrchestrator) -> None:
    """Revert to baseline, run attack scenario, acquire."""
    manifest = orch.run(args.distro, args.scenario)
    if manifest:
        print(f"[+] Experiment complete: {manifest}")


def cmd_destroy(args, orch: ForensicOrchestrator) -> None:
    """Remove lab VM and its storage."""
    orch.destroy(args.distro)
    print(f"[+] '{args.distro}' destroyed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensic-lab",
        description="KVM-based forensic experiment automation",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # setup
    sub.add_parser("setup", help="Create libvirt network and pool (run once)")

    # prepare
    p = sub.add_parser("prepare", help="Download image, create VM, snapshot baseline")
    p.add_argument("--distro", required=True, help="Distro ID (e.g. ubuntu-22.04)")

    # acquire
    a = sub.add_parser("acquire", help="Acquire baseline RAM+disk without attack")
    a.add_argument("--distro", required=True)

    # run
    r = sub.add_parser("run", help="Full experiment: revert + attack + acquire")
    r.add_argument("--distro", required=True)
    r.add_argument("--scenario", required=True, help="Scenario name (e.g. ptrace)")

    # destroy
    d = sub.add_parser("destroy", help="Remove lab VM and storage")
    d.add_argument("--distro", required=True)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    handlers = {
        "setup":   cmd_setup,
        "prepare": cmd_prepare,
        "acquire": cmd_acquire,
        "run":     cmd_run,
        "destroy": cmd_destroy,
    }

    with ForensicOrchestrator() as orch:
        handlers[args.command](args, orch)


if __name__ == "__main__":
    main()