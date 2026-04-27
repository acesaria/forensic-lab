"""CLI entry point for forensic-lab."""

import argparse

from pathlib import Path
from orchestrator.core.bootstrap import _run_init
from orchestrator.core.orchestrator import ForensicOrchestrator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="forensic-lab")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Initialize system directories with sudo + network/pool for libvirt")
    
    prepare = sub.add_parser("distro-setup", help="Create VM from yml profile + create ISF file + baseline snapshot")
    prepare.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")

    destroy = sub.add_parser("destroy", help="Destroy distro VM and storage")
    destroy.add_argument("--distro", required=True, help="Distro ID")

    run = sub.add_parser(
        "run",
        help="Run the full experiment pipeline for a given distro: create VM, run attack, dump memory, export ISF, destroy VM",
    )
    run.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")

    return parser


def main() -> None:
    repo_root = Path(__file__).resolve().parent
    args = build_parser().parse_args()

    try:
        with ForensicOrchestrator(repo_root) as orchestrator:
            if args.command == "init":
                _run_init(repo_root)
                orchestrator.setup()
                return

            if args.command == "distro-setup":
                distro_id: str = args.distro
                orchestrator.prepare(distro_id)
                return

            if args.command == "run":
                distro_id: str = args.distro
                orchestrator._run_pipeline(distro_id)
                return
            
            if args.command == "destroy":
                distro_id: str = args.distro
                orchestrator.destroy(distro_id)
                return
            else:
                print(f"[!] Unknown command: {args.command}")
                raise SystemExit(1)
            
    except FileNotFoundError as e:
        print(f"[!] {e}")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
