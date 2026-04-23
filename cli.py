"""CLI entry point for forensic-lab."""

import argparse
import os
import subprocess
from pathlib import Path
from orchestrator.core.orchestrator import ForensicOrchestrator

def _run_init() -> None:
    dirs = [
        Path("/var/lib/forensic-lab/disks"),
        Path("/var/lib/forensic-lab/images"),
    ]

    print("[*] This will create the following directories with sudo:")
    for d in dirs:
        print(f"    {d}")
    answer = input("[?] Proceed? [y/N] ").strip().lower()
    if answer != "y":
        print("[-] Aborted.")
        return

    import grp
    kvm_gid = grp.getgrnam("kvm").gr_gid
    uid = os.getuid()

    for d in dirs:
        subprocess.run(["sudo", "mkdir", "-p", str(d)], check=True)

    subprocess.run(["sudo", "chown", "-R", f"{uid}:{kvm_gid}", "/var/lib/forensic-lab"], check=True)
    subprocess.run(["sudo", "chmod", "-R", "775", "/var/lib/forensic-lab"], check=True)

    print("[+] System directories ready.")
    print("[i] Next step: python cli.py setup")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="forensic-lab")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Initialize system directories with sudo")
    
    sub.add_parser("setup", help="Create libvirt network and pool")


    prepare = sub.add_parser("prepare", help="Prepare distro VM and baseline")
    prepare.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")

    destroy = sub.add_parser("destroy", help="Destroy distro VM and storage")
    destroy.add_argument("--distro", required=True, help="Distro ID")

    pipeline = sub.add_parser(
        "pipeline",
        help="Run prepare + ISF build/export + baseline acquisition",
    )
    pipeline.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")

    return parser


def main() -> None:
    repo_root = Path(__file__).resolve().parent
    args = build_parser().parse_args()

    try:
        if args.command == "init":
            _run_init()
            return

        with ForensicOrchestrator(repo_root) as orchestrator:
            if args.command == "setup":
                orchestrator.setup()
                return

            if args.command == "prepare":
                distro_id: str = args.distro
                orchestrator.prepare(distro_id)
                return

            if args.command == "destroy":
                distro_id: str = args.distro
                orchestrator.destroy(distro_id)
                return

            if args.command == "pipeline":
                distro_id: str = args.distro
                orchestrator.setup()
                orchestrator.prepare(distro_id)
                orchestrator.build_isf(distro_id)
                manifest_path = orchestrator.acquire_baseline(distro_id)
                
                
                print(f"[+] Baseline acquisition manifest: {manifest_path}")
            
    except FileNotFoundError as e:
        print(f"[!] {e}")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
