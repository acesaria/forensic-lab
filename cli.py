"""CLI entry point for forensic-lab."""

import argparse
from pathlib import Path

from infra.provider import Provider
from orchestrator.core.bootstrap import run_init
from orchestrator.core.config import ISF_SHARED_DIR, load_config, load_profile
from orchestrator.core.orchestrator import ForensicOrchestrator
from orchestrator.core.vm_manager import VMManager
from orchestrator.forensics.dumper import Dumper
from orchestrator.forensics.sleuth_runner import SleuthKitRunner
from orchestrator.forensics.vol_runner import VolatilityRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensic-lab",
        description="Reproducible Linux attack reconstruction lab.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # init: one-time host setup (sudo required)
    sub.add_parser(
        "init",
        help="One-time host setup: system dirs, sudoers, libvirt network/pool",
    )

    # setup: prepare lab VM + build ISF + verify pipeline (idempotent)
    setup = sub.add_parser(
        "setup",
        help="Create lab VM, provision baseline, build ISF, verify pipeline (idempotent)",
    )
    setup.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")

    # run: execute an experiment
    run = sub.add_parser(
        "run",
        help="Run a full experiment: revert, attack, acquire",
    )
    run.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")
    run.add_argument(
        "--scenario",
        required=True,
        choices=["ptrace", "metasploit", "kernel"],
        help="Attack scenario to run",
    )

    # destroy: remove lab VM and storage
    destroy = sub.add_parser("destroy", help="Destroy lab VM and storage")
    destroy.add_argument("--distro", required=True, help="Distro ID")

    return parser


# --- init helpers --------------------------------------------------------


def _section(title: str) -> None:
    print(f"\n=== {title} ===")


# --- main ----------------------------------------------------------------


def main() -> None:
    repo_root = Path(__file__).resolve().parent
    args = build_parser().parse_args()
    cfg = load_config(repo_root)
    host_cfg = cfg["host"]
    role_defaults = cfg.get("role_defaults") or {}

    provider = Provider(
        libvirt_uri=host_cfg["libvirt_uri"],
        pool_name=host_cfg["pool_name"],
        pool_path=Path(host_cfg["pool_path"]),
    )

    vm_manager = VMManager(
        provider=provider,
        images_path=Path(host_cfg["images_path"]),
        ssh_key=host_cfg["ssh_key"],
        ssh_pub_key=host_cfg["ssh_pub_key"],
        repo_root=repo_root,
    )

    dumper = Dumper(repo_root)
    results_path = Path(host_cfg["shared_dir"]).expanduser() / "results"

    # VolatilityRunner is always constructible -- only validates the binary.
    # ISF lookup happens at call time inside VolatilityRunner via distro_id.
    isf_dir = repo_root / ISF_SHARED_DIR
    vol_runner = VolatilityRunner.from_config(host_cfg, isf_dir)
    sleuth_runner = SleuthKitRunner.from_config(host_cfg)

    distro_id: str = getattr(args, "distro", "ubuntu-22.04")

    

    try:
        with ForensicOrchestrator(
            vm_manager=vm_manager,
            dumper=dumper,
            vol_runner=vol_runner,
            sleuth_runner=sleuth_runner,
            repo_root=repo_root,
            results_path=results_path,
            role_defaults=role_defaults,
        ) as orchestrator:

            if args.command == "init":
                run_init(repo_root, host_cfg)
                orchestrator.setup_infra()

            elif args.command == "setup":
                _section("infra")
                orchestrator.setup_infra()
                _section("lab VM + baseline")
                orchestrator.prepare_lab(distro_id)
                _section("ISF")
                orchestrator.build_isf(distro_id)
                _section("pipeline verify")
                orchestrator.verify_pipeline(distro_id)
                print(f"\n[+] Setup complete for '{distro_id}'")

            elif args.command == "run":
                if not orchestrator.lab_exists(distro_id):
                    print(f"[!] Lab '{distro_id}' not found. " "Run 'setup' first.")
                    raise SystemExit(1)
                orchestrator.run_experiment(distro_id, args.scenario)

            elif args.command == "destroy":
                orchestrator.destroy_lab(distro_id)

    except FileNotFoundError as e:
        print(f"[!] {e}")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
