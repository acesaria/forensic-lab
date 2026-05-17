"""CLI entry point for forensic-lab."""

import argparse
import logging
import sys
from pathlib import Path

from infra.provider import Provider
from orchestrator.core.bootstrap import run_init
from orchestrator.core.config import ISF_SHARED_DIR, load_config, load_profile
from orchestrator.core.orchestrator import ForensicOrchestrator
from orchestrator.core.vm_manager import VMManager
from orchestrator.forensics import Dumper
from orchestrator.forensics import SleuthKitRunner, VolatilityRunner

_log = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensic-lab",
        description="Reproducible Linux attack reconstruction lab.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Show verbose subprocess output and internal detail",
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
        aliases=["run-experiment"],
        help="Run a full experiment: revert, attack, acquire",
    )
    run.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")
    run.add_argument(
        "--scenario",
        required=True,
        choices=["ptrace", "metasploit", "kernel", "art-t1070-003"],
        help="Attack scenario to run",
    )

    # destroy: remove lab VM and storage
    destroy = sub.add_parser("destroy", help="Destroy lab VM and storage")
    destroy.add_argument("--distro", required=True, help="Distro ID")

    return parser


# --- init helpers --------------------------------------------------------


def _section(title: str) -> None:
    _log.info("\n=== %s ===", title)


def _setup_logging(debug: bool) -> None:
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if debug else logging.INFO)
    console.setFormatter(logging.Formatter("%(message)s"))

    root = logging.getLogger()
    root.setLevel(logging.DEBUG if debug else logging.INFO)  # <-- was always DEBUG
    root.addHandler(console)

    for noisy in ("paramiko", "ansible", "libvirt", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _check_prerequisites() -> None:
    import shutil

    required = {
        "virsh": "libvirt-clients",
        "virt-install": "virtinst",
        "qemu-img": "qemu-utils",
        "ewfacquire": "libewf-dev",
        "vol3": "volatility3 (install manually)",
    }
    missing = [
        f"  {cmd}  (apt: {pkg})"
        for cmd, pkg in required.items()
        if shutil.which(cmd) is None
    ]
    if missing:
        raise RuntimeError("prereq: Missing required binaries:\n" + "\n".join(missing))


# --- main ----------------------------------------------------------------


def main() -> None:
    args = build_parser().parse_args()
    _setup_logging(args.debug)
    _check_prerequisites()
    if args.debug:
        _log.info("[i] Debug mode on")
    repo_root = Path(__file__).resolve().parent
    cfg = load_config(repo_root)
    host_cfg = cfg["host"]
    role_defaults = cfg.get("role_defaults") or {}
    for role_key in ("lab", "build-isf"):
        role_cfg = role_defaults.get(role_key)
        if isinstance(role_cfg, dict):
            role_cfg["network"] = host_cfg["isolated_network_name"]

    network_name = host_cfg["isolated_network_name"]
    provider = Provider(
        libvirt_uri=host_cfg["libvirt_uri"],
        pool_name=host_cfg["pool_name"],
        pool_path=Path(host_cfg["pool_path"]),
        network_name=network_name,
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
                from orchestrator.core.config import load_profile

                try:
                    load_profile(repo_root, args.distro)
                except (KeyError, FileNotFoundError, ValueError) as exc:
                    raise RuntimeError(
                        f"config: distro '{args.distro}' not found: {exc}"
                    ) from exc

                _section("infrastracture")
                orchestrator.setup_infra()
                _section("lab VM setup")
                orchestrator.prepare_lab(distro_id)
                _section("volatility symbols")
                orchestrator.build_isf(distro_id)
                _section("pipeline verification")
                orchestrator.verify_pipeline(distro_id)
                _log.info("\n[+] Setup complete for '%s'", distro_id)

            elif args.command in ("run", "run-experiment"):
                from orchestrator.core.config import load_profile

                try:
                    load_profile(repo_root, args.distro)
                except (KeyError, FileNotFoundError, ValueError) as exc:
                    raise RuntimeError(
                        f"config: distro '{args.distro}' not found: {exc}"
                    ) from exc

                if not orchestrator.lab_exists(distro_id):
                    _log.warning(
                        "[!] Lab '%s' not found. Run 'setup' first.",
                        distro_id,
                    )
                    raise SystemExit(1)
                orchestrator.run_experiment(distro_id, args.scenario)

            elif args.command == "destroy":
                orchestrator.destroy_lab(distro_id)

    except KeyboardInterrupt:
        logging.info("\n[-] Interrupted")
        sys.exit(1)
    except RuntimeError as exc:
        logging.error("[!] %s", exc)
        if args.debug:
            raise
        sys.exit(1)
    except Exception as exc:
        logging.error("[!] Unexpected error: %s", exc)
        if args.debug:
            raise
        sys.exit(1)


if __name__ == "__main__":
    main()
