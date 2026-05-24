"""CLI entry point for forensic-lab."""

import argparse
import logging
import shutil
import sys
from pathlib import Path

from infra.provider import Provider
from orchestrator.core.bootstrap import run_init
from orchestrator.core.config import load_config, load_profile, load_scenarios
from orchestrator.core.orchestrator import ForensicOrchestrator
from orchestrator.core.vm_manager import VMManager
from orchestrator.forensics import Dumper, SleuthKitRunner, VolatilityRunner

_log = logging.getLogger(__name__)


def build_parser(scenario_keys: tuple[str, ...]) -> argparse.ArgumentParser:
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
        help="Run a full experiment: revert, attack, acquire",
    )
    run.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")
    run.add_argument(
        "--scenario",
        required=True,
        choices=scenario_keys,
        help="Attack scenario to run",
    )
    run.add_argument(
        "--acquire",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Acquire memory + disk after the scenario (default: enabled)",
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
    repo_root = Path(__file__).resolve().parent
    scenarios = load_scenarios(repo_root)
    args = build_parser(tuple(sorted(scenarios.keys()))).parse_args()
    _setup_logging(args.debug)
    _check_prerequisites()
    if args.debug:
        _log.info("[i] Debug mode on")

    # All host path fields are absolute Paths after load_config(); no further
    # normalization is needed downstream. See orchestrator/core/config.py.
    cfg = load_config(repo_root)
    host_cfg = cfg["host"]
    role_defaults = cfg.get("role_defaults") or {}
    for role_key in ("lab", "build-isf"):
        role_cfg = role_defaults.get(role_key)
        if isinstance(role_cfg, dict):
            role_cfg["network"] = host_cfg["isolated_network_name"]

    provider = Provider(
        libvirt_uri=host_cfg["libvirt_uri"],
        pool_name=host_cfg["pool_name"],
        pool_path=host_cfg["pool_path"],
        network_name=host_cfg["isolated_network_name"],
    )

    vm_manager = VMManager(
        provider=provider,
        images_path=host_cfg["images_path"],
        ssh_key=host_cfg["ssh_key"],
        ssh_pub_key=host_cfg["ssh_pub_key"],
        repo_root=repo_root,
    )

    # shared_dir is the single root for all derived output locations.
    shared_dir = host_cfg["shared_dir"]
    dumps_dir = shared_dir / "dumps"
    isf_dir = shared_dir / "isf"

    dumper = Dumper(repo_root, dumps_dir)
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
            atomics_path=host_cfg["atomics_path"],
            isf_dir=isf_dir,
            role_defaults=role_defaults,
        ) as orchestrator:

            if args.command == "init":
                run_init(repo_root, host_cfg)
                orchestrator.setup_infra()

            elif args.command == "setup":
                try:
                    load_profile(repo_root, args.distro)
                except (KeyError, FileNotFoundError, ValueError) as exc:
                    raise RuntimeError(
                        f"config: distro '{args.distro}' not found: {exc}"
                    ) from exc

                _section("infrastructure")
                orchestrator.setup_infra()
                _section("lab VM setup")
                orchestrator.prepare_lab(distro_id)
                _section("volatility symbols")
                orchestrator.build_isf(distro_id)
                _section("pipeline verification")
                orchestrator.verify_pipeline(distro_id)
                _log.info("\n[+] Setup complete for '%s'", distro_id)

            elif args.command == "run":
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
                scenario_cfg = scenarios.get(args.scenario)
                if not scenario_cfg:
                    raise RuntimeError(f"Unknown scenario '{args.scenario}'")
                if "technique_id" in scenario_cfg or "module" in scenario_cfg:
                    orchestrator.run_experiment(distro_id, scenario_cfg, acquire=args.acquire)
                else:
                    raise RuntimeError(f"Invalid scenario config for '{args.scenario}'")

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
