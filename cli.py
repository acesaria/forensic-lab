"""CLI entry point for forensic-lab."""

import argparse
import logging
import shutil
import sys
from pathlib import Path

from infra.provider import Provider
from orchestrator.core import console
from orchestrator.core.bootstrap import run_init
from orchestrator.core.config import load_config, load_profile, load_scenarios
from orchestrator.core.orchestrator import ForensicOrchestrator
from orchestrator.core.paths import ProjectPaths
from orchestrator.core.vm_manager import VMManager
from orchestrator.forensics import Dumper, SleuthKitRunner, VolatilityRunner


def build_parser(scenario_keys: tuple[str, ...]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensic-lab",
        description=(
            "Linux post-mortem forensic lab. Primary thesis path: "
            "declarative scenario execution -> run manifest/command log -> "
            "acquisition -> raw forensic exports -> manual investigation."
        ),
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
        help=(
            "Create lab VM, provision baseline, build ISF, and verify raw "
            "extraction tools (idempotent)"
        ),
    )
    setup.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")

    # run: execute an experiment
    run = sub.add_parser(
        "run",
        help=(
            "Run a VM experiment. The active thesis registry path is "
            "userland_father_ldpreload."
        ),
    )
    run.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")
    run.add_argument(
        "--scenario",
        required=True,
        choices=scenario_keys,
        help="Controlled scenario key to run",
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

    sub.add_parser(
        "verify",
        help="Check pinned raw extraction tool versions",
    )

    run_scenario = sub.add_parser(
        "run-scenario",
        help="Run a declarative scenario.yml and write a manifest plus command log",
    )
    run_scenario.add_argument("scenario_yml")
    run_scenario.add_argument("--out-dir", default=None)
    run_scenario.add_argument("--run-id", default=None)

    return parser


# --- init helpers --------------------------------------------------------


def _setup_logging(debug: bool) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG if debug else logging.INFO)
    handler.setFormatter(console.PrefixColorFormatter("%(message)s"))

    root = logging.getLogger()
    root.setLevel(logging.DEBUG if debug else logging.INFO)
    root.addHandler(handler)

    for noisy in ("paramiko", "ansible", "libvirt", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _check_prerequisites(raw_tools: dict[str, str]) -> None:
    required = [
        ("virsh", "virsh", "libvirt-clients"),
        ("virt-install", "virt-install", "virtinst"),
        ("qemu-img", "qemu-img", "qemu-utils"),
        ("cloud-localds", "cloud-localds", "cloud-image-utils"),
        ("ansible-playbook", "ansible-playbook", "ansible"),
        ("ewfacquire", "ewfacquire", "libewf-dev"),
        ("volatility3", raw_tools["volatility3"], "volatility3"),
        ("mmls", raw_tools["mmls"], "sleuthkit"),
        ("fls", raw_tools["fls"], "sleuthkit"),
        ("fsstat", raw_tools["fsstat"], "sleuthkit"),
        ("log2timeline", raw_tools["log2timeline"], "plaso"),
        ("psort", raw_tools["psort"], "plaso"),
    ]
    missing = [
        f"  {name}: {command}  ({package})"
        for name, command, package in required
        if shutil.which(command) is None and not Path(command).is_file()
    ]
    if missing:
        raise RuntimeError("prereq: Missing required binaries:\n" + "\n".join(missing))


# --- no-lab-host handlers ------------------------------------------------


def _cmd_verify(args: argparse.Namespace) -> int:
    from orchestrator.forensics.pipeline_config import (
        load_pipeline_config,
        raw_tool_paths,
        verify_versions,
    )

    repo_root = Path(__file__).resolve().parent
    config_path = repo_root / "config.yaml"
    host_cfg = load_config(repo_root)["host"] if config_path.is_file() else {}
    cfg = load_pipeline_config()
    problems = verify_versions(cfg, raw_tool_paths(host_cfg))
    if problems:
        print("version problems:")
        for p in problems:
            print(f"  - {p}")
        return 1 if cfg.get("version_policy") == "strict" else 0
    print("all pinned tool versions satisfied")
    return 0


def _cmd_run_scenario(args: argparse.Namespace) -> int:
    from orchestrator.scenarios import run_scenario

    ctx = run_scenario(
        args.scenario_yml,
        out_dir=args.out_dir,
        run_id=args.run_id,
        repo_root=Path(__file__).resolve().parent,
    )
    print(f"scenario run written: {ctx.out_dir}")
    print(f"  manifest: {ctx.manifest_path}")
    print(f"  command_log: {ctx.command_log_path}")
    return 0


# These commands need neither libvirt nor the acquisition toolchain, so main()
# dispatches them before the prerequisite check and orchestrator construction.
_NO_LAB_HOST_HANDLERS = {
    "verify": _cmd_verify,
    "run-scenario": _cmd_run_scenario,
}


# --- main ----------------------------------------------------------------


def main() -> None:
    repo_root = Path(__file__).resolve().parent
    scenarios = load_scenarios(repo_root)
    args = build_parser(tuple(sorted(scenarios.keys()))).parse_args()
    _setup_logging(args.debug)

    if args.command in _NO_LAB_HOST_HANDLERS:
        sys.exit(_NO_LAB_HOST_HANDLERS[args.command](args))

    # The 'setup' and 'run' paths need a valid distro profile; fail fast with a
    # config error before any VM work starts.
    if args.command in ("setup", "run"):
        try:
            load_profile(repo_root, args.distro)
        except (KeyError, FileNotFoundError, ValueError) as exc:
            console.err(f"config: distro '{args.distro}' not found: {exc}")
            sys.exit(1)

    # All host path fields are absolute Paths and role_defaults carry their
    # network names after load_config(); ProjectPaths then derives every
    # layout-specific subdirectory once. Downstream code only sees `paths`,
    # never raw host_cfg path entries.
    cfg = load_config(repo_root)
    host_cfg = cfg["host"]
    from orchestrator.forensics.pipeline_config import raw_tool_paths

    raw_tools = raw_tool_paths(host_cfg)
    _check_prerequisites(raw_tools)
    if args.debug:
        console.info("debug mode on")

    paths = ProjectPaths.from_config(repo_root, host_cfg)
    role_defaults = cfg.get("role_defaults") or {}

    provider = Provider(
        libvirt_uri=host_cfg["libvirt_uri"],
        pool_name=host_cfg["pool_name"],
        pool_path=paths.pool_dir,
        network_name=host_cfg["isolated_network_name"],
    )

    vm_manager = VMManager(provider=provider, paths=paths)

    dumper = Dumper(paths)
    vol_runner = VolatilityRunner(raw_tools["volatility3"], paths.isf_dir)
    sleuth_runner = SleuthKitRunner(
        raw_tools["mmls"], raw_tools["fls"], raw_tools["fsstat"]
    )

    distro_id: str = getattr(args, "distro", "ubuntu-22.04")

    try:
        with ForensicOrchestrator(
            vm_manager=vm_manager,
            dumper=dumper,
            vol_runner=vol_runner,
            sleuth_runner=sleuth_runner,
            paths=paths,
            role_defaults=role_defaults,
            raw_tools=raw_tools,
        ) as orchestrator:

            if args.command == "init":
                run_init(paths)
                orchestrator.setup_infra()

            elif args.command == "setup":
                console.section("infrastructure")
                orchestrator.setup_infra()
                console.section("lab VM setup")
                orchestrator.prepare_lab(distro_id)
                console.section("volatility symbols")
                orchestrator.build_isf(distro_id)
                console.section("raw extraction verification")
                orchestrator.verify_pipeline(distro_id)
                console.ok(f"setup complete for '{distro_id}'")

            elif args.command == "run":
                if not orchestrator.lab_exists(distro_id):
                    console.warn(f"lab '{distro_id}' not found; run 'setup' first")
                    raise SystemExit(1)
                # argparse choices guarantee the key exists in the registry.
                scenario_cfg = scenarios[args.scenario]
                if "scenario_yml" not in scenario_cfg:
                    raise RuntimeError(
                        f"Invalid scenario config for '{args.scenario}': "
                        "missing 'scenario_yml'"
                    )
                orchestrator.run_declarative_experiment(
                    distro_id,
                    args.scenario,
                    scenario_cfg,
                    acquire=args.acquire,
                )

            elif args.command == "destroy":
                orchestrator.destroy_lab(distro_id)

    except KeyboardInterrupt:
        console.err("interrupted")
        sys.exit(1)
    except RuntimeError as exc:
        console.err(str(exc))
        if args.debug:
            raise
        sys.exit(1)
    except Exception as exc:
        console.err(f"unexpected error: {exc}")
        if args.debug:
            raise
        sys.exit(1)


if __name__ == "__main__":
    main()
