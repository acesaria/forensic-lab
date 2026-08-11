"""CLI entry point for forensic-lab."""

import argparse
import logging
import shutil
import sys
from pathlib import Path

from infra.provider import Provider
from orchestrator.core import console
from orchestrator.core.bootstrap import run_init
from orchestrator.core.config import load_config, load_profile
from orchestrator.core.orchestrator import ForensicOrchestrator
from orchestrator.core.paths import ProjectPaths
from orchestrator.core.vm_manager import VMManager
from orchestrator.forensics import Dumper, SleuthKitRunner, VolatilityRunner
from scenarios.interactive_shell.runner import SCENARIO_ID as INTERACTIVE_SHELL_SCENARIO
from scenarios.ptrace_fa.runner import SCENARIO_ID as PTRACE_FA_SCENARIO
from scenarios.userland_father_ldpreload.runner import SCENARIO_ID as FATHER_SCENARIO
from scenarios.userland_father_ldpreload.runner import (
    CLEANUP_SCENARIO_ID as FATHER_CLEANUP_SCENARIO,
)


SCENARIO_CHOICES = tuple(
    sorted(
        (
            INTERACTIVE_SHELL_SCENARIO,
            FATHER_SCENARIO,
            FATHER_CLEANUP_SCENARIO,
            PTRACE_FA_SCENARIO,
        )
    )
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensic-lab",
        description=(
            "Linux post-mortem forensic lab.\n"
            "Primary thesis path: controlled scenario execution -> "
            "run manifest/command log\n"
            "  -> acquisition -> raw forensic exports -> manual investigation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "First use:\n"
            "  .venv/bin/python cli.py init\n"
            "  .venv/bin/python cli.py setup --distro ubuntu-22.04\n"
            "  .venv/bin/python cli.py run --distro ubuntu-22.04 "
            "--scenario userland_father_ldpreload"
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Show verbose subprocess output and internal detail",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init_help = (
        "One-time host initialization for directories, sudoers, and libvirt "
        "infrastructure"
    )
    sub.add_parser(
        "init",
        help=init_help,
        description=init_help,
    )

    setup_help = "Prepare one distro/profile VM, baseline, and symbols; run after init"
    setup = sub.add_parser(
        "setup",
        help=setup_help,
        description=setup_help,
    )
    setup.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")

    build_help = "Build a scenario artifact on the builder VM and publish it"
    build = sub.add_parser("build", help=build_help, description=build_help)
    build.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")
    build.add_argument(
        "--scenario",
        required=True,
        choices=(FATHER_SCENARIO,),
        help="Scenario whose artifact to build",
    )

    run_help = (
        "Run one scenario using an existing prepared baseline; setup is not "
        "started automatically"
    )
    run = sub.add_parser(
        "run",
        help=run_help,
        description=run_help,
    )
    run.add_argument("--distro", default="ubuntu-22.04", help="Distro ID")
    run.add_argument(
        "--scenario",
        default="userland_father_ldpreload",
        choices=SCENARIO_CHOICES,
        help="Controlled scenario key to run",
    )
    run.add_argument(
        "--acquire",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Acquire memory + disk after the scenario (default: enabled)",
    )

    destroy_help = "Remove the selected lab VM and its VM storage"
    destroy = sub.add_parser(
        "destroy",
        help=destroy_help,
        description=destroy_help,
    )
    destroy.add_argument("--distro", required=True, help="Distro ID")

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
        ("ewfverify", "ewfverify", "libewf-dev"),
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


# --- main ----------------------------------------------------------------


def main() -> None:
    repo_root = Path(__file__).resolve().parent
    args = build_parser().parse_args()
    _setup_logging(args.debug)

    # The 'setup', 'build' and 'run' paths need a valid distro profile; fail
    # fast with a config error before any VM work starts.
    if args.command in ("build", "setup", "run"):
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

            elif args.command == "build":
                orchestrator.build_father(distro_id)

            elif args.command == "run":
                if not orchestrator.lab_exists(distro_id):
                    console.err(f"lab VM for distro '{distro_id}' not found")
                    console.info(
                        "setup command: "
                        f".venv/bin/python cli.py setup --distro {distro_id}"
                    )
                    raise SystemExit(1)
                orchestrator.run_experiment(
                    distro_id,
                    args.scenario,
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
