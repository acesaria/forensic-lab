# orchestrator/forensics/extract.py
#
# Thin extraction wrappers over the in-tree forensic runners. They produce the
# raw TSK and Volatility outputs used for manual source-family investigation.
# Extraction is scenario-blind by construction: no planted value is read here.

from __future__ import annotations

from pathlib import Path
from typing import Any

from orchestrator.forensics.sleuth_runner import SleuthKitRunner
from orchestrator.forensics.vol_runner import VolatilityRunner

DEFAULT_PLUGINS = (
    "linux.pslist",
    "linux.psscan",
    "linux.psaux",
    "linux.bash",
    "linux.sockstat",
    "linux.malfind",
    "linux.lsmod",
    "linux.proc.Maps",
)


def extract_plugins(
    vol: VolatilityRunner,
    memory_path: Path,
    distro_id: str,
    plugins: tuple[str, ...] = DEFAULT_PLUGINS,
    kernel_release: str | None = None,
    isf_path: Path | None = None,
    errors: dict[str, str] | None = None,
    invocations: dict[str, dict[str, Any]] | None = None,
) -> dict[str, list[dict[str, Any]] | None]:
    out: dict[str, list[dict[str, Any]] | None] = {}
    for plugin in plugins:
        invocation: dict[str, Any] = {"plugin": plugin}
        if invocations is not None:
            invocations[plugin] = invocation
        try:
            out[plugin] = vol.run_plugin(
                memory_path,
                distro_id,
                plugin,
                kernel_release=kernel_release,
                isf_path=isf_path,
                invocation=invocation,
            )
            invocation.setdefault("error", None)
        except RuntimeError as exc:
            # A plugin missing for this kernel build is not fatal; the run keeps
            # the raw output from whichever plugins did succeed.
            if errors is not None:
                errors[plugin] = str(exc)
            invocation.setdefault("exit_status", None)
            invocation.update({"status": "failed", "error": str(exc)})
            out[plugin] = None
    return out


def extract_bodyfile(
    sleuth: SleuthKitRunner,
    disk_path: Path,
    invocations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    offset = sleuth.partition_offset(disk_path, invocations=invocations)
    # fls -m emits bodyfile rows for every name, allocated or not, mounting the
    # listing at "/" so paths read absolute.
    lines = sleuth.fls(
        disk_path, offset, flags="-r -m /", invocations=invocations
    )
    return {"bodyfile": "\n".join(lines)}
