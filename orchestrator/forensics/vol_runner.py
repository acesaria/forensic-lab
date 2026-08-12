# orchestrator/forensics/vol_runner.py
#
# VolatilityRunner wraps vol3 subprocess calls.
# Owns: binary resolution, ISF lookup by distro_id, JSON parsing.
# All vol3 invocations go through here.
#
# ISF layout assumption:
#   <isf_dir>/<distro_family>_<kernel_release>.json
# e.g. shared/isf/ubuntu_5.15.0-91-generic.json
#
# Multi-distro usage: one shared instance, pass distro_id per call.

import json
import shutil
import subprocess
from pathlib import Path

from orchestrator.core import console


def _run_vol_command(
    vol_bin: str,
    memory_path: Path,
    isf_path: Path,
    plugin: str,
) -> list[dict]:
    cmd = [
        vol_bin,
        "-f",
        str(memory_path),
        "-s",
        str(isf_path.parent),
        "-r",
        "json",
        plugin,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "vol3: binary not found. Install volatility3 and ensure it is on PATH."
        ) from exc
    if result.returncode != 0:
        raise RuntimeError(
            f"vol3 '{plugin}' failed (rc={result.returncode}):\n"
            f"{result.stderr.strip() or '(no output)'}"
        )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"vol3 '{plugin}' output is not valid JSON: {exc}") from exc

    if isinstance(data, dict) and isinstance(data.get("rows"), list):
        raw_rows = data["rows"]
    elif isinstance(data, list):
        raw_rows = data
    else:
        raise RuntimeError(
            f"vol3 '{plugin}' JSON has an unsupported top-level structure"
        )
    return [row for row in raw_rows if isinstance(row, dict)]


def first_present(row: dict, *keys: str) -> object | None:
    # Volatility field names drift between versions (PID vs Pid, etc.).
    # Probes use this to stay tolerant without hard-coding one spelling.
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


class VolatilityRunner:
    def __init__(self, vol_bin: str, isf_dir: Path) -> None:
        resolved = shutil.which(vol_bin) or vol_bin
        if not Path(resolved).is_file():
            raise FileNotFoundError(
                f"Volatility binary not found: {vol_bin!r}. "
                "Set vol_bin in config.yaml or add vol3 to PATH."
            )
        self._vol_bin = resolved
        self._isf_dir = isf_dir

    def resolve_isf(self, distro_id: str) -> Path:
        # vol3 selects the matching ISF inside -s by kernel banner, so this
        # only has to prove the family has symbols at all and name one for
        # the error/repro text.
        family = distro_id.split("-", 1)[0]
        matches = sorted(self._isf_dir.glob(f"{family}_*.json"))
        if not matches:
            raise RuntimeError(
                f"ISF: no symbol file found for distro family '{family}' "
                f"in {self._isf_dir}. Run 'python cli.py setup --distro {distro_id}' first."
            )
        return matches[-1]

    def probe(self, memory_path: Path, distro_id: str) -> None:
        isf_path = self.resolve_isf(distro_id)
        repro = f"{self._vol_bin} -f {memory_path} -s {isf_path.parent} linux.pslist"

        try:
            rows = _run_vol_command(
                self._vol_bin, memory_path, isf_path, "linux.pslist"
            )
        except RuntimeError as exc:
            raise RuntimeError(
                f"Volatility ISF probe failed for {memory_path.name}. "
                f"ISF: {isf_path}. Repro: {repro}. "
                "ISF may not match this kernel -- check dwarf2json output"
            ) from exc

        has_pid = any(first_present(row, "PID", "Pid", "pid") is not None for row in rows)
        if not rows or not has_pid:
            raise RuntimeError(
                f"Volatility ISF probe returned no processes for {memory_path.name}. "
                f"ISF: {isf_path}. Repro: {repro}. "
                "ISF may not match this kernel -- check dwarf2json output"
            )

        console.ok(
            f"memory probe passed: {len(rows)} process(es) visible (linux.pslist)"
        )
