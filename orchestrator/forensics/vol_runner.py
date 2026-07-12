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
#   vol = VolatilityRunner.from_config(host_cfg, isf_dir)
#   vol.run_plugins(memory_path, "ubuntu-22.04", ["linux.pslist"])

import json
import logging
import shutil
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from orchestrator.core import console

_log = logging.getLogger(__name__)


def _isf_name(family: str, kernel_release: str) -> str:
    # Mirrors orchestrator._isf_filename so build and resolve agree on the name.
    return f"{family}_{kernel_release.replace('/', '_')}.json"


def _run_vol_command(
    vol_bin: str,
    memory_path: Path,
    isf_path: Path,
    plugin: str,
    extra_args: list[str] | None = None,
    invocation: dict | None = None,
) -> list[dict]:
    # Module-level so ProcessPoolExecutor can pickle it. Centralises JSON
    # normalization so run_plugin and run_plugins agree on row shape.
    cmd = [
        vol_bin,
        "-f",
        str(memory_path),
        "-s",
        str(isf_path.parent),
        "-r",
        "json",
        plugin,
        *(extra_args or []),
    ]
    if invocation is not None:
        invocation.update({"command": cmd, "status": "running"})
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError as exc:
        if invocation is not None:
            invocation.update(
                {
                    "status": "failed",
                    "exit_status": None,
                    "stdout": "",
                    "stderr": str(exc),
                }
            )
        raise RuntimeError(
            "vol3: binary not found. Install volatility3 and ensure it is on PATH."
        ) from exc
    if invocation is not None:
        invocation.update(
            {
                "exit_status": result.returncode,
                "stderr": result.stderr or "",
            }
        )
    if result.returncode != 0:
        if invocation is not None:
            invocation["status"] = "failed"
            invocation["stdout"] = result.stdout or ""
        raise RuntimeError(
            f"vol3 '{plugin}' failed (rc={result.returncode}):\n"
            f"{result.stderr.strip() or '(no output)'}"
        )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        if invocation is not None:
            invocation["status"] = "failed"
            invocation["stdout"] = result.stdout or ""
        raise RuntimeError(f"vol3 '{plugin}' output is not valid JSON: {exc}") from exc

    if isinstance(data, dict) and isinstance(data.get("rows"), list):
        raw_rows = data["rows"]
    elif isinstance(data, list):
        raw_rows = data
    else:
        if invocation is not None:
            invocation["status"] = "failed"
            invocation["stdout"] = result.stdout or ""
        raise RuntimeError(
            f"vol3 '{plugin}' JSON has an unsupported top-level structure"
        )
    rows = [row for row in raw_rows if isinstance(row, dict)]
    if invocation is not None:
        invocation.update(
            {
                "status": "completed",
                "result": "zero_results" if not rows else "results",
                "row_count": len(rows),
            }
        )
    return rows


def first_present(row: dict, *keys: str) -> object | None:
    # Volatility field names drift between versions (PID vs Pid, etc.).
    # Evaluator code can use this to stay tolerant without hard-coding one spelling.
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
                "Set vol_bin in config.yml or add vol3 to PATH."
            )
        self._vol_bin = resolved
        self._isf_dir = isf_dir

    @classmethod
    def from_config(cls, host_cfg: dict, isf_dir: Path) -> "VolatilityRunner":
        return cls(
            vol_bin=host_cfg.get("vol_bin", "vol3"),
            isf_dir=isf_dir,
        )

    def resolve_isf(self, distro_id: str, kernel_release: str | None = None) -> Path:
        family = distro_id.split("-", 1)[0]
        # An exact kernel match is required when several distros share a family
        # prefix (ubuntu-22.04 and ubuntu-24.04 both glob as ubuntu_*); the
        # lexically-last ISF would otherwise be the wrong kernel's symbols.
        if kernel_release:
            exact = self._isf_dir / _isf_name(family, kernel_release)
            if exact.is_file():
                return exact
        matches = sorted(self._isf_dir.glob(f"{family}_*.json"))
        if not matches:
            raise RuntimeError(
                f"ISF: no symbol file found for distro family '{family}' "
                f"in {self._isf_dir}. Run 'python cli.py setup --distro {distro_id}' first."
            )
        return matches[-1]

    def run_plugin(
        self,
        memory_path: Path,
        distro_id: str,
        plugin: str,
        extra_args: list[str] | None = None,
        kernel_release: str | None = None,
        invocation: dict | None = None,
    ) -> list[dict]:
        isf_path = self.resolve_isf(distro_id, kernel_release)
        return _run_vol_command(
            self._vol_bin,
            memory_path,
            isf_path,
            plugin,
            extra_args,
            invocation,
        )

    def run_plugins(
        self,
        memory_path: Path,
        distro_id: str,
        plugins: list[str] | dict[str, list[str]],
        max_workers: int = 4,
    ) -> dict[str, list[dict]]:
        # Accept either a flat list (no extra args) or a mapping of
        # plugin -> args. Normalize to a single dict shape internally.
        if isinstance(plugins, dict):
            plugin_args: dict[str, list[str]] = {p: list(a) for p, a in plugins.items()}
        else:
            plugin_args = {p: [] for p in plugins}

        isf_path = self.resolve_isf(distro_id)
        results: dict[str, list[dict]] = {}
        failures: list[str] = []

        with ProcessPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(
                    _run_vol_command,
                    self._vol_bin,
                    memory_path,
                    isf_path,
                    plugin,
                    args,
                ): plugin
                for plugin, args in plugin_args.items()
            }
            for future in as_completed(futures):
                plugin = futures[future]
                try:
                    rows = future.result()
                    results[plugin] = rows
                    _log.debug("vol3 %s: %d row(s)", plugin, len(rows))
                except Exception as exc:
                    failures.append(f"{plugin}: {exc}")
                    console.warn(f"vol3 {plugin} failed: {exc}")

        if failures:
            raise RuntimeError("Volatility plugins failed:\n" + "\n".join(failures))
        return results

    def probe(self, memory_path: Path, distro_id: str) -> None:
        isf_path = self.resolve_isf(distro_id)
        repro = f"{self._vol_bin} -f {memory_path} -s {isf_path.parent} linux.pslist"

        try:
            rows = self.run_plugin(memory_path, distro_id, "linux.pslist")
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
