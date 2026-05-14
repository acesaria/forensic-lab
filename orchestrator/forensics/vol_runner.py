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

_log = logging.getLogger(__name__)


def _run_vol_subprocess(
    vol_bin: str,
    memory_path: str,
    isf_path: str,
    plugin: str,
    extra_args: list[str],
) -> tuple[str, list[dict]]:
    """
    Module-level function required for pickling with ProcessPoolExecutor.
    Returns (plugin_name, rows).
    """
    isf_dir = str(Path(isf_path).parent)
    cmd = [
        vol_bin,
        "-f",
        memory_path,
        "-s",
        isf_dir,
        "-r",
        "json",
        plugin,
        *extra_args,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        raise RuntimeError(
            "vol3: binary not found. Install volatility3 and ensure " "it is on PATH."
        )
    if result.returncode != 0:
        raise RuntimeError(
            f"vol3 '{plugin}' failed (rc={result.returncode}):\n"
            f"{result.stderr.strip() or '(no output)'}"
        )
    try:
        data = json.loads(result.stdout)
        if isinstance(data, dict) and isinstance(data.get("rows"), list):
            raw_rows = data["rows"]
        elif isinstance(data, list):
            raw_rows = data
        else:
            raw_rows = []
        rows = [row for row in raw_rows if isinstance(row, dict)]
        return plugin, rows
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"vol3 '{plugin}' output is not valid JSON: {exc}") from exc


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

    def resolve_isf(self, distro_id: str) -> Path:
        """
        Find the ISF file for distro_id in isf_dir.
        Matches on the distro family prefix (e.g. "ubuntu" from "ubuntu-22.04").
        Returns the most recently modified match.
        Raises if none found.
        """
        family = distro_id.split("-", 1)[0]
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
    ) -> list[dict]:
        """Run a single vol3 plugin. Returns parsed JSON rows."""
        isf_path = self.resolve_isf(distro_id)
        _, rows = _run_vol_subprocess(
            self._vol_bin,
            str(memory_path),
            str(isf_path),
            plugin,
            extra_args or [],
        )
        return rows

    def run_plugins(
        self,
        memory_path: Path,
        distro_id: str,
        plugins: list[str],
        max_workers: int = 4,
    ) -> dict[str, list[dict]]:
        """
        Run multiple plugins in parallel against one memory image.
        Returns {plugin_name: rows} for all plugins.
        Raises RuntimeError listing all failures if any plugin fails.
        """
        isf_path = self.resolve_isf(distro_id)
        results: dict[str, list[dict]] = {}
        failures: list[str] = []

        with ProcessPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(
                    _run_vol_subprocess,
                    self._vol_bin,
                    str(memory_path),
                    str(isf_path),
                    plugin,
                    [],
                ): plugin
                for plugin in plugins
            }
            for future in as_completed(futures):
                plugin = futures[future]
                try:
                    _, rows = future.result()
                    results[plugin] = rows
                    _log.debug("[+] vol3 %s: %d row(s)", plugin, len(rows))
                except Exception as exc:
                    failures.append(f"{plugin}: {exc}")
                    _log.warning("[!] vol3 %s failed: %s", plugin, exc)

        if failures:
            raise RuntimeError("Volatility plugins failed:\n" + "\n".join(failures))
        return results

    def probe(self, memory_path: Path, distro_id: str) -> None:
        """Sanity check: linux.pslist must return at least one process row."""
        isf_path = self.resolve_isf(distro_id)
        isf_dir = isf_path.parent
        cmd = f"{self._vol_bin} -f {memory_path} -s {isf_dir} " "linux.pslist"

        try:
            rows = self.run_plugin(memory_path, distro_id, "linux.pslist")
        except RuntimeError as exc:
            raise RuntimeError(
                f"Volatility ISF probe failed for {memory_path.name}. "
                f"ISF: {isf_path}. Repro: {cmd}. "
                "ISF may not match this kernel -- check dwarf2json output"
            ) from exc

        if isinstance(rows, dict) and "__children" in rows:
            rows_list = rows.get("__children", [])
        elif isinstance(rows, list):
            rows_list = rows
        else:
            rows_list = []

        has_pid = any(
            isinstance(row, dict) and row.get("PID") not in (None, "")
            for row in rows_list
        )
        if not rows_list or not has_pid:
            raise RuntimeError(
                f"Volatility ISF probe returned no processes for {memory_path.name}. "
                f"ISF: {isf_path}. Repro: {cmd}. "
                "ISF may not match this kernel -- check dwarf2json output"
            )

        _log.info(
            "[+] Memory probe passed: %d process visible (linux.pslist)",
            len(rows_list),
        )
