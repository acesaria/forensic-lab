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
import shutil
import subprocess
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path


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
    cmd = [
        vol_bin,
        "-f",
        memory_path,
        "--single-location",
        isf_path,
        "-r",
        "json",
        plugin,
        *extra_args,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"vol3 '{plugin}' failed (rc={result.returncode}):\n"
            f"{result.stderr.strip() or '(no output)'}"
        )
    try:
        return plugin, json.loads(result.stdout)
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
            raise FileNotFoundError(
                f"No ISF found for '{distro_id}' in {self._isf_dir}. "
                "Run 'forensic-lab setup' first."
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
                    print(f"[+] vol3 {plugin}: {len(rows)} row(s)")
                except Exception as exc:
                    failures.append(f"{plugin}: {exc}")
                    print(f"[!] vol3 {plugin} failed: {exc}")

        if failures:
            raise RuntimeError("Volatility plugins failed:\n" + "\n".join(failures))
        return results

    def probe(self, memory_path: Path, distro_id: str) -> None:
        """Sanity check: banners plugin must return at least one row."""
        rows = self.run_plugin(memory_path, distro_id, "banners")
        if not rows:
            raise RuntimeError(
                f"Volatility banner probe returned no output for " f"{memory_path.name}"
            )
        print(f"[+] Memory probe passed ({len(rows)} banner(s))")
