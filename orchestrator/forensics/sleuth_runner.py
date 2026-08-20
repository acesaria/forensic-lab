# orchestrator/forensics/sleuth_runner.py
#
# SleuthKitRunner wraps Sleuth Kit subprocess calls.
# Owns: binary resolution and the setup-time EWF probe.
# Investigation-time Sleuth Kit work is run by hand from the notebooks.

import shutil
import subprocess
from pathlib import Path

from orchestrator.core import console


class SleuthKitRunner:
    def __init__(
        self,
        mmls_bin: str,
        fls_bin: str,
        fsstat_bin: str,
    ) -> None:
        self._mmls_bin = self._resolve(mmls_bin)
        self._fls_bin = self._resolve(fls_bin)
        self._fsstat_bin = self._resolve(fsstat_bin)

    @staticmethod
    def _resolve(binary: str) -> str:
        resolved = shutil.which(binary) or binary
        if not Path(resolved).is_file():
            raise FileNotFoundError(
                f"Sleuth Kit binary not found: {binary!r}. "
                "Install sleuthkit or add it to PATH."
            )
        return resolved

    def probe(self, disk_path: Path) -> None:
        image_flag = _image_type_flag(disk_path)
        cmd = [self._mmls_bin, *image_flag, str(disk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            hint = ""
            if "-i" in image_flag:
                hint = (
                    " This image is EWF (.E01); a distribution's prebuilt "
                    "sleuthkit package is not guaranteed to be compiled "
                    "against libewf even if libewf-dev is installed "
                    "separately. Run 'mmls -i list' to confirm 'ewf' is "
                    "listed as a supported type; if not, rebuild Sleuth Kit "
                    "from source against libewf-dev."
                )
            raise RuntimeError(
                f"mmls probe failed for {disk_path.name}:\n"
                f"{result.stderr.strip() or '(no output)'}{hint}"
            )
        console.ok(f"disk probe passed: filesystem readable ({disk_path.name})")


def _image_type_flag(disk_path: Path) -> list[str]:
    suffix = disk_path.suffix.lower()
    if suffix in (".e01", ".ewf", ".E01"):
        return ["-i", "ewf"]
    # raw dd images need no -i flag; mmls auto-detects
    return []
