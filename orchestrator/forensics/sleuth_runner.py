# orchestrator/forensics/sleuth_runner.py
#
# SleuthKitRunner wraps Sleuth Kit subprocess calls.
# Owns: binary resolution, EWF probing, error reporting.
# All Sleuth Kit invocations go through here.

import shutil
import subprocess
from pathlib import Path


class SleuthKitRunner:
    def __init__(self, mmls_bin: str) -> None:
        resolved = shutil.which(mmls_bin) or mmls_bin
        if not Path(resolved).is_file():
            raise FileNotFoundError(
                f"Sleuth Kit binary not found: {mmls_bin!r}. "
                "Install sleuthkit or add mmls to PATH."
            )
        self._mmls_bin = resolved

    @classmethod
    def from_config(cls, host_cfg: dict) -> "SleuthKitRunner":
        return cls(mmls_bin=host_cfg.get("mmls_bin", "mmls"))

    def probe(self, disk_path: Path) -> None:
        cmd = [self._mmls_bin, "-i", "ewf", str(disk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"mmls probe failed for {disk_path.name}:\n"
                f"{result.stderr.strip() or '(no output)'}"
            )
        print(f"[+] Disk probe passed ({disk_path.name})")
