# orchestrator/forensics/sleuth_runner.py
#
# SleuthKitRunner wraps Sleuth Kit subprocess calls.
# Owns: binary resolution, EWF probing, partition discovery, file listing
# (fls), file content extraction (icat), and inode metadata (istat).
# All Sleuth Kit invocations go through here.

import logging
import re
import shutil
import subprocess
from pathlib import Path

from orchestrator.core import console

_log = logging.getLogger(__name__)


# fls -l line format:
#   r/r 12345:        name.txt    <size> <mtime> ...
#   d/d 12346:        dirname/
#   r/r * 12347:      deleted.txt ...
# Inode can be compound (e.g. "12345-128-1") on NTFS/ext attribute streams.
_FLS_LINE_RE = re.compile(
    r"^"
    r"(?P<t1>[a-zA-Z\-])/(?P<t2>[a-zA-Z\-])"
    r"\s+"
    r"(?P<deleted>\*\s+)?"
    r"(?P<inode>[\d\-]+):"
    r"\s+"
    r"(?P<name>.+?)"
    r"(?:\s{2,}.*)?$"
)


class SleuthKitRunner:
    def __init__(
        self,
        mmls_bin: str,
        fls_bin: str,
        icat_bin: str,
        istat_bin: str,
    ) -> None:
        self._mmls_bin = self._resolve(mmls_bin)
        self._fls_bin = self._resolve(fls_bin)
        self._icat_bin = self._resolve(icat_bin)
        self._istat_bin = self._resolve(istat_bin)

    @staticmethod
    def _resolve(binary: str) -> str:
        resolved = shutil.which(binary) or binary
        if not Path(resolved).is_file():
            raise FileNotFoundError(
                f"Sleuth Kit binary not found: {binary!r}. "
                "Install sleuthkit or add it to PATH."
            )
        return resolved

    @classmethod
    def from_config(cls, host_cfg: dict) -> "SleuthKitRunner":
        return cls(
            mmls_bin=host_cfg.get("mmls_bin", "mmls"),
            fls_bin=host_cfg.get("fls_bin", "fls"),
            icat_bin=host_cfg.get("icat_bin", "icat"),
            istat_bin=host_cfg.get("istat_bin", "istat"),
        )

    def probe(self, disk_path: Path) -> None:
        cmd = [self._mmls_bin, *_image_type_flag(disk_path), str(disk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"mmls probe failed for {disk_path.name}:\n"
                f"{result.stderr.strip() or '(no output)'}"
            )
        console.ok(f"disk probe passed: filesystem readable ({disk_path.name})")

    def partition_offset(self, disk_path: Path) -> int:
        cmd = [self._mmls_bin, *_image_type_flag(disk_path), str(disk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"mmls failed for {disk_path.name}:\n"
                f"{result.stderr.strip() or '(no output)'}"
            )

        # Prefer an explicit "Linux" partition; fall back to the first real
        # slot entry (slot column contains ':', which excludes Meta/unallocated).
        first_sector: int | None = None
        linux_sector: int | None = None
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            slot = parts[1]
            if ":" not in slot:
                continue
            try:
                start = int(parts[2])
            except ValueError:
                continue
            if first_sector is None:
                first_sector = start
            if "Linux" in line and linux_sector is None:
                linux_sector = start

        chosen = linux_sector if linux_sector is not None else first_sector
        if chosen is None:
            raise RuntimeError(
                f"no usable partition found in mmls output for {disk_path.name}"
            )
        return chosen * 512

    def fls(self, disk_path: Path, offset: int, flags: str = "-r -l") -> list[str]:
        # fls expects -o in sectors, while callers carry offsets in bytes.
        offset_sectors = offset // 512
        cmd = [self._fls_bin, *flags.split(), "-o", str(offset_sectors), str(disk_path)]
        _log.debug("fls: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"fls failed for {disk_path.name}:\n"
                f"{result.stderr.strip() or '(no output)'}"
            )
        return [line for line in result.stdout.splitlines() if line.strip()]

    def icat(self, disk_path: Path, offset: int, inode: str) -> bytes:
        offset_sectors = offset // 512
        cmd = [self._icat_bin, "-o", str(offset_sectors), str(disk_path), inode]
        _log.debug("icat: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"icat failed for inode {inode} on {disk_path.name}:\n"
                f"{result.stderr.decode('utf-8', errors='replace').strip() or '(no output)'}"
            )
        return result.stdout

    def istat(self, disk_path: Path, offset: int, inode: str) -> str:
        offset_sectors = offset // 512
        cmd = [self._istat_bin, "-o", str(offset_sectors), str(disk_path), inode]
        _log.debug("istat: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"istat failed for inode {inode} on {disk_path.name}:\n"
                f"{result.stderr.strip() or '(no output)'}"
            )
        return result.stdout


def _image_type_flag(disk_path: Path) -> list[str]:
    suffix = disk_path.suffix.lower()
    if suffix in (".e01", ".ewf", ".E01"):
        return ["-i", "ewf"]
    # raw dd images need no -i flag; mmls auto-detects
    return []


def parse_fls_line(line: str) -> dict | None:
    match = _FLS_LINE_RE.match(line)
    if not match:
        return None
    return {
        "inode": match.group("inode"),
        "name": match.group("name").strip(),
        "deleted": match.group("deleted") is not None,
        "is_dir": match.group("t1").lower() == "d",
        "raw": line,
    }
