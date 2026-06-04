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


# fls lines are tab-separated: a "<type>/<type> [*] <inode>:" prefix, then the
# name, then -l metadata (mtime, size, ...) in later fields. We split on tabs
# and only regex-match the prefix; the name is just the next field.
#   d/d 1541:\thome\t<mtime>\t...\t<size>\t<gid>\t<uid>
#   r/r * 12347:\tdeleted.txt\t...
# Inode can be compound (e.g. "12345-128-1") on NTFS/ext attribute streams.
_FLS_PREFIX_RE = re.compile(
    r"^(?P<type>[a-zA-Z\-])/[a-zA-Z\-]\s+(?P<deleted>\*)?\s*(?P<inode>[\d\-]+):$"
)


class SleuthKitRunner:
    def __init__(
        self,
        mmls_bin: str,
        fls_bin: str,
        icat_bin: str,
        fsstat_bin: str,
        istat_bin: str,
    ) -> None:
        self._mmls_bin = self._resolve(mmls_bin)
        self._fls_bin = self._resolve(fls_bin)
        self._icat_bin = self._resolve(icat_bin)
        self._fsstat_bin = self._resolve(fsstat_bin)
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
            fsstat_bin=host_cfg.get("fsstat_bin", "fsstat"),
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

        best_start: int | None = None
        best_length: int = -1
        for line in result.stdout.splitlines():
            parts = line.split()
            # mmls output rows: Slot Start End Length Description
            # Skip header lines and meta/unallocated rows.
            if len(parts) < 4:
                continue
            slot = parts[1]
            # Unallocated rows have "---" in slot; meta rows have "Meta".
            # Real partition slots are numeric (DOS: "00", GPT: "000", "013"...).
            if not slot.replace("-", "").isdigit():
                continue
            try:
                start = int(parts[2])
                length = int(parts[4])
            except (ValueError, IndexError):
                continue
            # Pick the partition with the largest sector count -- that is the root fs.
            if length > best_length:
                best_length = length
                best_start = start

        if best_start is None:
            raise RuntimeError(
                f"no usable partition found in mmls output for {disk_path.name}"
            )

        offset = best_start * 512
        if not self._verify_partition(disk_path, offset):
            raise RuntimeError(
                f"selected partition at sector {best_start} does not appear to be "
                f"ext2/3/4 (fsstat check failed) for {disk_path.name}"
            )
        return offset

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

    def _verify_partition(self, disk_path: Path, offset_bytes: int) -> bool:
        # fsstat confirms the selected offset is actually an ext filesystem before
        # we commit to it. Avoids silently running fls against a swap or EFI partition.
        offset_sectors = offset_bytes // 512
        cmd = [
            self._fsstat_bin,
            "-o",
            str(offset_sectors),
            str(disk_path),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return False
        return "File System Type: Ext" in result.stdout


def _image_type_flag(disk_path: Path) -> list[str]:
    suffix = disk_path.suffix.lower()
    if suffix in (".e01", ".ewf", ".E01"):
        return ["-i", "ewf"]
    # raw dd images need no -i flag; mmls auto-detects
    return []


def parse_fls_line(line: str) -> dict | None:
    # fields: prefix, name, then -l metadata. Only the prefix needs a regex;
    # the name is just the first field after it.
    fields = line.split("\t")
    match = _FLS_PREFIX_RE.match(fields[0])
    if not match or len(fields) < 2:
        return None
    name = fields[1].strip()
    if not name:
        return None
    return {
        "inode": match.group("inode"),
        "name": name,
        "deleted": match.group("deleted") is not None,
        "is_dir": match.group("type").lower() == "d",
        "raw": line,
    }
