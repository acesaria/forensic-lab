# orchestrator/forensics/sleuth_runner.py
#
# SleuthKitRunner wraps Sleuth Kit subprocess calls.
# Owns: binary resolution, EWF probing, partition discovery, and recursive
# file listing with fls.
# All Sleuth Kit invocations go through here.

import logging
import shutil
import subprocess
from pathlib import Path

from orchestrator.core import console
from orchestrator.core.provenance import command_result

_log = logging.getLogger(__name__)


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
        cmd = [self._mmls_bin, *_image_type_flag(disk_path), str(disk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"mmls probe failed for {disk_path.name}:\n"
                f"{result.stderr.strip() or '(no output)'}"
            )
        console.ok(f"disk probe passed: filesystem readable ({disk_path.name})")

    def partition_offset(
        self,
        disk_path: Path,
        invocations: list[dict] | None = None,
    ) -> int:
        # Byte offset of the first ext2/3/4 filesystem. Walk the mmls table and
        # confirm candidate partitions with fsstat. The pipeline intentionally
        # uses the first ext partition and does not handle multi-root layouts.
        cmd = [self._mmls_bin, *_image_type_flag(disk_path), str(disk_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        _record_invocation(invocations, cmd, result, preserve_stdout=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"mmls failed for {disk_path.name}:\n"
                f"{result.stderr.strip() or '(no output)'}"
            )

        for line in result.stdout.splitlines():
            parts = line.split()
            # mmls rows: Slot Start End Length Description. Skip headers and
            # meta/unallocated rows (slot "Meta" or "---"); real slots are numeric.
            if len(parts) < 5:
                continue
            if not parts[1].replace("-", "").isdigit():
                continue
            try:
                start = int(parts[2])
            except (ValueError, IndexError):
                continue
            offset = start * 512
            if self._verify_partition(
                disk_path, offset, invocations=invocations
            ):  # fsstat says ext?
                return offset

        raise RuntimeError(
            f"no ext2/3/4 partition found in mmls output for {disk_path.name}"
        )

    def fls(
        self,
        disk_path: Path,
        offset: int,
        flags: str = "-r -l",
        invocations: list[dict] | None = None,
    ) -> list[str]:
        # fls expects -o in sectors, while callers carry offsets in bytes.
        offset_sectors = offset // 512
        cmd = [self._fls_bin, *flags.split(), "-o", str(offset_sectors), str(disk_path)]
        _log.debug("fls: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        _record_invocation(invocations, cmd, result, preserve_stdout=False)
        if result.returncode != 0:
            raise RuntimeError(
                f"fls failed for {disk_path.name}:\n"
                f"{result.stderr.strip() or '(no output)'}"
            )
        return [line for line in result.stdout.splitlines() if line.strip()]

    def _verify_partition(
        self,
        disk_path: Path,
        offset_bytes: int,
        invocations: list[dict] | None = None,
    ) -> bool:
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
        _record_invocation(invocations, cmd, result, preserve_stdout=True)
        if result.returncode != 0:
            return False
        return "File System Type: Ext" in result.stdout


def _record_invocation(
    invocations: list[dict] | None,
    command: list[str],
    result: subprocess.CompletedProcess[str],
    *,
    preserve_stdout: bool,
) -> None:
    if invocations is None:
        return
    invocations.append(
        command_result(command, result, include_stdout=preserve_stdout)
    )


def _image_type_flag(disk_path: Path) -> list[str]:
    suffix = disk_path.suffix.lower()
    if suffix in (".e01", ".ewf", ".E01"):
        return ["-i", "ewf"]
    # raw dd images need no -i flag; mmls auto-detects
    return []
