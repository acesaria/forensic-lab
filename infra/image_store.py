"""
infra/image_store.py

Given a distro profile, ensure the base cloud
image is present on disk and its checksum is valid. Nothing else.
VMs use qcow2 overlays so the base image is never written to directly
"""

import hashlib
import os
import shutil
import tempfile
from pathlib import Path
import subprocess
from typing import Any

import requests

from orchestrator.core import console


def _filename_from_url(url: str) -> str:
    return url.rstrip("/").split("/")[-1]


def _compute_checksum(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_image(profile: dict[str, Any], images_dir: Path) -> Path:
    """
    Ensure the base image for *profile* exists in *images_dir* and is valid.

    Returns the absolute path to the verified image. A cached file whose
    checksum no longer matches is removed and re-downloaded once; the user
    never has to manually rm a corrupt cache.
    """
    images_dir.mkdir(parents=True, exist_ok=True)

    img_cfg = profile["image"]
    url: str = img_cfg["url"]
    algo: str = img_cfg["checksum_algo"]
    filename: str = img_cfg.get("filename") or _filename_from_url(url)
    dest = images_dir / filename
    # Every profile pins its own checksum; it is also the build compatibility key.
    expected = str(img_cfg["checksum"]).lower()

    if dest.exists():
        console.info(f"image already present: {dest}")
        console.step(f"verifying {algo} checksum...")
        actual = _compute_checksum(dest, algo)
        if actual == expected:
            console.ok(f"checksum OK: {actual[:16]}...")
            return dest
        console.warn(
            f"cached image checksum mismatch ({actual[:8]} != {expected[:8]}); "
            "redownloading"
        )
        dest.unlink()

    console.step(f"downloading {filename}...")
    _download_atomic(url, dest, expected, algo)
    _lock_base_image(dest)
    console.ok(f"image ready: {dest.name} (locked read-only)")
    return dest


def _download_atomic(url: str, dest: Path, expected: str, algo: str) -> None:
    # Stream into a sibling .part file and only rename on verified checksum.
    # tempfile.mkstemp + os.replace is the stdlib atomic-write pattern and
    # survives SIGINT, network drops, and disk-full mid-write without ever
    # leaving a half-written file at the final path.
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{dest.name}.", suffix=".part", dir=dest.parent
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            _stream_to_file(url, fh)
        console.step(f"verifying {algo} checksum...")
        actual = _compute_checksum(tmp_path, algo)
        if actual != expected:
            raise RuntimeError(
                "checksum mismatch after download\n"
                f"  expected: {expected}\n"
                f"  actual:   {actual}"
            )
        os.replace(tmp_path, dest)
        console.ok(f"checksum OK: {actual[:16]}...")
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def _stream_to_file(url: str, fh) -> None:
    with requests.get(url, stream=True, timeout=60) as resp:
        resp.raise_for_status()
        total = int(resp.headers.get("content-length", 0))
        downloaded = 0
        for chunk in resp.iter_content(chunk_size=4 * 1024 * 1024):
            fh.write(chunk)
            downloaded += len(chunk)
            if total:
                pct = downloaded * 100 // total
                print(
                    f"\r    {pct:3d}%  {downloaded // 1024 // 1024} MB",
                    end="",
                    flush=True,
                )
    print()  # newline after progress


def _lock_base_image(path: Path) -> None:
    # Cached base images are pinned setup-time inputs. Lock them after
    # checksum verification so experiment-time code cannot silently mutate them.
    chown_bin = shutil.which("chown") or "/usr/bin/chown"
    chmod_bin = shutil.which("chmod") or "/usr/bin/chmod"
    try:
        subprocess.run(
            ["sudo", chown_bin, "root:root", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["sudo", chmod_bin, "0444", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"failed to lock base image '{path}':\n"
            f"{(exc.stderr or exc.stdout).strip()}"
        ) from exc
