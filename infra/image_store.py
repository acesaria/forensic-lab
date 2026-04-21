"""
infra/image_store.py

Responsible for one thing: given a distro profile, ensure the base cloud
image is present on disk and its checksum is valid. Nothing else.

After a successful verification the image is set read-only so nothing
accidentally writes to the base image (VMs use qcow2 overlays instead).
"""

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

import requests


def _filename_from_url(url: str) -> str:
    return url.rstrip("/").split("/")[-1]


def _compute_checksum(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _expected_checksum(checksum_url: str, filename: str, algo: str) -> str:
    """
    Fetch the remote checksum file and extract the hash for *filename*.

    Ubuntu SHA256SUMS format:   <hash>  <filename>
    Debian  SHA512SUMS format:  <hash>  <filename>
    Both are the same line structure, so one parser handles both.
    """
    resp = requests.get(checksum_url, timeout=30)
    resp.raise_for_status()

    for line in resp.text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        # the filename in the manifest may have a leading "./" or "*"
        manifest_name = parts[-1].lstrip("./").lstrip("*")
        if manifest_name == filename:
            return parts[0].lower()

    raise RuntimeError(
        f"Checksum for '{filename}' not found in {checksum_url}"
    )


def _set_readonly(path: Path) -> None:
    current = stat.S_IMODE(os.stat(path).st_mode)
    readonly = current & ~(stat.S_IWRITE | stat.S_IWGRP | stat.S_IWOTH)
    os.chmod(path, readonly)


def ensure_image(profile: dict[str, Any], images_dir: Path) -> Path:
    """
    Ensure the base image for *profile* exists in *images_dir* and is valid.

    Returns the absolute path to the verified image.
    Raises RuntimeError on checksum mismatch.
    """
    images_dir.mkdir(parents=True, exist_ok=True)

    img_cfg = profile["image"]
    url: str = img_cfg["url"]
    checksum_url: str = img_cfg["checksum_url"]
    algo: str = img_cfg["checksum_algo"]
    filename: str = img_cfg.get("filename") or _filename_from_url(url)
    dest = images_dir / filename

    # --- already present: just verify ---
    if dest.exists():
        print(f"[i] Image already present: {dest}")
        print(f"[*] Verifying {algo} checksum...")
        actual = _compute_checksum(dest, algo)
        expected = _expected_checksum(checksum_url, filename, algo)
        if actual != expected:
            raise RuntimeError(
                f"Checksum mismatch for {filename}\n"
                f"  expected: {expected}\n"
                f"  actual:   {actual}"
            )
        print(f"[+] Checksum OK: {actual[:16]}...")
        _set_readonly(dest)
        return dest

    # --- not present: download then verify ---
    print(f"[*] Downloading {filename} ...")
    _download(url, dest)
    print(f"[*] Verifying {algo} checksum...")
    actual = _compute_checksum(dest, algo)
    expected = _expected_checksum(checksum_url, filename, algo)
    if actual != expected:
        dest.unlink(missing_ok=True)
        raise RuntimeError(
            f"Checksum mismatch after download — file removed.\n"
            f"  expected: {expected}\n"
            f"  actual:   {actual}"
        )
    print(f"[+] Checksum OK: {actual[:16]}...")
    _set_readonly(dest)
    return dest


def _download(url: str, dest: Path) -> None:
    with requests.get(url, stream=True, timeout=60) as resp:
        resp.raise_for_status()
        total = int(resp.headers.get("content-length", 0))
        downloaded = 0
        with open(dest, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=4 * 1024 * 1024):
                fh.write(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded * 100 // total
                    print(f"\r    {pct:3d}%  {downloaded // 1024 // 1024} MB", end="", flush=True)
    print()  # newline after progress
