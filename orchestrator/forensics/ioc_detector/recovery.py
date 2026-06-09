# orchestrator/forensics/ioc_detector/recovery.py
#
# Disk content recovery as an ordered chain of backends. The Sleuth Kit detector
# asks recover_content() for an inode's bytes; each ContentRecoverer is tried in
# turn and the first to return data wins, with its name recorded so the report
# shows how the content was recovered.
#
# Today the chain is icat alone. To add a tool -- e.g. extundelete, then
# ext4magic, for deleted ext4 inodes whose block pointers icat can't follow --
# write a ContentRecoverer and append it to DISK_RECOVERY_CHAIN. Nothing else
# changes: the detector, the evidence schema, and the status grading stay put.

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from orchestrator.forensics.ioc_detector.context import DetectorContext

_log = logging.getLogger(__name__)


class ContentRecoverer(Protocol):
    name: str

    def available(self) -> bool:
        ...

    def recover(self, ctx: "DetectorContext", inode: str) -> bytes | None:
        ...


class IcatRecoverer:
    # Sleuth Kit icat reads the data blocks the inode still points at. For a live
    # file that is its content; for a deleted ext4 inode whose block pointers were
    # zeroed it returns nothing -- which is where the next recoverer takes over.
    name = "icat"

    def available(self) -> bool:
        return True

    def recover(self, ctx: "DetectorContext", inode: str) -> bytes | None:
        try:
            return ctx.sleuth.icat(ctx.disk_path, ctx.offset, inode)
        except RuntimeError as exc:
            _log.warning("icat failed for inode %s: %s", inode, exc)
            return None


DISK_RECOVERY_CHAIN: tuple[ContentRecoverer, ...] = (IcatRecoverer(),)


def recover_content(ctx: "DetectorContext", inode: str) -> tuple[bytes | None, str]:
    # Returns (content, winning_method). content is None when no available backend
    # recovered anything; the method name then defaults to the first backend just
    # for labelling (the caller ignores it when there is no body).
    for recoverer in DISK_RECOVERY_CHAIN:
        if not recoverer.available():
            continue
        blob = recoverer.recover(ctx, inode)
        if blob:
            return blob, recoverer.name
    return None, DISK_RECOVERY_CHAIN[0].name
