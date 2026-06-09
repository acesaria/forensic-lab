# orchestrator/forensics/ioc_detector/status.py
#
# The shared status vocabulary. Every detector reports one of these, and the
# evaluator imports them to grade recovery quality, so it is defined once here --
# the producer (detector) and consumer (evaluator) never drift.

from __future__ import annotations

from typing import Any

DISK_STATUS_NOT_FOUND = "not_found"
DISK_STATUS_DELETED_ENTRY_ONLY = "deleted_entry_only"
DISK_STATUS_DELETED_RECOVERED = "deleted_recovered"
DISK_STATUS_PRESENT = "present"

# Ordered weakest -> strongest; STATUS_RANK lets the disk detector pick the best
# of several candidate inodes. Memory/timeline detections have no deletion
# semantics and reuse only present / not_found from this same set.
DISK_STATUSES = (
    DISK_STATUS_NOT_FOUND,
    DISK_STATUS_DELETED_ENTRY_ONLY,
    DISK_STATUS_DELETED_RECOVERED,
    DISK_STATUS_PRESENT,
)
STATUS_RANK = {name: i for i, name in enumerate(DISK_STATUSES)}


def empty_detection() -> dict[str, Any]:
    # The "looked, found nothing" result, shared by every detector.
    return {
        "found": False,
        "status": DISK_STATUS_NOT_FOUND,
        "evidence": None,
        "timestamp": None,
        "matches": [],
    }


def found_from_status(status: str) -> bool:
    # Uniform policy (no per-spec flags): any surviving trace counts as found,
    # including a bare tombstone (deleted_entry_only). How well it survived is
    # graded later by the status -> quality scale. Content specs add their own
    # content gate on top of this in the disk detector.
    return status != DISK_STATUS_NOT_FOUND
