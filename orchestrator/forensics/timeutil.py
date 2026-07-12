# orchestrator/forensics/timeutil.py
#
# Time normalization helpers. Current raw-export timestamps are ISO-8601 UTC
# with millisecond resolution; the string form is the contract.

from __future__ import annotations

from datetime import datetime, timezone

_ISO_MS = "%Y-%m-%dT%H:%M:%S.%fZ"


def iso_utc_ms(dt: datetime) -> str:
    """Format a datetime as ISO-8601 UTC with millisecond resolution (Z suffix)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    # %f is microseconds; trim to milliseconds.
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def now_utc_ms() -> str:
    return iso_utc_ms(datetime.now(timezone.utc))


def parse_iso_utc(ts: str) -> float:
    """Parse an ISO-8601 UTC timestamp to epoch seconds (float).

    Accepts a trailing Z or an explicit offset. Raises ValueError on garbage.
    """
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).timestamp()


def epoch_us_to_iso_ms(ts_us: int) -> str:
    """Plaso stores timestamps as microseconds since the Unix epoch (UTC)."""
    return iso_utc_ms(datetime.fromtimestamp(ts_us / 1_000_000, timezone.utc))
