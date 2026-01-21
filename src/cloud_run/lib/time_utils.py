from __future__ import annotations

from datetime import UTC, datetime


def human_readable_time(dt) -> str:
    """Convert a datetime to human-readable relative time."""
    if dt is None:
        return "unknown"

    now = datetime.now(UTC)
    if getattr(dt, "tzinfo", None) is None:
        dt = dt.replace(tzinfo=UTC)

    diff = now - dt
    seconds = diff.total_seconds()

    if seconds < 60:
        return "just now"
    if seconds < 3600:
        mins = int(seconds / 60)
        return f"{mins} minute{'s' if mins != 1 else ''} ago"
    if seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    if seconds < 604800:
        days = int(seconds / 86400)
        return f"{days} day{'s' if days != 1 else ''} ago"
    return dt.strftime("%Y-%m-%d")
