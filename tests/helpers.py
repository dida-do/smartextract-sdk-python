"""Helper functions for the tests."""

from datetime import datetime, timezone


def recent_time(time: datetime, max_timedelta_second=600) -> bool:
    delta = datetime.now(timezone.utc) - time
    return abs(delta.total_seconds()) < max_timedelta_second
