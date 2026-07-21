"""System adapters for clocks and UUID generation."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from apex_forensic._time import utc_now


class SystemClock:
    """Clock adapter backed by the host system clock."""

    def now(self) -> datetime:
        """Return the current UTC timestamp."""

        return utc_now()


class UuidGenerator:
    """UUID4 identifier generator."""

    def new_id(self) -> str:
        """Return a new UUID string."""

        return str(uuid4())
