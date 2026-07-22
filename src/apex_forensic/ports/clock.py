"""Clock port."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    """Provides timezone-aware timestamps."""

    def now(self) -> datetime:
        """Return current UTC-aware time."""
        ...
