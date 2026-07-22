"""Cooperative cancellation token."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Event


@dataclass(slots=True)
class PauseToken:
    """A tiny thread-safe cooperative pause token."""

    _event: Event

    @classmethod
    def new(cls) -> PauseToken:
        """Create a new unset token."""

        return cls(Event())

    def request_pause(self) -> None:
        """Request a pause at the next coordinator checkpoint."""

        self._event.set()

    @property
    def is_pause_requested(self) -> bool:
        """Whether a pause has been requested."""

        return self._event.is_set()


@dataclass(slots=True)
class CancellationToken:
    """A tiny thread-safe cancellation token."""

    _event: Event

    @classmethod
    def new(cls) -> CancellationToken:
        """Create a new unset token."""

        return cls(Event())

    def cancel(self) -> None:
        """Request cancellation."""

        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        """Whether cancellation has been requested."""

        return self._event.is_set()
