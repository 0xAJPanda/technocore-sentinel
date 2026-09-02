"""Closed, immutable command-local capability availability."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Mapping


class Capability(StrEnum):
    """Capabilities understood by this client release."""

    ROOMS = "rooms"
    READ = "read"
    FOLLOW = "follow"
    POST = "post"
    PROFILE_WRITE = "profile-write"
    EVENTS_ROOM = "events-room"


class Command(StrEnum):
    """Commands governed by the capability registry."""

    ROOMS = "rooms"
    READ = "read"
    FOLLOW = "follow"
    MESSAGE_SEND = "message send"
    MESSAGE_RECONCILE = "message reconcile"
    PUBLISH_PROFILE = "publish-profile"
    EVENT_ROOM_CONSUMPTION = "event-room consumption"


@dataclass(frozen=True, slots=True)
class CapabilityStatus:
    """One exact capability's immutable availability status."""

    capability: Capability
    available: bool

    def __post_init__(self) -> None:
        if type(self.capability) is not Capability:
            raise TypeError("capability must be a Capability")
        if type(self.available) is not bool:
            raise TypeError("available must be a bool")


@dataclass(frozen=True, slots=True, init=False)
class CapabilityRegistry:
    """One complete immutable snapshot of all capability statuses."""

    statuses: tuple[CapabilityStatus, ...]
    available: frozenset[Capability]
    unavailable: frozenset[Capability]

    def __init__(self, statuses: tuple[CapabilityStatus, ...]) -> None:
        if type(statuses) is not tuple:
            raise TypeError("statuses must be a tuple")
        if any(type(status) is not CapabilityStatus for status in statuses):
            raise TypeError("each status must be a CapabilityStatus")

        seen: set[Capability] = set()
        available: set[Capability] = set()
        unavailable: set[Capability] = set()
        for status in statuses:
            if status.capability in seen:
                raise ValueError("capability statuses must be unique")
            seen.add(status.capability)
            if status.available:
                available.add(status.capability)
            else:
                unavailable.add(status.capability)

        if seen != set(Capability):
            raise ValueError("registry must contain every capability exactly once")

        object.__setattr__(self, "statuses", statuses)
        object.__setattr__(self, "available", frozenset(available))
        object.__setattr__(self, "unavailable", frozenset(unavailable))


COMMAND_CAPABILITIES: Final[Mapping[Command, tuple[Capability, ...]]] = (
    MappingProxyType(
        {
            Command.ROOMS: (Capability.ROOMS,),
            Command.READ: (Capability.READ,),
            Command.FOLLOW: (Capability.READ, Capability.FOLLOW),
            Command.MESSAGE_SEND: (Capability.READ, Capability.POST),
            Command.MESSAGE_RECONCILE: (Capability.READ,),
            Command.PUBLISH_PROFILE: (Capability.PROFILE_WRITE,),
            Command.EVENT_ROOM_CONSUMPTION: (
                Capability.READ,
                Capability.EVENTS_ROOM,
            ),
        }
    )
)

CAPABILITY_ERROR_CODES: Final[Mapping[Capability, str]] = MappingProxyType(
    {
        Capability.ROOMS: "capability_rooms_unavailable",
        Capability.READ: "capability_read_unavailable",
        Capability.FOLLOW: "capability_follow_unavailable",
        Capability.POST: "capability_post_unavailable",
        Capability.PROFILE_WRITE: "capability_profile_write_unavailable",
        Capability.EVENTS_ROOM: "capability_events_room_unavailable",
    }
)


class CapabilityUnavailableError(RuntimeError):
    """A command's first required capability is unavailable."""

    def __init__(
        self,
        command: Command,
        missing: tuple[Capability, ...],
    ) -> None:
        if type(command) is not Command:
            raise TypeError("command must be a Command")
        if type(missing) is not tuple or len(missing) != 1:
            raise TypeError("missing must be a one-item tuple")
        if any(type(capability) is not Capability for capability in missing):
            raise TypeError("missing must contain only Capability values")
        self.command = command
        self.missing = missing
        self.error_code = CAPABILITY_ERROR_CODES[missing[0]]
        super().__init__("required capability unavailable")


def required_capabilities(command: Command) -> tuple[Capability, ...]:
    """Return a command's immutable, exact required capability tuple."""
    if type(command) is not Command:
        raise TypeError("command must be a Command")
    return COMMAND_CAPABILITIES[command]


def require_capabilities(command: Command, registry: CapabilityRegistry) -> None:
    """Require only the capabilities used by ``command`` in ``registry``."""
    required = required_capabilities(command)
    if type(registry) is not CapabilityRegistry:
        raise TypeError("registry must be a CapabilityRegistry")
    for capability in required:
        if capability in registry.unavailable:
            raise CapabilityUnavailableError(command, (capability,))
