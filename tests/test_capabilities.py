"""Executable specifications for the closed command capability registry."""

from dataclasses import FrozenInstanceError
from enum import Enum
from types import MappingProxyType
import unittest

from technocore_sentinel.capabilities import (
    CAPABILITY_ERROR_CODES,
    COMMAND_CAPABILITIES,
    Capability,
    CapabilityRegistry,
    CapabilityStatus,
    CapabilityUnavailableError,
    Command,
    require_capabilities,
    required_capabilities,
)


class CapabilityTests(unittest.TestCase):
    @staticmethod
    def _registry(*unavailable: Capability) -> CapabilityRegistry:
        unavailable_set = frozenset(unavailable)
        return CapabilityRegistry(
            tuple(
                CapabilityStatus(capability, capability not in unavailable_set)
                for capability in Capability
            )
        )

    def test_missing_capability_is_command_local(self) -> None:
        without_post = self._registry(Capability.POST)
        with self.assertRaises(CapabilityUnavailableError) as raised:
            require_capabilities(Command.MESSAGE_SEND, without_post)
        self.assertEqual(raised.exception.command, Command.MESSAGE_SEND)
        self.assertEqual(raised.exception.missing, (Capability.POST,))
        self.assertEqual(raised.exception.error_code, "capability_post_unavailable")
        self.assertEqual(str(raised.exception), "required capability unavailable")
        self.assertIsNone(require_capabilities(Command.READ, without_post))
        self.assertIsNone(require_capabilities(Command.MESSAGE_RECONCILE, without_post))

        without_follow = self._registry(Capability.FOLLOW)
        with self.assertRaises(CapabilityUnavailableError) as raised:
            require_capabilities(Command.FOLLOW, without_follow)
        self.assertEqual(raised.exception.missing, (Capability.FOLLOW,))
        self.assertIsNone(require_capabilities(Command.READ, without_follow))

        independent_cases = (
            (Capability.ROOMS, Command.ROOMS, Command.READ),
            (Capability.PROFILE_WRITE, Command.PUBLISH_PROFILE, Command.ROOMS),
            (
                Capability.EVENTS_ROOM,
                Command.EVENT_ROOM_CONSUMPTION,
                Command.MESSAGE_RECONCILE,
            ),
        )
        for unavailable, blocked, unaffected in independent_cases:
            with self.subTest(unavailable=unavailable):
                registry = self._registry(unavailable)
                with self.assertRaises(CapabilityUnavailableError):
                    require_capabilities(blocked, registry)
                self.assertIsNone(require_capabilities(unaffected, registry))

    def test_enums_are_closed_and_serialize_exactly(self) -> None:
        self.assertEqual(
            tuple((member.name, member.value) for member in Capability),
            (
                ("ROOMS", "rooms"),
                ("READ", "read"),
                ("FOLLOW", "follow"),
                ("POST", "post"),
                ("PROFILE_WRITE", "profile-write"),
                ("EVENTS_ROOM", "events-room"),
            ),
        )
        self.assertEqual(
            tuple((member.name, member.value) for member in Command),
            (
                ("ROOMS", "rooms"),
                ("READ", "read"),
                ("FOLLOW", "follow"),
                ("MESSAGE_SEND", "message send"),
                ("MESSAGE_RECONCILE", "message reconcile"),
                ("PUBLISH_PROFILE", "publish-profile"),
                ("EVENT_ROOM_CONSUMPTION", "event-room consumption"),
            ),
        )

    def test_exact_command_map_is_immutable_and_complete(self) -> None:
        expected = {
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
        self.assertIs(type(COMMAND_CAPABILITIES), MappingProxyType)
        self.assertEqual(dict(COMMAND_CAPABILITIES), expected)
        self.assertEqual(tuple(COMMAND_CAPABILITIES), tuple(Command))
        for command, capabilities in expected.items():
            with self.subTest(command=command):
                required = required_capabilities(command)
                self.assertIs(type(required), tuple)
                self.assertEqual(required, capabilities)
                with self.assertRaises((AttributeError, TypeError)):
                    required.append(Capability.POST)  # type: ignore[attr-defined]
        with self.assertRaises(TypeError):
            COMMAND_CAPABILITIES[Command.READ] = ()  # type: ignore[index]

    def test_each_command_checks_only_its_exact_requirements(self) -> None:
        all_available = self._registry()
        for command, requirements in COMMAND_CAPABILITIES.items():
            with self.subTest(command=command, state="all-available"):
                self.assertIsNone(require_capabilities(command, all_available))
            unrelated = tuple(
                capability for capability in Capability if capability not in requirements
            )
            with self.subTest(command=command, state="only-unrelated-unavailable"):
                self.assertIsNone(require_capabilities(command, self._registry(*unrelated)))
            for capability in requirements:
                with self.subTest(command=command, missing=capability):
                    with self.assertRaises(CapabilityUnavailableError) as raised:
                        require_capabilities(command, self._registry(capability))
                    self.assertEqual(raised.exception.command, command)
                    self.assertEqual(raised.exception.missing, (capability,))
                    self.assertEqual(
                        raised.exception.error_code,
                        CAPABILITY_ERROR_CODES[capability],
                    )

    def test_available_unavailable_matrix_is_command_local(self) -> None:
        capabilities = tuple(Capability)
        for mask in range(1 << len(capabilities)):
            unavailable = tuple(
                capability
                for index, capability in enumerate(capabilities)
                if mask & (1 << index)
            )
            registry = self._registry(*unavailable)
            for command, requirements in COMMAND_CAPABILITIES.items():
                expected_missing = next(
                    (item for item in requirements if item in unavailable),
                    None,
                )
                with self.subTest(mask=mask, command=command):
                    if expected_missing is None:
                        self.assertIsNone(require_capabilities(command, registry))
                    else:
                        with self.assertRaises(CapabilityUnavailableError) as raised:
                            require_capabilities(command, registry)
                        self.assertEqual(raised.exception.missing, (expected_missing,))
                        self.assertEqual(
                            raised.exception.error_code,
                            CAPABILITY_ERROR_CODES[expected_missing],
                        )

    def test_capability_error_codes_are_exact_closed_and_immutable(self) -> None:
        expected = {
            Capability.ROOMS: "capability_rooms_unavailable",
            Capability.READ: "capability_read_unavailable",
            Capability.FOLLOW: "capability_follow_unavailable",
            Capability.POST: "capability_post_unavailable",
            Capability.PROFILE_WRITE: "capability_profile_write_unavailable",
            Capability.EVENTS_ROOM: "capability_events_room_unavailable",
        }
        self.assertIs(type(CAPABILITY_ERROR_CODES), MappingProxyType)
        self.assertEqual(dict(CAPABILITY_ERROR_CODES), expected)
        self.assertEqual(tuple(CAPABILITY_ERROR_CODES), tuple(Capability))
        with self.assertRaises(TypeError):
            CAPABILITY_ERROR_CODES[Capability.READ] = "changed"  # type: ignore[index]

    def test_status_and_registry_are_frozen_slotted_snapshots(self) -> None:
        status = CapabilityStatus(Capability.READ, True)
        registry = self._registry(Capability.POST)
        self.assertFalse(hasattr(status, "__dict__"))
        self.assertFalse(hasattr(registry, "__dict__"))
        with self.assertRaises(FrozenInstanceError):
            status.available = False  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            registry.statuses = ()  # type: ignore[misc]
        self.assertIs(type(registry.statuses), tuple)
        self.assertIs(type(registry.available), frozenset)
        self.assertIs(type(registry.unavailable), frozenset)
        self.assertEqual(registry.unavailable, frozenset({Capability.POST}))
        self.assertEqual(
            registry.available | registry.unavailable,
            frozenset(Capability),
        )
        source = tuple(CapabilityStatus(capability, True) for capability in Capability)
        first = CapabilityRegistry(source)
        second = CapabilityRegistry(tuple(source))
        self.assertIsNot(first, second)
        self.assertIsNot(first.available, second.available)
        self.assertIsNot(first.unavailable, second.unavailable)

    def test_status_rejects_strings_classes_spoofs_and_non_bool_state(self) -> None:
        class SpoofCapability(Enum):
            READ = "read"

        with self.assertRaises(TypeError):
            class ExtendedCapability(Capability):  # type: ignore[misc]
                EXTRA = "extra"

        with self.assertRaises(TypeError):
            class ExtendedCommand(Command):  # type: ignore[misc]
                EXTRA = "extra"

        class StatusSubclass(CapabilityStatus):
            pass

        complete = tuple(CapabilityStatus(capability, True) for capability in Capability)
        with self.assertRaises(TypeError):
            CapabilityRegistry(complete[:-1] + (StatusSubclass(Capability.EVENTS_ROOM, True),))

        for capability in ("read", Capability, SpoofCapability.READ, True, 1):
            with self.subTest(capability=capability):
                with self.assertRaises(TypeError):
                    CapabilityStatus(capability, True)  # type: ignore[arg-type]
        for available in (1, 0, "available", None, Capability.READ):
            with self.subTest(available=available):
                with self.assertRaises(TypeError):
                    CapabilityStatus(Capability.READ, available)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            CapabilityStatus(Capability.READ, True, unknown=True)  # type: ignore[call-arg]

    def test_registry_rejects_non_tuple_incomplete_duplicate_and_contradictory_statuses(self) -> None:
        complete = tuple(CapabilityStatus(capability, True) for capability in Capability)
        with self.assertRaises(TypeError):
            CapabilityRegistry(list(complete))  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            CapabilityRegistry((object(),))  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            CapabilityRegistry(complete[:-1])
        with self.assertRaises(ValueError):
            CapabilityRegistry(complete + (complete[0],))
        contradictory = complete + (CapabilityStatus(Capability.READ, False),)
        with self.assertRaises(ValueError):
            CapabilityRegistry(contradictory)
        with self.assertRaises(TypeError):
            CapabilityRegistry(complete, unknown=True)  # type: ignore[call-arg]

    def test_public_functions_reject_command_registry_strings_and_spoofs(self) -> None:
        class SpoofCommand(Enum):
            READ = "read"

        registry = self._registry()
        for command in ("read", Command, SpoofCommand.READ, True, 1):
            with self.subTest(command=command):
                with self.assertRaises(TypeError):
                    required_capabilities(command)  # type: ignore[arg-type]
                with self.assertRaises(TypeError):
                    require_capabilities(command, registry)  # type: ignore[arg-type]
        for spoof in (None, (), True, CapabilityRegistry):
            with self.subTest(registry=spoof):
                with self.assertRaises(TypeError):
                    require_capabilities(Command.READ, spoof)  # type: ignore[arg-type]

    def test_error_orders_multiple_missing_capabilities_by_command_map(self) -> None:
        registry = self._registry(Capability.READ, Capability.POST)
        with self.assertRaises(CapabilityUnavailableError) as raised:
            require_capabilities(Command.MESSAGE_SEND, registry)
        self.assertEqual(
            raised.exception.missing,
            (Capability.READ,),
        )
        self.assertEqual(
            raised.exception.error_code,
            "capability_read_unavailable",
        )
        self.assertNotIn("read", str(raised.exception))
        self.assertNotIn("post", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
