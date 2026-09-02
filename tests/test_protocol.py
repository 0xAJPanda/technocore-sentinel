"""Executable specifications for strict, bounded JSON decoding."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
import sys
import unittest

import technocore_sentinel.protocol as protocol
from technocore_sentinel.protocol import ProtocolDecodeError, decode_strict_json


class StrictJsonTests(unittest.TestCase):
    def test_rejects_duplicate_keys_trailing_data_and_nonfinite(self) -> None:
        hostile_documents = (
            b'{"secret-marker": 1, "secret-marker": 2}',
            b'{"outer": {"secret-marker": 1, "secret-marker": 2}}',
            b'{"a": 1, "\\u0061": 2}',
            b'{} []',
            b'{} trailing-secret-marker',
            b'NaN',
            b'Infinity',
            b'-Infinity',
            b'[0, {"value": NaN}]',
        )

        for document in hostile_documents:
            with self.subTest(document=document):
                with self.assertRaises(ProtocolDecodeError) as raised:
                    decode_strict_json(document)
                self.assertNotIn("secret-marker", str(raised.exception))

    def test_rejects_exponent_overflow_at_every_nesting_level(self) -> None:
        overflowing_documents = (
            b"1e309",
            b"-1e309",
            b"[1e9999]",
            b"[-1e9999]",
            b'{"value": 1e9999}',
            b'{"value": -1e9999}',
        )

        for document in overflowing_documents:
            with self.subTest(document=document):
                with self.assertRaises(ProtocolDecodeError) as raised:
                    decode_strict_json(document)
                self.assertEqual(
                    str(raised.exception),
                    "JSON document contains a non-finite number",
                )
                self.assertNotIn(document.decode("ascii"), str(raised.exception))

    def test_accepts_finite_float_extremes_and_underflow(self) -> None:
        self.assertEqual(decode_strict_json(b"1e308"), 1e308)
        self.assertEqual(decode_strict_json(b"-1e308"), -1e308)
        self.assertEqual(decode_strict_json(b"1e-9999"), 0.0)

    def test_rejects_65_digit_integer_and_lone_surrogates(self) -> None:
        sixty_four_digits = "9" * 64
        sixty_five_digits = "8" * 65

        accepted_integers = {
            sixty_four_digits.encode("ascii"): int(sixty_four_digits),
            f"-{sixty_four_digits}".encode("ascii"): -int(sixty_four_digits),
            f"[{sixty_four_digits}]".encode("ascii"): [int(sixty_four_digits)],
            f'{{"nested": -{sixty_four_digits}}}'.encode("ascii"): {
                "nested": -int(sixty_four_digits)
            },
        }
        for document, expected in accepted_integers.items():
            with self.subTest(accepted_integer=document):
                self.assertEqual(decode_strict_json(document), expected)

        for document in (
            sixty_five_digits.encode("ascii"),
            f"-{sixty_five_digits}".encode("ascii"),
            f"[{sixty_five_digits}]".encode("ascii"),
            f'{{"nested": {{"value": -{sixty_five_digits}}}}}'.encode("ascii"),
        ):
            with self.subTest(rejected_integer=document):
                with self.assertRaises(ProtocolDecodeError) as raised:
                    decode_strict_json(document)
                self.assertEqual(str(raised.exception), "JSON integer exceeds digit limit")
                self.assertNotIn(sixty_five_digits, str(raised.exception))

        for document in (
            b'"\\ud800"',
            b'"\\udfff"',
            b'["\\uD800"]',
            b'{"value": {"nested": "\\uDFFF"}}',
            b'{"\\ud800": "value"}',
            b'{"outer": {"\\uDFFF": [null]}}',
        ):
            with self.subTest(rejected_surrogate=document):
                with self.assertRaises(ProtocolDecodeError) as raised:
                    decode_strict_json(document)
                self.assertEqual(
                    str(raised.exception),
                    "JSON document contains a non-scalar Unicode value",
                )
                self.assertNotIn("d800", str(raised.exception).lower())
                self.assertNotIn("dfff", str(raised.exception).lower())

        self.assertEqual(decode_strict_json(b"0"), 0)
        self.assertEqual(decode_strict_json(b"-0"), 0)
        with self.assertRaises(ProtocolDecodeError) as raised:
            decode_strict_json(b"01")
        self.assertEqual(str(raised.exception), "invalid JSON document")

        emoji = "\U0001f600"
        self.assertEqual(decode_strict_json(f'"{emoji}"'.encode()), emoji)
        self.assertEqual(decode_strict_json(b'"\\ud83d\\ude00"'), emoji)
        self.assertEqual(
            decode_strict_json(b'{"\\ud83d\\ude00": ["\\u0000", "\\uffff"]}'),
            {emoji: ["\x00", "\uffff"]},
        )

        deeply_nested = (b"[" * 1_100) + b"0" + (b"]" * 1_100)
        nested_value = decode_strict_json(deeply_nested)
        nesting_depth = 0
        while isinstance(nested_value, list):
            self.assertEqual(len(nested_value), 1)
            nested_value = nested_value[0]
            nesting_depth += 1
        self.assertEqual((nesting_depth, nested_value), (1_100, 0))

    def test_decoder_keeps_its_finite_float_callback_from_input_spoofs(self) -> None:
        class SpoofedBytes(bytes):
            parse_float = staticmethod(float)

        original_callback = protocol._parse_finite_float
        protocol._parse_finite_float = float
        try:
            with self.assertRaises(ProtocolDecodeError) as raised:
                decode_strict_json(SpoofedBytes(b"1e309"))
        finally:
            protocol._parse_finite_float = original_callback

        self.assertEqual(
            str(raised.exception),
            "JSON document contains a non-finite number",
        )

    def test_shared_decoder_remains_thread_safe_with_finite_float_callback(self) -> None:
        documents = (b"1e308", b"-1e308", b"1e-9999", b"1e309", b"-1e9999") * 20

        def decode(document: bytes) -> tuple[str, object]:
            try:
                return ("value", decode_strict_json(document))
            except ProtocolDecodeError as error:
                return ("error", str(error))

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(decode, documents))

        expected = (
            ("value", 1e308),
            ("value", -1e308),
            ("value", 0.0),
            ("error", "JSON document contains a non-finite number"),
            ("error", "JSON document contains a non-finite number"),
        ) * 20
        self.assertEqual(results, list(expected))

    def test_allows_json_whitespace_and_returns_values_without_schema_assumptions(self) -> None:
        values = {
            b' \t\r\n {"nested": [true, false, null, 1, 1.5, "text"]} \n': {
                "nested": [True, False, None, 1, 1.5, "text"]
            },
            b' [1, 2, 3] ': [1, 2, 3],
            b' "scalar" ': "scalar",
            b' 42 ': 42,
            b' true ': True,
            b' null ': None,
        }

        for document, expected in values.items():
            with self.subTest(document=document):
                self.assertEqual(decode_strict_json(document), expected)

    def test_accepts_defined_bytes_like_inputs(self) -> None:
        for document in (b'{"ok": true}', bytearray(b'{"ok": true}'), memoryview(b'{"ok": true}')):
            with self.subTest(input_type=type(document).__name__):
                self.assertEqual(decode_strict_json(document), {"ok": True})

        for invalid in ("{}", 1, None, [123]):
            with self.subTest(input_type=type(invalid).__name__):
                with self.assertRaises(TypeError):
                    decode_strict_json(invalid)  # type: ignore[arg-type]

    def test_enforces_byte_cap_before_decoding(self) -> None:
        self.assertEqual(decode_strict_json(b'"123456"', max_bytes=8), "123456")
        with self.assertRaises(ProtocolDecodeError) as raised:
            decode_strict_json(b'"123456" ', max_bytes=8)
        self.assertEqual(str(raised.exception), "JSON input exceeds byte limit")

    def test_byte_cap_uses_underlying_buffer_for_adversarial_subclasses(self) -> None:
        class LyingBytes(bytes):
            def __len__(self) -> int:
                return 1

            def decode(self, *_args: object, **_kwargs: object) -> str:
                return "null"

            def tobytes(self) -> bytes:
                return b"null"

        class LyingBytearray(bytearray):
            def __len__(self) -> int:
                return 1

            def decode(self, *_args: object, **_kwargs: object) -> str:
                return "null"

            def tobytes(self) -> bytes:
                return b"null"

        oversized = b"0" + (b" " * 202)
        self.assertEqual(bytes.__len__(LyingBytes(oversized)), 203)
        self.assertEqual(bytearray.__len__(LyingBytearray(oversized)), 203)

        for document in (LyingBytes(oversized), LyingBytearray(oversized)):
            with self.subTest(input_type=type(document).__name__):
                with self.assertRaises(ProtocolDecodeError) as raised:
                    decode_strict_json(document, max_bytes=1)
                self.assertEqual(str(raised.exception), "JSON input exceeds byte limit")

    def test_subclass_input_is_snapshotted_without_calling_overrides(self) -> None:
        class HostileBytes(bytes):
            def __len__(self) -> int:
                raise AssertionError("override must not be called")

            def decode(self, *_args: object, **_kwargs: object) -> str:
                raise AssertionError("override must not be called")

            def tobytes(self) -> bytes:
                raise AssertionError("override must not be called")

        class HostileBytearray(bytearray):
            def __len__(self) -> int:
                self.clear()
                raise AssertionError("override must not be called")

            def decode(self, *_args: object, **_kwargs: object) -> str:
                self.clear()
                raise AssertionError("override must not be called")

            def tobytes(self) -> bytes:
                self.clear()
                raise AssertionError("override must not be called")

        mutable = HostileBytearray(b'{"ok": true}')
        self.assertEqual(decode_strict_json(HostileBytes(b'{"ok": true}')), {"ok": True})
        self.assertEqual(decode_strict_json(mutable), {"ok": True})
        mutable.extend(b" ")
        self.assertEqual(bytearray.__len__(mutable), 13)

    def test_memoryview_slices_formats_and_released_views_are_handled_safely(self) -> None:
        contiguous = memoryview(b'xx{"ok": true}yy')[2:-2]
        non_contiguous = memoryview(b"n0u0l0l0")[::2]
        non_byte_format = memoryview(b"null").cast("H")

        self.assertEqual(decode_strict_json(contiguous), {"ok": True})
        self.assertIsNone(decode_strict_json(non_contiguous))
        self.assertIsNone(decode_strict_json(non_byte_format))

        released = memoryview(b"secret-marker")
        released.release()
        with self.assertRaises(ProtocolDecodeError) as raised:
            decode_strict_json(released)
        self.assertEqual(str(raised.exception), "invalid bytes-like input")
        self.assertNotIn("secret-marker", str(raised.exception))

    def test_releases_temporary_view_without_releasing_caller_view(self) -> None:
        source = bytearray(b"null")
        caller_view = memoryview(source)
        self.assertIsNone(decode_strict_json(caller_view))
        self.assertEqual(caller_view.tobytes(), b"null")
        caller_view.release()
        source.extend(b" ")
        self.assertEqual(source, b"null ")

    def test_rejects_invalid_max_bytes(self) -> None:
        for invalid in (True, False, 0, -1, 1.0, "1", None):
            with self.subTest(max_bytes=invalid):
                expected = ValueError if isinstance(invalid, int) and not isinstance(invalid, bool) else TypeError
                with self.assertRaises(expected):
                    decode_strict_json(b"null", max_bytes=invalid)  # type: ignore[arg-type]

    def test_empty_and_malformed_json_use_stable_non_echoing_error(self) -> None:
        for document in (b"", b"   ", b'{"secret-marker":', b"[secret-marker]"):
            with self.subTest(document=document):
                with self.assertRaises(ProtocolDecodeError) as raised:
                    decode_strict_json(document)
                self.assertEqual(str(raised.exception), "invalid JSON document")
                self.assertNotIn("secret-marker", str(raised.exception))


class RoomWindowTests(unittest.TestCase):
    @staticmethod
    def _valid_window() -> dict[str, object]:
        return {
            "room": "lobby",
            "count": 2,
            "first_seq": 7,
            "last_seq": 8,
            "messages": [
                {"seq": 7, "ts": "opaque-zulu", "from": "alice", "text": "first"},
                {
                    "seq": 8,
                    "ts": "not-a-date",
                    "from": "bob",
                    "text": "second",
                    "nonce": 123,
                },
            ],
        }

    def test_required_and_unknown_fields(self) -> None:
        for field in ("room", "count", "last_seq", "messages"):
            value = self._valid_window()
            del value[field]
            with self.subTest(missing_envelope=field):
                with self.assertRaisesRegex(
                    ProtocolDecodeError, "^room window has invalid fields$"
                ):
                    protocol.parse_room_window(value)

        value = self._valid_window()
        value["secret-marker"] = "must not be echoed"
        with self.assertRaises(ProtocolDecodeError) as raised:
            protocol.parse_room_window(value)
        self.assertEqual(str(raised.exception), "room window has invalid fields")
        self.assertNotIn("secret-marker", str(raised.exception))

        for field in ("seq", "ts", "from", "text"):
            value = self._valid_window()
            del value["messages"][0][field]  # type: ignore[index]
            with self.subTest(missing_message=field):
                with self.assertRaisesRegex(
                    ProtocolDecodeError, "^room message has invalid fields$"
                ):
                    protocol.parse_room_window(value)

        value = self._valid_window()
        value["messages"][0]["secret-marker"] = "must not be echoed"  # type: ignore[index]
        with self.assertRaises(ProtocolDecodeError) as raised:
            protocol.parse_room_window(value)
        self.assertEqual(str(raised.exception), "room message has invalid fields")
        self.assertNotIn("secret-marker", str(raised.exception))

    def test_optional_fields_valid_shapes_and_input_order(self) -> None:
        empty = protocol.parse_room_window(
            {"room": "lobby", "count": 0, "last_seq": 0, "messages": []}
        )
        self.assertEqual(
            empty,
            protocol.RoomWindow(
                room="lobby", count=0, last_seq=0, messages=(), first_seq=None
            ),
        )
        explicit_null = protocol.parse_room_window(
            {
                "room": "lobby",
                "count": 0,
                "first_seq": None,
                "last_seq": 0,
                "messages": [],
            }
        )
        self.assertIsNone(explicit_null.first_seq)

        parsed = protocol.parse_room_window(self._valid_window())
        self.assertEqual(parsed.first_seq, 7)
        self.assertIsInstance(parsed.messages, tuple)
        self.assertEqual([message.seq for message in parsed.messages], [7, 8])
        self.assertEqual(parsed.messages[0].ts, "opaque-zulu")
        self.assertEqual(parsed.messages[0].sender, "alice")
        self.assertIsNone(parsed.messages[0].nonce)
        self.assertEqual(parsed.messages[1].nonce, 123)

    def test_rejects_wrong_containers_and_basic_types(self) -> None:
        class DictSubclass(dict[str, object]):
            pass

        class ListSubclass(list[object]):
            pass

        class StrSubclass(str):
            pass

        class IntSubclass(int):
            pass

        for invalid in (None, [], (), "window", DictSubclass(self._valid_window())):
            with self.subTest(window_container=type(invalid).__name__):
                with self.assertRaisesRegex(
                    ProtocolDecodeError, "^room window must be an object$"
                ):
                    protocol.parse_room_window(invalid)

        for field, invalid_values in {
            "room": (None, 1, StrSubclass("lobby")),
            "count": (None, True, 1.0, IntSubclass(2)),
            "last_seq": (None, False, "8", IntSubclass(8)),
            "first_seq": (False, "7", 7.0, IntSubclass(7)),
        }.items():
            for invalid in invalid_values:
                value = self._valid_window()
                value[field] = invalid
                with self.subTest(field=field, value_type=type(invalid).__name__):
                    with self.assertRaisesRegex(
                        ProtocolDecodeError, "^room window field has invalid type$"
                    ):
                        protocol.parse_room_window(value)

        for invalid in (None, {}, (), ListSubclass()):
            value = self._valid_window()
            value["messages"] = invalid
            with self.subTest(messages_container=type(invalid).__name__):
                with self.assertRaisesRegex(
                    ProtocolDecodeError, "^room window messages must be an array$"
                ):
                    protocol.parse_room_window(value)

        for invalid in (None, [], (), "message", DictSubclass()):
            value = self._valid_window()
            value["messages"] = [invalid]
            with self.subTest(message_container=type(invalid).__name__):
                with self.assertRaisesRegex(
                    ProtocolDecodeError, "^room message must be an object$"
                ):
                    protocol.parse_room_window(value)

        for field, invalid_values in {
            "seq": (None, True, 1.0, IntSubclass(7)),
            "ts": (None, 1, StrSubclass("opaque")),
            "from": (None, 1, StrSubclass("alice")),
            "text": (None, 1, StrSubclass("hello")),
            "nonce": (None, False, "123", IntSubclass(123)),
        }.items():
            for invalid in invalid_values:
                value = self._valid_window()
                value["messages"][0][field] = invalid  # type: ignore[index]
                with self.subTest(message_field=field, value_type=type(invalid).__name__):
                    with self.assertRaisesRegex(
                        ProtocolDecodeError, "^room message field has invalid type$"
                    ):
                        protocol.parse_room_window(value)

    def test_models_are_deeply_immutable_and_snapshot_input(self) -> None:
        source = self._valid_window()
        parsed = protocol.parse_room_window(source)

        with self.assertRaises(FrozenInstanceError):
            parsed.count = 99  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            parsed.messages[0].text = "changed"  # type: ignore[misc]
        self.assertFalse(hasattr(parsed, "__dict__"))
        self.assertFalse(hasattr(parsed.messages[0], "__dict__"))

        source["room"] = "changed"
        source["messages"][0]["text"] = "changed"  # type: ignore[index]
        source["messages"].clear()  # type: ignore[union-attr]
        self.assertEqual(parsed.room, "lobby")
        self.assertEqual(parsed.messages[0].text, "first")
        self.assertEqual(len(parsed.messages), 2)

    def test_request_room_limit_and_since_binding(self) -> None:
        def parse(
            value: object,
            *,
            requested_room: object = "lobby",
            requested_limit: object = 2,
            since: object = None,
        ) -> protocol.RoomWindow:
            return protocol.parse_room_window_for_request(
                value,
                requested_room=requested_room,  # type: ignore[arg-type]
                requested_limit=requested_limit,  # type: ignore[arg-type]
                since=since,  # type: ignore[arg-type]
            )

        class StrSubclass(str):
            pass

        class IntSubclass(int):
            pass

        # Request arguments are rejected before hostile remote data is inspected.
        for argument, invalid_values in {
            "requested_room": (None, 1, "", StrSubclass("lobby")),
            "requested_limit": (None, True, False, 0, -1, 201, 1.0, IntSubclass(2)),
            "since": (True, False, -1, 1.0, "1", IntSubclass(1), 10**64),
        }.items():
            for invalid in invalid_values:
                kwargs = {
                    "requested_room": "lobby",
                    "requested_limit": 2,
                    "since": None,
                }
                kwargs[argument] = invalid
                if argument == "requested_room":
                    has_valid_type = type(invalid) is str
                elif argument == "requested_limit":
                    has_valid_type = type(invalid) is int
                else:
                    has_valid_type = type(invalid) in {int, type(None)}
                expected = ValueError if has_valid_type else TypeError
                with self.subTest(request_argument=argument, invalid=invalid):
                    with self.assertRaises(expected):
                        parse("hostile remote data", **kwargs)

        sixty_four_digit_since = protocol.MAX_REQUEST_SEQUENCE
        empty = {"room": "lobby", "count": 0, "last_seq": 0, "messages": []}
        self.assertEqual(
            parse(
                empty,
                requested_limit=1,
                since=sixty_four_digit_since,
            ).messages,
            (),
        )

        int_max_str_digits = sys.get_int_max_str_digits()
        for invalid_since in (
            protocol.MAX_REQUEST_SEQUENCE + 1,
            10**5000,
            -(10**5000),
        ):
            with self.subTest(rejected_since_bound=invalid_since.bit_length()):
                with self.assertRaises(ValueError) as raised:
                    parse("hostile remote data", since=invalid_since)
                self.assertEqual(
                    str(raised.exception),
                    "since must be non-negative and at most 64 digits",
                )
        self.assertEqual(sys.get_int_max_str_digits(), int_max_str_digits)

        # Room matching is exact and case-sensitive, and mismatch errors do not echo it.
        for response_room in ("other-room-secret-marker", "Lobby"):
            value = self._valid_window()
            value["room"] = response_room
            with self.subTest(response_room=response_room):
                with self.assertRaises(ProtocolDecodeError) as raised:
                    parse(value)
                self.assertEqual(
                    str(raised.exception), "room window does not match requested room"
                )
                self.assertNotIn(response_room, str(raised.exception))

        # Count is bounded by the request, including both accepted boundaries.
        for count in (-1, 3):
            value = self._valid_window()
            value["count"] = count
            with self.subTest(rejected_count=count):
                with self.assertRaisesRegex(
                    ProtocolDecodeError,
                    "^room window count is outside requested limit$",
                ):
                    parse(value)
        for count in (0, 2):
            value = self._valid_window()
            value["count"] = count
            with self.subTest(accepted_count=count):
                self.assertEqual(parse(value).count, count)

        # Every message must be strictly newer than since, regardless of position.
        for sequences in ((9, 11), (11, 10), (11, 9)):
            value = self._valid_window()
            for message, sequence in zip(value["messages"], sequences):  # type: ignore[union-attr]
                message["seq"] = sequence
            with self.subTest(rejected_sequences=sequences):
                with self.assertRaisesRegex(
                    ProtocolDecodeError,
                    "^room window contains non-incremental message$",
                ):
                    parse(value, since=10)

        for sequences in ((11, 12),):
            value = self._valid_window()
            for message, sequence in zip(value["messages"], sequences):  # type: ignore[union-attr]
                message["seq"] = sequence
            value["first_seq"] = sequences[0]
            value["last_seq"] = sequences[-1]
            with self.subTest(accepted_sequences=sequences):
                parsed = parse(value, since=10)
                self.assertEqual(
                    tuple(message.seq for message in parsed.messages), sequences
                )

        # Count equality remains deferred even after sequence semantics are bound.
        deferred = self._valid_window()
        deferred["count"] = 1  # Deliberately differs from len(messages).
        deferred["first_seq"] = 11
        deferred["last_seq"] = 12
        deferred["messages"][0]["seq"] = 11  # type: ignore[index]
        deferred["messages"][1]["seq"] = 12  # type: ignore[index]
        source_snapshot = repr(deferred)
        parsed = parse(deferred, requested_limit=2, since=10)
        self.assertEqual(parsed.count, 1)
        self.assertEqual(tuple(message.seq for message in parsed.messages), (11, 12))
        self.assertEqual((parsed.first_seq, parsed.last_seq), (11, 12))
        self.assertFalse(parsed.leading_gap)
        self.assertEqual(repr(deferred), source_snapshot)

    def test_first_last_contiguity_and_visible_leading_gap(self) -> None:
        def parse(
            value: object, *, since: int | None = None, requested_limit: int = 4
        ) -> protocol.RoomWindow:
            return protocol.parse_room_window_for_request(
                value,
                requested_room="lobby",
                requested_limit=requested_limit,
                since=since,
            )

        shape_only = protocol.parse_room_window(self._valid_window())
        self.assertIsNone(shape_only.leading_gap)

        valid = self._valid_window()
        initial_gap = parse(valid)
        self.assertTrue(initial_gap.leading_gap)
        self.assertEqual(tuple(message.seq for message in initial_gap.messages), (7, 8))
        self.assertEqual((initial_gap.first_seq, initial_gap.last_seq), (7, 8))

        incremental = self._valid_window()
        incremental["messages"][0]["seq"] = 11  # type: ignore[index]
        incremental["messages"][1]["seq"] = 12  # type: ignore[index]
        incremental["first_seq"] = 11
        incremental["last_seq"] = 12
        no_gap = parse(incremental, since=10)
        self.assertFalse(no_gap.leading_gap)
        incremental_gap = parse(incremental, since=9)
        self.assertTrue(incremental_gap.leading_gap)

        one = self._valid_window()
        one["count"] = 1
        one["first_seq"] = None
        one["last_seq"] = 1
        one["messages"] = [one["messages"][0]]  # type: ignore[index]
        one["messages"][0]["seq"] = 1  # type: ignore[index]
        parsed_one = parse(one)
        self.assertFalse(parsed_one.leading_gap)
        self.assertIsNone(parsed_one.first_seq)

        first_absent = dict(one)
        del first_absent["first_seq"]
        self.assertFalse(parse(first_absent).leading_gap)

        empty = parse(
            {"room": "lobby", "count": 0, "last_seq": 999, "messages": []},
            since=20,
        )
        self.assertFalse(empty.leading_gap)
        self.assertEqual(empty.messages, ())

        mismatch_count = self._valid_window()
        mismatch_count["count"] = 1
        self.assertEqual(parse(mismatch_count).count, 1)

        invalid_cases = (
            ("wrong-first", {"first_seq": 6}, "room window first sequence does not match messages"),
            ("wrong-last", {"last_seq": 9}, "room window last sequence does not match messages"),
        )
        for label, changes, error in invalid_cases:
            value = self._valid_window()
            value.update(changes)
            with self.subTest(case=label):
                with self.assertRaisesRegex(ProtocolDecodeError, f"^{error}$"):
                    parse(value)

        for label, sequences in (
            ("duplicate", (7, 7)),
            ("descending", (8, 7)),
            ("skipped", (7, 9)),
        ):
            value = self._valid_window()
            for message, sequence in zip(value["messages"], sequences):  # type: ignore[union-attr]
                message["seq"] = sequence
            value["first_seq"] = sequences[0]
            value["last_seq"] = sequences[-1]
            with self.subTest(case=label):
                with self.assertRaisesRegex(
                    ProtocolDecodeError, "^room window messages are not contiguous$"
                ):
                    parse(value)

        for sequence in (0, -1):
            value = self._valid_window()
            value["count"] = 1
            value["first_seq"] = sequence
            value["last_seq"] = sequence
            value["messages"] = [value["messages"][0]]  # type: ignore[index]
            value["messages"][0]["seq"] = sequence  # type: ignore[index]
            with self.subTest(nonpositive=sequence):
                with self.assertRaisesRegex(
                    ProtocolDecodeError,
                    "^room window contains nonpositive message sequence$",
                ):
                    parse(value)

        source = self._valid_window()
        bound = parse(source)
        with self.assertRaises(FrozenInstanceError):
            bound.leading_gap = False  # type: ignore[misc]
        self.assertEqual(source, self._valid_window())

        wire_metadata = self._valid_window()
        wire_metadata["leading_gap"] = True
        with self.assertRaisesRegex(
            ProtocolDecodeError, "^room window has invalid fields$"
        ):
            protocol.parse_room_window(wire_metadata)

    def test_defers_semantic_validation_to_later_microtasks(self) -> None:
        parsed = protocol.parse_room_window(
            {
                "room": "NOT YET GRAMMAR CHECKED",
                "count": -20,
                "first_seq": -10,
                "last_seq": -30,
                "messages": [
                    {"seq": -10, "ts": "", "from": "", "text": "", "nonce": -1},
                    {"seq": -99, "ts": "later?", "from": "", "text": ""},
                ],
            }
        )
        self.assertEqual(parsed.count, -20)
        self.assertEqual([message.seq for message in parsed.messages], [-10, -99])


if __name__ == "__main__":
    unittest.main()
