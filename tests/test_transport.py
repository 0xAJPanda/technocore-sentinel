"""Executable specifications for the closed strict request builder."""

from __future__ import annotations

import inspect
import io
import multiprocessing
import os
import struct
import threading
import time
import unittest
import urllib.request
from dataclasses import FrozenInstanceError
from email.message import Message
from http.client import HTTPMessage
from typing import Any
from unittest import mock
from urllib.parse import parse_qsl, urlsplit


class TransportTests(unittest.TestCase):
    def test_validated_room_response_attests_to_the_exact_request(self) -> None:
        from technocore_sentinel.transport import (
            InvalidResponseAttestationError,
            ResponseTooLargeError,
            Route,
            UnsupportedContentEncodingError,
            UnsupportedResponseMediaError,
            ValidatedRoomResponse,
            WorkerRequest,
            _has_validated_room_response_proof,
            build_request,
            validate_room_response,
        )

        request = WorkerRequest(Route.ROOM_READ, "lobby", 2, 6, 4)
        expected_url = build_request(
            request.route,
            room=request.room,
            limit=request.limit,
            since=request.since,
            wait=request.wait,
        ).full_url

        def headers(*, media: str = "application/json", encoding: str | None = None) -> HTTPMessage:
            value = HTTPMessage()
            value["Content-Type"] = media
            if encoding is not None:
                value["Content-Encoding"] = encoding
            return value

        class TrackingReader(io.BytesIO):
            def __init__(self, body: bytes) -> None:
                super().__init__(body)
                self.read_sizes: list[int | None] = []
                self.close_calls = 0

            def read(self, size: int | None = -1) -> bytes:
                self.read_sizes.append(size)
                return super().read(size)

            def close(self) -> None:
                self.close_calls += 1
                super().close()

        reader = TrackingReader(b"{}")
        result = validate_room_response(
            request,
            final_url=expected_url,
            status=200,
            headers=headers(),
            response=reader,
        )
        self.assertIs(type(result), ValidatedRoomResponse)
        self.assertIs(result.route, Route.ROOM_READ)
        self.assertEqual(result.method, "GET")
        self.assertIs(type(result.method), str)
        self.assertEqual(result.url, expected_url)
        self.assertIs(type(result.url), str)
        self.assertIs(type(result.status), int)
        self.assertEqual(result.status, 200)
        self.assertIs(type(result.body), bytes)
        self.assertEqual(result.body, b"{}")
        self.assertEqual(reader.read_sizes, [1_048_577])
        self.assertEqual(reader.close_calls, 0)
        self.assertTrue(_has_validated_room_response_proof(result))
        proof = result._proof
        self.assertIs(type(proof), tuple)
        self.assertEqual(len(proof), 2)
        self.assertIs(type(proof[1]), bytes)
        self.assertEqual(len(proof[1]), 32)

        semantic_copy = object.__new__(ValidatedRoomResponse)
        for name in ("route", "method", "url", "status", "body", "_proof"):
            object.__setattr__(semantic_copy, name, getattr(result, name))
        self.assertTrue(_has_validated_room_response_proof(semantic_copy))

        for field, replacement in (
            ("route", "room-read"),
            ("method", "POST"),
            ("url", expected_url + "&changed=1"),
            ("status", 201),
            ("body", b'{"changed":true}'),
        ):
            changed = object.__new__(ValidatedRoomResponse)
            for name in ("route", "method", "url", "status", "body", "_proof"):
                object.__setattr__(changed, name, getattr(result, name))
            object.__setattr__(changed, field, replacement)
            with self.subTest(changed_proof_field=field):
                self.assertFalse(_has_validated_room_response_proof(changed))

        changed_proof = object.__new__(ValidatedRoomResponse)
        for name in ("route", "method", "url", "status", "body", "_proof"):
            object.__setattr__(changed_proof, name, getattr(result, name))
        object.__setattr__(changed_proof, "_proof", (proof[0], b"x" * 32))
        self.assertFalse(_has_validated_room_response_proof(changed_proof))
        with self.assertRaises(FrozenInstanceError):
            result.status = 201  # type: ignore[misc]
        with self.assertRaises(TypeError):
            ValidatedRoomResponse(Route.ROOM_READ, "GET", expected_url, 200, b"{}")
        with self.assertRaises(TypeError):
            ValidatedRoomResponse(
                Route.ROOM_READ,
                "GET",
                expected_url,
                200,
                b"{}",
                _proof=object(),
            )

        class FinalURL(str):
            pass

        class Status(int):
            pass

        for final_url, status in (
            (expected_url + "&redirected=1", 200),
            (FinalURL(expected_url), 200),
            (expected_url, 204),
            (expected_url, True),
            (expected_url, Status(200)),
        ):
            rejected = TrackingReader(b"body-secret")
            with self.subTest(final_url=final_url, status=status), self.assertRaises(
                InvalidResponseAttestationError
            ) as raised:
                validate_room_response(
                    request,
                    final_url=final_url,
                    status=status,
                    headers=headers(),
                    response=rejected,
                )
            self.assertEqual(raised.exception.args, ("invalid response attestation",))
            self.assertEqual(rejected.read_sizes, [])

        for bad_headers, error_type in (
            (headers(media="text/plain"), UnsupportedResponseMediaError),
            (headers(encoding="gzip"), UnsupportedContentEncodingError),
        ):
            rejected = TrackingReader(b"body-secret")
            with self.subTest(error=error_type.__name__), self.assertRaises(error_type):
                validate_room_response(
                    request,
                    final_url=expected_url,
                    status=200,
                    headers=bad_headers,
                    response=rejected,
                )
            self.assertEqual(rejected.read_sizes, [])
            self.assertEqual(rejected.close_calls, 0)

        signature_parameters = inspect.signature(validate_room_response).parameters
        self.assertEqual(
            tuple(signature_parameters),
            ("request", "final_url", "status", "headers", "response"),
        )
        self.assertNotIn("max_bytes", signature_parameters)
        self.assertNotIn("limit", signature_parameters)

        exact_cap = TrackingReader(b"x" * 1_048_576)
        exact_result = validate_room_response(
            request,
            final_url=expected_url,
            status=200,
            headers=headers(),
            response=exact_cap,
        )
        self.assertEqual(len(exact_result.body), 1_048_576)
        self.assertEqual(exact_cap.read_sizes, [1_048_577])
        self.assertEqual(exact_cap.close_calls, 0)

        oversized = TrackingReader(b"x" * 1_048_577)
        with (
            mock.patch(
                "technocore_sentinel.transport.ValidatedRoomResponse"
            ) as attestation_factory,
            self.assertRaises(ResponseTooLargeError),
        ):
            validate_room_response(
                request,
                final_url=expected_url,
                status=200,
                headers=headers(),
                response=oversized,
            )
        attestation_factory.assert_not_called()
        self.assertEqual(oversized.read_sizes, [1_048_577])
        self.assertEqual(oversized.close_calls, 0)

    def test_validated_room_response_proof_rejects_bounded_malformed_fields(self) -> None:
        from technocore_sentinel.transport import (
            ROOM_RESPONSE_MAX_BYTES,
            Route,
            ValidatedRoomResponse,
            WorkerRequest,
            _has_validated_room_response_proof,
            build_request,
            validate_room_response,
        )

        request = WorkerRequest(Route.ROOM_READ, "lobby", 2)
        expected_url = build_request(
            request.route, room=request.room, limit=request.limit
        ).full_url
        headers = HTTPMessage()
        headers["Content-Type"] = "application/json"
        authentic = validate_room_response(
            request,
            final_url=expected_url,
            status=200,
            headers=headers,
            response=io.BytesIO(b'{"secret":"attestation-body"}'),
        )

        class MethodSubclass(str):
            pass

        class URLSubclass(str):
            pass

        class StatusSubclass(int):
            pass

        class BodySubclass(bytes):
            pass

        malformed_fields = (
            ("route", "room-read"),
            ("route", object()),
            ("method", "M" * 8_193),
            ("method", "\ud800"),
            ("method", MethodSubclass("GET")),
            ("url", "u" * 8_193),
            ("url", "https://technocore.chat/\ud800"),
            ("url", URLSubclass(expected_url)),
            ("status", 10**5_000),
            ("status", -(10**5_000)),
            ("status", True),
            ("status", StatusSubclass(200)),
            ("status", 99),
            ("status", 600),
            ("body", b"x" * (ROOM_RESPONSE_MAX_BYTES + 1)),
            ("body", BodySubclass(authentic.body)),
        )
        for field, replacement in malformed_fields:
            mutated = object.__new__(ValidatedRoomResponse)
            for name in ("route", "method", "url", "status", "body", "_proof"):
                object.__setattr__(mutated, name, getattr(authentic, name))
            object.__setattr__(mutated, field, replacement)
            with self.subTest(field=field, replacement_type=type(replacement).__name__):
                self.assertFalse(_has_validated_room_response_proof(mutated))

    def test_decoded_body_cap_is_one_mib(self) -> None:
        from technocore_sentinel.transport import (
            InvalidResponseBodyError,
            ResponseTooLargeError,
            TransportError,
            read_bounded_body,
        )

        self.assertTrue(issubclass(ResponseTooLargeError, TransportError))
        self.assertTrue(issubclass(InvalidResponseBodyError, TransportError))
        self.assertEqual(
            inspect.signature(read_bounded_body).parameters["max_bytes"].default,
            1_048_576,
        )

        class Reader:
            def __init__(self, result: object) -> None:
                self.result = result
                self.read_sizes: list[int] = []
                self.close_calls = 0

            def read(self, size: int) -> object:
                self.read_sizes.append(size)
                return self.result

            def close(self) -> None:
                self.close_calls += 1

        for size in (0, 1, 1_048_575, 1_048_576):
            with self.subTest(accepted_size=size):
                response = Reader(b"x" * size)
                result = read_bounded_body(response)
                self.assertIs(type(result), bytes)
                self.assertEqual(result, b"x" * size)
                self.assertEqual(response.read_sizes, [1_048_577])
                self.assertEqual(response.close_calls, 0)

        oversized = Reader(b"x" * 1_048_577)
        with self.assertRaises(ResponseTooLargeError) as raised:
            read_bounded_body(oversized)
        self.assertIs(type(raised.exception), ResponseTooLargeError)
        self.assertEqual(raised.exception.args, ("response body exceeds byte limit",))
        self.assertEqual(oversized.read_sizes, [1_048_577])
        self.assertEqual(oversized.close_calls, 0)

        # A size-bounded urllib/http-style read may return fewer bytes only at
        # EOF. The primitive therefore treats one short result as the complete
        # body rather than issuing another read with a second allocation budget.
        short = Reader(b"short")
        self.assertEqual(read_bounded_body(short, max_bytes=8), b"short")
        self.assertEqual(short.read_sizes, [9])

        class HostileBytes(bytes):
            def __len__(self) -> int:
                return 0

            def __bytes__(self) -> bytes:
                raise AssertionError("override must not be called")

        class HostileBytearray(bytearray):
            def __len__(self) -> int:
                self.clear()
                return 0

            def __bytes__(self) -> bytes:
                self.clear()
                raise AssertionError("override must not be called")

        for body in (
            HostileBytes(b"12345"),
            HostileBytearray(b"12345"),
            memoryview(b"xx12345yy")[2:-2],
            memoryview(b"1020304050")[::2],
        ):
            with self.subTest(bytes_like=type(body).__name__):
                response = Reader(body)
                self.assertEqual(read_bounded_body(response, max_bytes=5), b"12345")
                self.assertEqual(response.read_sizes, [6])

        lying = Reader(HostileBytes(b"secret-marker" + b"x" * 20))
        with self.assertRaises(ResponseTooLargeError) as raised:
            read_bounded_body(lying, max_bytes=4)
        self.assertEqual(str(raised.exception), "response body exceeds byte limit")
        self.assertNotIn("secret-marker", str(raised.exception))

        released = memoryview(b"released-secret-marker")
        released.release()
        invalid_values = (None, "body-secret-marker", [b"body"], object(), released)
        for value in invalid_values:
            with self.subTest(invalid_type=type(value).__name__):
                response = Reader(value)
                with self.assertRaises(InvalidResponseBodyError) as raised:
                    read_bounded_body(response, max_bytes=8)
                self.assertIs(type(raised.exception), InvalidResponseBodyError)
                self.assertEqual(raised.exception.args, ("invalid response body",))
                self.assertNotIn("secret-marker", str(raised.exception))
                self.assertEqual(response.read_sizes, [9])
                self.assertEqual(response.close_calls, 0)

        for invalid in (True, False, 0, -1, 1.0, "1", None):
            with self.subTest(invalid_max_bytes=invalid):
                expected = (
                    ValueError
                    if type(invalid) is int and invalid <= 0
                    else TypeError
                )
                response = Reader(b"")
                with self.assertRaises(expected):
                    read_bounded_body(response, max_bytes=invalid)  # type: ignore[arg-type]
                self.assertEqual(response.read_sizes, [])

        reader_error = RuntimeError("reader failure marker")
        failing = mock.Mock()
        failing.read.side_effect = reader_error
        with self.assertRaises(RuntimeError) as raised:
            read_bounded_body(failing, max_bytes=12)
        self.assertIs(raised.exception, reader_error)
        failing.read.assert_called_once_with(13)
        failing.close.assert_not_called()

    def test_raw_headers_are_validated_from_one_immutable_snapshot(self) -> None:
        import technocore_sentinel.transport as transport

        cases = (
            (
                "Content-Encoding",
                "identity",
                "gzip",
                transport.validate_content_encoding,
                transport.UnsupportedContentEncodingError,
            ),
            (
                "Content-Type",
                "application/json",
                "text/plain",
                lambda headers: transport.validate_response_media(
                    transport.Route.ROOM_READ, headers
                ),
                transport.UnsupportedResponseMediaError,
            ),
        )

        for name, safe_value, unsafe_value, validate, error_type in cases:
            with self.subTest(header=name, phase="controlled-post-snapshot-mutation"):
                raw_headers = [(name, safe_value), (name, unsafe_value)]
                snapshot = tuple(raw_headers)
                raw_headers[:] = [(name, safe_value)]

                self.assertIs(type(snapshot), tuple)
                self.assertEqual(
                    transport._raw_header_values_from_snapshot(
                        snapshot, name.lower()
                    ),
                    (safe_value, unsafe_value),
                )

            with self.subTest(header=name, phase="concurrent-stress"):
                headers = Message()
                raw_headers = [(name, safe_value), (name, unsafe_value)]
                vars(headers)["_headers"] = raw_headers
                mutate = threading.Event()
                mutated = threading.Event()
                stop = threading.Event()

                def mutate_after_snapshot() -> None:
                    while True:
                        mutate.wait()
                        mutate.clear()
                        if stop.is_set():
                            return
                        if len(raw_headers) == 1:
                            raw_headers.append((name, unsafe_value))
                        else:
                            raw_headers.pop()
                        mutated.set()

                mutator = threading.Thread(target=mutate_after_snapshot)
                mutator.start()
                snapshots: list[tuple[object, ...]] = []
                original_parser = transport._raw_header_values_from_snapshot

                def parse_after_concurrent_mutation(
                    snapshot: tuple[object, ...], target: str
                ) -> tuple[str, ...]:
                    self.assertIs(type(snapshot), tuple)
                    snapshots.append(snapshot)
                    mutated.clear()
                    mutate.set()
                    self.assertTrue(mutated.wait(timeout=2))
                    return original_parser(snapshot, target)

                outcomes: list[tuple[tuple[object, ...], bool]] = []
                try:
                    with mock.patch.object(
                        transport,
                        "_raw_header_values_from_snapshot",
                        side_effect=parse_after_concurrent_mutation,
                    ):
                        for _ in range(200):
                            before = len(snapshots)
                            try:
                                validate(headers)
                            except error_type:
                                accepted = False
                            else:
                                accepted = True
                            self.assertEqual(len(snapshots), before + 1)
                            outcomes.append((snapshots[-1], accepted))
                finally:
                    stop.set()
                    mutate.set()
                    mutator.join(timeout=2)

                self.assertFalse(mutator.is_alive())
                safe_snapshot = ((name, safe_value),)
                duplicate_snapshot = (
                    (name, safe_value),
                    (name, unsafe_value),
                )
                self.assertIn((safe_snapshot, True), outcomes)
                self.assertIn((duplicate_snapshot, False), outcomes)
                self.assertTrue(
                    all(
                        (snapshot == safe_snapshot and accepted)
                        or (snapshot == duplicate_snapshot and not accepted)
                        for snapshot, accepted in outcomes
                    )
                )

    def test_non_identity_content_encoding_is_refused(self) -> None:
        from technocore_sentinel.transport import (
            TransportError,
            UnsupportedContentEncodingError,
            validate_content_encoding,
        )

        self.assertTrue(issubclass(UnsupportedContentEncodingError, TransportError))

        class TrackingBody(io.BytesIO):
            def __init__(self) -> None:
                super().__init__(b"encoded-body-secret")
                self.read_calls = 0

            def read(self, size: int | None = -1) -> bytes:
                self.read_calls += 1
                return super().read(size)

        def headers_with(*values: str) -> Message:
            headers = Message()
            for value in values:
                headers["cOnTeNt-EnCoDiNg"] = value
            return headers

        accepted = (
            Message(),
            HTTPMessage(),
            headers_with("identity"),
            headers_with("IDENTITY"),
            headers_with(" \tIdEnTiTy\t "),
        )
        self.assertEqual(len(accepted), 5)
        for headers in accepted:
            with self.subTest(accepted=headers.get_all("Content-Encoding")):
                validate_content_encoding(headers)

        for container_type in (Message, HTTPMessage):
            headers = container_type()
            vars(headers)["_headers"] = [("Content-Encoding", "identity")]
            with mock.patch.object(
                container_type,
                "get_all",
                side_effect=AssertionError("class get_all must not be called"),
            ) as class_get_all:
                validate_content_encoding(headers)
            class_get_all.assert_not_called()

        rejected_values = (
            "",
            " ",
            "gzip",
            "deflate",
            "br",
            "compress",
            "identity,gzip",
            "identity, gzip",
            "gzip,identity",
            "identity,identity",
            "identity;level=0",
            'identity; parameter="value"',
            "identity\x00",
            "identity\x1f",
            "identity\x7f",
            "identity\r\n gzip",
            "identity\n",
            "identitý",
            "x-identity",
        )
        for value in rejected_values:
            with self.subTest(rejected=value):
                body = TrackingBody()
                with self.assertRaises(UnsupportedContentEncodingError) as raised:
                    validate_content_encoding(headers_with(value))
                self.assertIs(type(raised.exception), UnsupportedContentEncodingError)
                self.assertEqual(
                    raised.exception.args,
                    ("unsupported response content encoding",),
                )
                self.assertEqual(body.read_calls, 0)
                self.assertEqual(body.getvalue(), b"encoded-body-secret")

        for values in (("identity", "identity"), ("identity", "gzip")):
            with self.subTest(duplicate=values):
                body = TrackingBody()
                with self.assertRaises(UnsupportedContentEncodingError):
                    validate_content_encoding(headers_with(*values))
                self.assertEqual(body.read_calls, 0)

        exact_shadow_calls = {"empty": 0, "message": 0, "http": 0}

        exact_empty = Message()

        def shadow_empty(name: str, failobj: object = None) -> list[str]:
            exact_shadow_calls["empty"] += 1
            return ["identity"]

        exact_empty.get_all = shadow_empty
        # Real header state is absent, so the shadow's synthetic identity is ignored.
        validate_content_encoding(exact_empty)

        exact_message = Message()
        exact_message["Content-Encoding"] = "identity"
        exact_message["Content-Encoding"] = "gzip"

        def shadow_message(name: str, failobj: object = None) -> list[str]:
            exact_shadow_calls["message"] += 1
            return ["identity"]

        exact_message.get_all = shadow_message

        exact_http = HTTPMessage()
        exact_http["Content-Encoding"] = "identity"
        exact_http["Content-Encoding"] = "gzip"

        def shadow_http(name: str, failobj: object = None) -> list[str]:
            exact_shadow_calls["http"] += 1
            raise AssertionError("instance get_all must not be called")

        exact_http.get_all = shadow_http

        for headers in (exact_message, exact_http):
            with self.subTest(exact_shadow=type(headers).__name__):
                with self.assertRaises(UnsupportedContentEncodingError):
                    validate_content_encoding(headers)

        self.assertEqual(exact_shadow_calls, {"empty": 0, "message": 0, "http": 0})

        class HostilePolicy:
            def __init__(self) -> None:
                self.calls = 0

            def header_fetch_parse(self, name: str, value: str) -> str:
                self.calls += 1
                return "identity"

        hostile_policy = HostilePolicy()
        policy_spoof = Message()
        vars(policy_spoof)["_headers"] = [("Content-Encoding", "gzip")]
        vars(policy_spoof)["policy"] = hostile_policy
        with self.assertRaises(UnsupportedContentEncodingError) as raised:
            validate_content_encoding(policy_spoof)
        self.assertEqual(
            raised.exception.args,
            ("unsupported response content encoding",),
        )
        self.assertEqual(hostile_policy.calls, 0)

        class HeaderList(list):
            pass

        class HeaderTuple(tuple):
            pass

        class HeaderValue(str):
            pass

        malformed_raw_states = (
            HeaderList([("Content-Encoding", "identity")]),
            (("Content-Encoding", "identity"),),
            [HeaderTuple(("Content-Encoding", "identity"))],
            [("Content-Encoding", HeaderValue("identity"))],
            [(HeaderValue("Content-Encoding"), "identity")],
            [("Content Encoding", "identity")],
            [("Content-Encoding:", "identity")],
            [("Cöntent-Encoding", "identity")],
            [("", "identity")],
        )
        for raw_state in malformed_raw_states:
            with self.subTest(raw_encoding_state=type(raw_state).__name__):
                headers = Message()
                vars(headers)["_headers"] = raw_state
                body = TrackingBody()
                with self.assertRaises(UnsupportedContentEncodingError) as raised:
                    validate_content_encoding(headers)
                self.assertEqual(
                    raised.exception.args,
                    ("unsupported response content encoding",),
                )
                self.assertEqual(body.read_calls, 0)

        class EmptySpoofMessage(Message):
            def __init__(self) -> None:
                super().__init__()
                self.get_all_calls = 0

            def get_all(self, name: str, failobj: object = None) -> list[str]:
                self.get_all_calls += 1
                return ["identity"]

        class DuplicateHidingMessage(Message):
            def __init__(self) -> None:
                super().__init__()
                self["Content-Encoding"] = "identity"
                self["Content-Encoding"] = "gzip"
                self.get_all_calls = 0

            def get_all(self, name: str, failobj: object = None) -> list[str]:
                self.get_all_calls += 1
                return ["identity"]

        class SpoofHTTPMessage(HTTPMessage):
            def __init__(self) -> None:
                super().__init__()
                self.get_all_calls = 0

            def get_all(self, name: str, failobj: object = None) -> list[str]:
                self.get_all_calls += 1
                return ["identity"]

        empty_spoof = EmptySpoofMessage()
        duplicate_hiding = DuplicateHidingMessage()
        http_spoof = SpoofHTTPMessage()
        self.assertIsNone(Message.get_all(empty_spoof, "Content-Encoding"))
        self.assertEqual(
            Message.get_all(duplicate_hiding, "Content-Encoding"),
            ["identity", "gzip"],
        )
        self.assertIsNone(Message.get_all(http_spoof, "Content-Encoding"))

        spoofing_headers = (
            empty_spoof,
            duplicate_hiding,
            http_spoof,
        )
        hostile_headers = (
            None,
            {},
            object(),
            (),
            "identity",
            *spoofing_headers,
        )
        self.assertEqual(len(rejected_values) + 2 + len(hostile_headers), 29)
        for headers in hostile_headers:
            with self.subTest(hostile=type(headers).__name__):
                body = TrackingBody()
                with self.assertRaises(UnsupportedContentEncodingError) as raised:
                    validate_content_encoding(headers)
                self.assertEqual(
                    str(raised.exception),
                    "unsupported response content encoding",
                )
                self.assertEqual(body.read_calls, 0)

        for headers in spoofing_headers:
            self.assertEqual(headers.get_all_calls, 0)

        self.assertEqual(
            tuple(inspect.signature(validate_content_encoding).parameters),
            ("headers",),
        )

    def test_response_media_is_endpoint_specific(self) -> None:
        from technocore_sentinel.transport import (
            Route,
            TransportError,
            UnsupportedContentEncodingError,
            UnsupportedResponseMediaError,
            validate_content_encoding,
            validate_response_media,
        )

        self.assertTrue(issubclass(UnsupportedResponseMediaError, TransportError))

        class TrackingBody(io.BytesIO):
            def __init__(self) -> None:
                super().__init__(b"response-body-secret")
                self.read_calls = 0

            def read(self, size: int | None = -1) -> bytes:
                self.read_calls += 1
                return super().read(size)

        def headers_with(*values: str, http: bool = False) -> Message | HTTPMessage:
            headers = HTTPMessage() if http else Message()
            for value in values:
                headers["cOnTeNt-TyPe"] = value
            return headers

        accepted = (
            headers_with("application/json"),
            headers_with("APPLICATION/JSON"),
            headers_with(" \tApPlIcAtIoN/JsOn\t "),
            headers_with("\tAPPLICATION/JSON \t", http=True),
        )
        self.assertEqual(len(accepted), 4)
        for headers in accepted:
            with self.subTest(accepted=Message.get_all(headers, "Content-Type")):
                body = TrackingBody()
                validate_response_media(Route.ROOM_READ, headers)
                self.assertEqual(body.read_calls, 0)
                self.assertEqual(body.getvalue(), b"response-body-secret")

        for container_type in (Message, HTTPMessage):
            headers = container_type()
            vars(headers)["_headers"] = [("Content-Type", "application/json")]
            with mock.patch.object(
                container_type,
                "get_all",
                side_effect=AssertionError("class get_all must not be called"),
            ) as class_get_all:
                validate_response_media(Route.ROOM_READ, headers)
            class_get_all.assert_not_called()

        rejected_values = (
            "",
            " ",
            "text/plain",
            "text/json",
            "application/problem+json",
            "application/vnd.technocore+json",
            "application/json, text/plain",
            "application/json,application/json",
            "application/json;",
            "application/json; charset",
            "application/json; charset=",
            "application/json;charset=utf-8",
            "application/json ; charset = UTF-8",
            "\tAPPLICATION/JSON\t;\tCHARSET\t=\tutf-8\t",
            'application/json; charset="utf-8"',
            'application/json;charset="utf-8"',
            "application/json; charset =utf-8",
            "application/json; charset= utf-8",
            "application/json; charset=us-ascii",
            "application/json; charset=utf8",
            "application/json; charset=utf-8; charset=utf-8",
            "application/json; charset=utf-8; boundary=x",
            "application/json; boundary=x",
            "application/json; profile=x",
            "application/json\x00",
            "application/json\x1f",
            "application/json\x7f",
            "application/json\r\n charset=utf-8",
            "application/json\n",
            "applicatiön/json",
        )
        self.assertEqual(len(rejected_values), 30)
        for value in rejected_values:
            with self.subTest(rejected=value):
                body = TrackingBody()
                with self.assertRaises(UnsupportedResponseMediaError) as raised:
                    validate_response_media(Route.ROOM_READ, headers_with(value))
                self.assertIs(type(raised.exception), UnsupportedResponseMediaError)
                self.assertEqual(
                    raised.exception.args,
                    ("unsupported response media type",),
                )
                self.assertEqual(body.read_calls, 0)
                self.assertEqual(body.getvalue(), b"response-body-secret")

        duplicate_fields = (
            (("application/json", "application/json"), False),
            (("application/json", "text/plain"), False),
            (("application/json", "application/json"), True),
        )
        for values, http in duplicate_fields:
            with self.subTest(duplicates=values, http=http):
                body = TrackingBody()
                with self.assertRaises(UnsupportedResponseMediaError):
                    validate_response_media(
                        Route.ROOM_READ,
                        headers_with(*values, http=http),
                    )
                self.assertEqual(body.read_calls, 0)

        class SpoofMessage(Message):
            def __init__(self) -> None:
                super().__init__()
                self.get_all_calls = 0

            def get_all(self, name: str, failobj: object = None) -> list[str]:
                self.get_all_calls += 1
                return ["application/json"]

        class SpoofHTTPMessage(HTTPMessage):
            def __init__(self) -> None:
                super().__init__()
                self.get_all_calls = 0

            def get_all(self, name: str, failobj: object = None) -> list[str]:
                self.get_all_calls += 1
                return ["application/json"]

        spoof_message = SpoofMessage()
        spoof_http = SpoofHTTPMessage()
        exact_shadow = headers_with("application/json")
        shadow_calls = 0

        def shadow_get_all(name: str, failobj: object = None) -> list[str]:
            nonlocal shadow_calls
            shadow_calls += 1
            return ["application/json"]

        exact_shadow.get_all = shadow_get_all
        hostile_headers = (
            Message(),
            HTTPMessage(),
            None,
            {},
            object(),
            (),
            "application/json",
            spoof_message,
            spoof_http,
        )
        for headers in hostile_headers:
            with self.subTest(hostile=type(headers).__name__):
                body = TrackingBody()
                with self.assertRaises(UnsupportedResponseMediaError) as raised:
                    validate_response_media(Route.ROOM_READ, headers)
                self.assertEqual(str(raised.exception), "unsupported response media type")
                self.assertEqual(body.read_calls, 0)

        self.assertEqual(spoof_message.get_all_calls, 0)
        self.assertEqual(spoof_http.get_all_calls, 0)
        validate_response_media(Route.ROOM_READ, exact_shadow)
        self.assertEqual(shadow_calls, 0)

        class HostilePolicy:
            def __init__(self) -> None:
                self.calls = 0

            def header_fetch_parse(self, name: str, value: str) -> str:
                self.calls += 1
                return "application/json"

        hostile_policy = HostilePolicy()
        policy_spoof = Message()
        vars(policy_spoof)["_headers"] = [("Content-Type", "text/plain")]
        vars(policy_spoof)["policy"] = hostile_policy
        with self.assertRaises(UnsupportedResponseMediaError) as raised:
            validate_response_media(Route.ROOM_READ, policy_spoof)
        self.assertEqual(raised.exception.args, ("unsupported response media type",))
        self.assertEqual(hostile_policy.calls, 0)

        class HeaderList(list):
            pass

        class HeaderTuple(tuple):
            pass

        class HeaderValue(str):
            pass

        malformed_raw_states = (
            HeaderList([("Content-Type", "application/json")]),
            (("Content-Type", "application/json"),),
            [HeaderTuple(("Content-Type", "application/json"))],
            [("Content-Type", HeaderValue("application/json"))],
            [(HeaderValue("Content-Type"), "application/json")],
            [("Content Type", "application/json")],
            [("Content-Type:", "application/json")],
            [("Cöntent-Type", "application/json")],
            [("", "application/json")],
            [("X-Bad\nName", "ignored"), ("Content-Type", "application/json")],
        )
        for raw_state in malformed_raw_states:
            with self.subTest(raw_media_state=type(raw_state).__name__):
                headers = Message()
                vars(headers)["_headers"] = raw_state
                body = TrackingBody()
                with self.assertRaises(UnsupportedResponseMediaError) as raised:
                    validate_response_media(Route.ROOM_READ, headers)
                self.assertEqual(raised.exception.args, ("unsupported response media type",))
                self.assertNotIn("ignored", str(raised.exception))
                self.assertEqual(body.read_calls, 0)

        for route in ("room-read", object(), None, mock.Mock(spec=Route)):
            with self.subTest(route=type(route).__name__):
                body = TrackingBody()
                with self.assertRaises(UnsupportedResponseMediaError):
                    validate_response_media(route, headers_with("application/json"))
                self.assertEqual(body.read_calls, 0)

        encoding_headers = headers_with("application/json")
        encoding_headers["Content-Encoding"] = "identity"
        validate_content_encoding(encoding_headers)
        with self.assertRaises(UnsupportedContentEncodingError):
            encoding_headers["Content-Encoding"] = "gzip"
            validate_content_encoding(encoding_headers)

        self.assertEqual(
            tuple(inspect.signature(validate_response_media).parameters),
            ("route", "headers"),
        )
        self.assertEqual(
            len(rejected_values)
            + len(duplicate_fields)
            + len(hostile_headers)
            + 4,
            46,
        )

    def test_redirect_is_refused(self) -> None:
        from technocore_sentinel.transport import (
            RedirectRefusalHandler,
            RedirectRefusedError,
            build_strict_opener,
        )

        with mock.patch(
            "urllib.request.getproxies",
            side_effect=AssertionError("system proxy discovery is forbidden"),
        ) as getproxies:
            opener = build_strict_opener()

        getproxies.assert_not_called()
        self.assertIsInstance(opener, urllib.request.OpenerDirector)
        self.assertEqual(
            tuple(type(handler) for handler in opener.handlers),
            (
                urllib.request.UnknownHandler,
                urllib.request.HTTPHandler,
                urllib.request.HTTPDefaultErrorHandler,
                urllib.request.FTPHandler,
                urllib.request.FileHandler,
                urllib.request.DataHandler,
                urllib.request.HTTPSHandler,
                RedirectRefusalHandler,
                urllib.request.HTTPErrorProcessor,
            ),
        )
        self.assertEqual(
            sum(isinstance(handler, RedirectRefusalHandler) for handler in opener.handlers),
            1,
        )
        self.assertFalse(
            any(type(handler) is urllib.request.HTTPRedirectHandler for handler in opener.handlers)
        )
        self.assertFalse(
            any(isinstance(handler, urllib.request.ProxyHandler) for handler in opener.handlers)
        )

        class TrackingBody(io.BytesIO):
            def __init__(self) -> None:
                super().__init__(b"response-body-secret")
                self.read_calls = 0
                self.close_calls = 0
                self.msg = "synthetic redirect"
                self.code = 0
                self.status = 0
                self.headers = Message()
                self.url = ""

            def read(self, size: int | None = -1) -> bytes:
                self.read_calls += 1
                return super().read(size)

            def close(self) -> None:
                self.close_calls += 1
                super().close()

            def info(self) -> Message:
                return self.headers

            def geturl(self) -> str:
                return self.url

        class CloseFailingBody(TrackingBody):
            def close(self) -> None:
                self.close_calls += 1
                raise RuntimeError("cleanup secret")

        class SyntheticRedirectHandler(urllib.request.BaseHandler):
            handler_order = 100

            def __init__(self, status: int, location: str, body: TrackingBody) -> None:
                self.status = status
                self.location = location
                self.body = body
                self.requests: list[urllib.request.Request] = []

            def https_open(
                self, request: urllib.request.Request
            ) -> TrackingBody:
                self.requests.append(request)
                headers = Message()
                headers["Location"] = self.location
                self.body.code = self.status
                self.body.status = self.status
                self.body.headers = headers
                self.body.url = request.full_url
                return self.body

        statuses = (301, 302, 303, 307, 308)
        locations = (
            "/alternate/path?location-secret=relative",
            "https://evil.example/alternate?location-secret=absolute",
            "//evil.example/alternate?location-secret=scheme-relative",
            "https://user:password@evil.example/alternate",
            "javascript:location-secret",
            "#location-secret-fragment",
            "::::location-secret-invalid::::",
            "",
        )
        methods_and_bodies = (
            ("GET", None),
            ("HEAD", None),
            ("POST", b"request-body-secret"),
            ("PUT", b"request-body-secret"),
            ("DELETE", b"request-body-secret"),
        )

        case = 0
        for status in statuses:
            for location in locations:
                method, data = methods_and_bodies[case % len(methods_and_bodies)]
                case += 1
                with self.subTest(status=status, location=location, method=method):
                    body = TrackingBody()
                    redirect = SyntheticRedirectHandler(status, location, body)
                    case_opener = build_strict_opener()
                    case_opener.add_handler(redirect)
                    request = urllib.request.Request(
                        "https://technocore.chat/r/request-secret?format=json&limit=1",
                        data=data,
                        headers={"Authorization": "Bearer credential-secret"},
                        method=method,
                    )

                    with (
                        mock.patch(
                            "socket.getaddrinfo",
                            side_effect=AssertionError("DNS is forbidden"),
                        ),
                        mock.patch(
                            "socket.create_connection",
                            side_effect=AssertionError("socket connection is forbidden"),
                        ),
                        mock.patch(
                            "socket.socket",
                            side_effect=AssertionError("socket construction is forbidden"),
                        ),
                        mock.patch(
                            "urllib.request.AbstractHTTPHandler.do_open",
                            side_effect=AssertionError("default HTTP handling is forbidden"),
                        ),
                    ):
                        with self.assertRaises(RedirectRefusedError) as raised:
                            case_opener.open(request)

                    self.assertEqual(raised.exception.args, ("redirect response refused",))
                    self.assertEqual(str(raised.exception), "redirect response refused")
                    self.assertEqual(len(redirect.requests), 1)
                    self.assertIs(redirect.requests[0], request)
                    self.assertEqual(body.read_calls, 0)
                    self.assertEqual(body.close_calls, 1)
                    self.assertTrue(body.closed)

        body = CloseFailingBody()
        redirect = SyntheticRedirectHandler(
            302,
            "https://evil.example/follow-target?location-secret=cleanup",
            body,
        )
        case_opener = build_strict_opener()
        case_opener.add_handler(redirect)
        request = urllib.request.Request("https://technocore.chat/r/request-secret")

        with self.assertRaises(RedirectRefusedError) as raised:
            case_opener.open(request)

        self.assertIs(type(raised.exception), RedirectRefusedError)
        self.assertEqual(raised.exception.args, ("redirect response refused",))
        self.assertEqual(str(raised.exception), "redirect response refused")
        self.assertEqual(len(redirect.requests), 1)
        self.assertIs(redirect.requests[0], request)
        self.assertEqual(body.read_calls, 0)
        self.assertEqual(body.close_calls, 1)

        direct_body = mock.Mock()
        with self.assertRaises(RedirectRefusedError) as direct_raised:
            RedirectRefusalHandler().redirect_request(
                request,
                direct_body,
                302,
                "Found",
                Message(),
                "https://evil.example/follow-target",
            )

        self.assertIs(type(direct_raised.exception), RedirectRefusedError)
        self.assertEqual(direct_raised.exception.args, ("redirect response refused",))
        direct_body.read.assert_not_called()
        direct_body.close.assert_not_called()

    def test_spawned_child_uses_bounded_private_ipc(self) -> None:
        import technocore_sentinel.transport as transport
        from technocore_sentinel.transport import (
            PreparedRequestResult,
            Route,
            WorkerRequest,
            build_request,
            prepare_request_in_spawned_worker,
        )

        request = WorkerRequest(
            route=Route.ROOM_READ,
            room="private-ipc-marker",
            limit=17,
            since=42,
            wait=3,
        )
        with self.assertRaises(FrozenInstanceError):
            request.room = "mutated"  # type: ignore[misc]

        before = {child.pid for child in multiprocessing.active_children()}
        result = prepare_request_in_spawned_worker(request)
        expected = build_request(
            Route.ROOM_READ,
            room="private-ipc-marker",
            limit=17,
            since=42,
            wait=3,
        )

        self.assertIs(type(result), PreparedRequestResult)
        self.assertEqual(
            (result.method, result.url, result.body_present),
            (expected.get_method(), expected.full_url, expected.data is not None),
        )
        self.assertNotEqual(result.worker_pid, os.getpid())
        self.assertEqual(result.start_method, "spawn")
        self.assertGreater(result.request_frame_bytes, 0)
        self.assertLessEqual(
            result.request_frame_bytes, transport.REQUEST_FRAME_MAX_BYTES
        )
        self.assertGreater(result.result_frame_bytes, 0)
        self.assertLessEqual(result.result_frame_bytes, transport.RESULT_FRAME_MAX_BYTES)
        self.assertNotIn(result.worker_pid, before)
        self.assertNotIn(
            result.worker_pid,
            {child.pid for child in multiprocessing.active_children()},
        )

        target_parameters = tuple(
            inspect.signature(transport._spawned_request_worker).parameters
        )
        self.assertEqual(
            target_parameters,
            ("request_receiver", "result_sender", "request_cap", "result_cap"),
        )
        target_source = inspect.getsource(transport._spawned_request_worker)
        self.assertNotIn("open(", target_source)
        self.assertNotIn("build_strict_opener", target_source)
        self.assertNotIn("urllib", target_source)

        # The fixed child target fails closed for malformed, unknown-field, and
        # oversized request frames. Its Process args remain only private handles
        # and numeric caps; request bytes are sent after spawn through send_bytes.
        context = multiprocessing.get_context("spawn")
        malformed_cases = (
            (b"not-json-private-ipc-marker", transport.RESULT_FRAME_MAX_BYTES),
            (
                b'{"v":1,"kind":"request","route":"room-read","request":{},"extra":1}',
                transport.RESULT_FRAME_MAX_BYTES,
            ),
            (
                b"x" * (transport.REQUEST_FRAME_MAX_BYTES + 1),
                transport.RESULT_FRAME_MAX_BYTES,
            ),
            # A valid request whose ordinary result cannot fit still produces
            # only the fixed bounded error category and exits cleanly.
            (transport._encode_worker_request(request), len(transport._ERROR_FRAME)),
        )
        for frame, result_cap in malformed_cases:
            with self.subTest(frame_size=len(frame), result_cap=result_cap):
                request_receiver, request_sender = context.Pipe(duplex=False)
                result_receiver, result_sender = context.Pipe(duplex=False)
                process = context.Process(
                    target=transport._spawned_request_worker,
                    args=(
                        request_receiver,
                        result_sender,
                        transport.REQUEST_FRAME_MAX_BYTES,
                        result_cap,
                    ),
                )
                self.assertEqual(
                    getattr(process, "_args"),
                    (
                        request_receiver,
                        result_sender,
                        transport.REQUEST_FRAME_MAX_BYTES,
                        result_cap,
                    ),
                )
                process.start()
                request_receiver.close()
                result_sender.close()
                try:
                    try:
                        request_sender.send_bytes(frame)
                    finally:
                        request_sender.close()
                    self.assertTrue(result_receiver.poll(5))
                    error_frame = result_receiver.recv_bytes(result_cap)
                    self.assertLessEqual(len(error_frame), result_cap)
                    self.assertEqual(
                        error_frame,
                        b'{"v":1,"kind":"error","error":"invalid-request"}',
                    )
                finally:
                    result_receiver.close()
                    process.join(5)
                    if process.is_alive():
                        process.kill()
                        process.join(5)
                self.assertFalse(process.is_alive())

    def test_result_frame_reader_is_bounded_nonblocking_and_deadline_aware(
        self,
    ) -> None:
        import technocore_sentinel.transport as transport

        context = multiprocessing.get_context("spawn")

        def read_from_writer(
            writer: Any, *, maximum: int, timeout: float = 1.0
        ) -> bytes:
            receiver, sender = context.Pipe(duplex=False)
            writer_errors: list[BaseException] = []

            def run_writer() -> None:
                try:
                    writer(sender)
                except BaseException as error:
                    writer_errors.append(error)

            thread = threading.Thread(target=run_writer, daemon=True)
            thread.start()
            try:
                try:
                    result = transport._read_bounded_connection_frame(
                        receiver,
                        maximum=maximum,
                        deadline=time.monotonic() + timeout,
                    )
                finally:
                    thread.join(2)
                    if thread.is_alive():
                        # The writer normally owns this endpoint exclusively.
                        # Main closes it only to unblock a stuck writer.
                        sender.close()
                        thread.join(2)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(writer_errors, [])
            finally:
                receiver.close()
            return result

        # Pin the private parser to the real POSIX Connection.send_bytes wire
        # format rather than duplicating only our expectation in the test. Repeat
        # each boundary to exercise clean endpoint ownership under thread races.
        for iteration in range(50):
            for payload in (
                b"",
                b"real-connection-frame",
                b"x" * transport.RESULT_FRAME_MAX_BYTES,
            ):
                with self.subTest(iteration=iteration, real_send_bytes=len(payload)):
                    def send_real(sender: object, frame: bytes = payload) -> None:
                        try:
                            sender.send_bytes(frame)  # type: ignore[attr-defined]
                        finally:
                            sender.close()  # type: ignore[attr-defined]

                    self.assertEqual(
                        read_from_writer(
                            send_real, maximum=transport.RESULT_FRAME_MAX_BYTES
                        ),
                        payload,
                    )

        payload = b"one-byte-at-a-time"
        wire_frame = struct.pack("!i", len(payload)) + payload

        def send_one_byte_at_a_time(sender: object) -> None:
            try:
                for byte in wire_frame:
                    os.write(sender.fileno(), bytes((byte,)))  # type: ignore[attr-defined]
            finally:
                sender.close()  # type: ignore[attr-defined]

        self.assertEqual(
            read_from_writer(send_one_byte_at_a_time, maximum=len(payload)), payload
        )

        invalid_wires = (
            struct.pack("!i", transport.RESULT_FRAME_MAX_BYTES + 1),
            struct.pack("!i", -2),
            struct.pack("!i", -1) + b"\0" * 4,
            struct.pack("!iQ", -1, transport.RESULT_FRAME_MAX_BYTES + 1),
            struct.pack("!iQ", -1, 1),
            struct.pack("!i", 5) + b"xx",
        )
        for wire in invalid_wires:
            with self.subTest(invalid_wire=wire[:12]):
                receiver, sender = context.Pipe(duplex=False)
                try:
                    try:
                        os.write(sender.fileno(), wire)
                    finally:
                        sender.close()
                    with self.assertRaises(transport._InvalidConnectionFrame):
                        transport._read_bounded_connection_frame(
                            receiver,
                            maximum=transport.RESULT_FRAME_MAX_BYTES,
                            deadline=time.monotonic() + 1.0,
                        )
                finally:
                    receiver.close()

        # Readiness after only a header and partial body must not turn into a
        # blocking recv_bytes call. Keeping the writer open pins that regression.
        receiver, sender = context.Pipe(duplex=False)
        try:
            os.write(sender.fileno(), struct.pack("!i", 100) + b"partial")
            started = time.monotonic()
            with self.assertRaises(transport._ConnectionFrameTimeout):
                transport._read_bounded_connection_frame(
                    receiver, maximum=100, deadline=started + 0.1
                )
            self.assertLessEqual(time.monotonic() - started, 0.5)
            self.assertTrue(os.get_blocking(receiver.fileno()))
        finally:
            receiver.close()
            sender.close()

    def test_partial_result_frame_uses_teardown_reserve_and_reaps_worker(self) -> None:
        import technocore_sentinel.transport as transport
        from technocore_sentinel.transport import (
            Route,
            SpawnedWorkerError,
            WorkerRequest,
            prepare_request_in_spawned_worker,
        )

        fork_context = multiprocessing.get_context("fork")
        trace: list[str] = []
        workers: list[object] = []

        def partial_worker(
            request_receiver: object,
            result_sender: object,
            request_cap: int,
            result_cap: int,
        ) -> None:
            request_receiver.recv_bytes(request_cap)  # type: ignore[attr-defined]
            os.write(
                result_sender.fileno(),  # type: ignore[attr-defined]
                struct.pack("!i", 100) + b"partial",
            )
            time.sleep(10)

        class RecordingProcess:
            def __init__(self, **kwargs: Any) -> None:
                self._process = fork_context.Process(**kwargs)
                self.pid: int | None = None
                workers.append(self)

            @property
            def exitcode(self) -> int | None:
                return self._process.exitcode

            def start(self) -> None:
                self._process.start()
                self.pid = self._process.pid

            def is_alive(self) -> bool:
                return self._process.is_alive()

            def join(self, timeout: float) -> None:
                self._process.join(timeout)

            def terminate(self) -> None:
                trace.append("terminate")
                self._process.terminate()

            def kill(self) -> None:
                trace.append("kill")
                self._process.kill()

            def close(self) -> None:
                trace.append("close")
                self._process.close()

        class RecordingContext:
            Pipe = staticmethod(fork_context.Pipe)
            Process = RecordingProcess

        started = time.monotonic()
        with (
            mock.patch.object(
                transport.multiprocessing,
                "get_context",
                return_value=RecordingContext(),
            ),
            mock.patch.object(transport, "_spawned_request_worker", partial_worker),
            self.assertRaises(SpawnedWorkerError) as raised,
        ):
            prepare_request_in_spawned_worker(
                WorkerRequest(Route.ROOM_READ, "partial-frame", 1), timeout=3.0
            )
        elapsed = time.monotonic() - started

        self.assertEqual(raised.exception.args, ("request worker did not complete",))
        self.assertLessEqual(elapsed, 3.0)
        self.assertIn("terminate", trace)
        self.assertIn("close", trace)
        self.assertEqual(len(workers), 1)
        worker_pid = workers[0].pid  # type: ignore[attr-defined]
        self.assertNotIn(
            worker_pid, {child.pid for child in multiprocessing.active_children()}
        )

    def test_deadline_reserves_teardown_and_leaves_no_child(self) -> None:
        import math

        import technocore_sentinel.transport as transport
        from technocore_sentinel.transport import (
            Route,
            SpawnedWorkerError,
            WorkerRequest,
            prepare_request_in_spawned_worker,
        )

        request = WorkerRequest(Route.ROOM_READ, "deadline-room", 1)
        expected_url = "https://technocore.chat/r/deadline-room?format=json&limit=1"

        class Clock:
            def __init__(self) -> None:
                self.now = 100.0

            def monotonic(self) -> float:
                return self.now

            def spend(self, seconds: float) -> None:
                self.now += seconds

        class Connection:
            def __init__(
                self,
                clock: Clock,
                events: list[tuple[str, float | None]],
                *,
                poll_result: bool = False,
                poll_delay: float | None = None,
                received: bytes | BaseException = b"",
            ) -> None:
                self.clock = clock
                self.events = events
                self.poll_result = poll_result
                self.poll_delay = poll_delay
                self.received = received
                self.close_calls = 0

            def send_bytes(self, frame: bytes) -> None:
                self.events.append(("send", float(len(frame))))

            def close(self) -> None:
                self.close_calls += 1

        class Process:
            def __init__(
                self,
                clock: Clock,
                events: list[tuple[str, float | None]],
                mode: str,
            ) -> None:
                self.clock = clock
                self.events = events
                self.mode = mode
                self.pid = 4242
                self.alive = True
                self.phase = "work"
                self.terminate_calls = 0
                self.kill_calls = 0
                self.close_calls = 0

            @property
            def exitcode(self) -> int | None:
                return None if self.alive else 0

            def start(self) -> None:
                self.events.append(("start", None))

            def is_alive(self) -> bool:
                return self.alive

            def join(self, timeout: float) -> None:
                self.events.append((f"join-{self.phase}", timeout))
                if self.phase == "work":
                    if self.mode == "success":
                        self.clock.spend(min(timeout, 0.1))
                        self.alive = False
                    else:
                        self.clock.spend(timeout)
                elif self.phase == "terminate":
                    duration = 0.25 if self.mode == "terminate-exits" else timeout
                    self.clock.spend(min(timeout, duration))
                    if self.mode == "terminate-exits" and timeout >= duration:
                        self.alive = False
                else:
                    self.clock.spend(timeout)
                    if self.mode in {"kill-required", "linger"}:
                        self.alive = False

            def terminate(self) -> None:
                self.terminate_calls += 1
                self.phase = "terminate"
                self.events.append(("terminate", None))

            def kill(self) -> None:
                self.kill_calls += 1
                self.phase = "kill"
                self.events.append(("kill", None))

            def close(self) -> None:
                self.close_calls += 1
                if self.alive:
                    raise ValueError("cannot close live process")

        def run_case(
            mode: str,
            *,
            poll_result: bool,
            poll_delay: float | None = None,
            received: bytes | BaseException = b"",
            timeout: float = 3.0,
        ) -> tuple[object | None, SpawnedWorkerError | None, Process, list[Connection], list[tuple[str, float | None]], float]:
            clock = Clock()
            events: list[tuple[str, float | None]] = []
            request_receiver = Connection(clock, events)
            request_sender = Connection(clock, events)
            result_receiver = Connection(
                clock,
                events,
                poll_result=poll_result,
                poll_delay=poll_delay,
                received=received,
            )
            result_sender = Connection(clock, events)
            connections = [
                request_receiver,
                request_sender,
                result_receiver,
                result_sender,
            ]
            process = Process(clock, events, mode)
            context = mock.Mock()
            context.Pipe.side_effect = (
                (request_receiver, request_sender),
                (result_receiver, result_sender),
            )
            context.Process.return_value = process
            result: object | None = None
            error: SpawnedWorkerError | None = None

            def read_fake_frame(
                connection: Connection, *, maximum: int, deadline: float
            ) -> bytes:
                self.assertEqual(maximum, transport.RESULT_FRAME_MAX_BYTES)
                events.append(("read", deadline - clock.monotonic()))
                clock.spend(
                    deadline - clock.monotonic()
                    if connection.poll_delay is None
                    else connection.poll_delay
                )
                if not connection.poll_result:
                    raise transport._ConnectionFrameTimeout
                if isinstance(connection.received, BaseException):
                    raise transport._InvalidConnectionFrame
                return connection.received

            with (
                mock.patch.object(transport.time, "monotonic", clock.monotonic),
                mock.patch.object(
                    transport.multiprocessing, "get_context", return_value=context
                ),
                mock.patch.object(
                    transport,
                    "_read_bounded_connection_frame",
                    side_effect=read_fake_frame,
                ),
            ):
                try:
                    result = prepare_request_in_spawned_worker(request, timeout=timeout)
                except SpawnedWorkerError as caught:
                    error = caught
            return result, error, process, connections, events, clock.now - 100.0

        valid_result = transport._compact_json(
            {
                "v": 1,
                "kind": "prepared",
                "method": "GET",
                "url": expected_url,
                "body_present": False,
                "pid": 4242,
                "start_method": "spawn",
            }
        )

        result, error, process, connections, events, elapsed = run_case(
            "success", poll_result=True, poll_delay=0.1, received=valid_result
        )
        self.assertIsNone(error)
        self.assertEqual(getattr(result, "url", None), expected_url)
        self.assertFalse(process.alive)
        self.assertEqual((process.terminate_calls, process.kill_calls), (0, 0))
        self.assertLessEqual(elapsed, 1.0)
        self.assertTrue(all(connection.close_calls >= 1 for connection in connections))
        self.assertEqual(process.close_calls, 1)

        for mode, expected_kills, expected_elapsed in (
            ("terminate-exits", 0, 1.25),
            ("kill-required", 1, 3.0),
            ("unreaped", 1, 3.0),
        ):
            with self.subTest(mode=mode):
                _, error, process, connections, events, elapsed = run_case(
                    mode, poll_result=False
                )
                self.assertIsNotNone(error)
                self.assertEqual(process.terminate_calls, 1)
                self.assertEqual(process.kill_calls, expected_kills)
                self.assertLessEqual(elapsed, expected_elapsed)
                self.assertLessEqual(elapsed, 3.0)
                self.assertTrue(
                    all(connection.close_calls >= 1 for connection in connections)
                )
                self.assertEqual(process.close_calls, 1)
                read_budget = next(value for name, value in events if name == "read")
                self.assertEqual(read_budget, 1.0)
                teardown_joins = [
                    (name, value)
                    for name, value in events
                    if name in {"join-terminate", "join-kill"}
                ]
                self.assertEqual(teardown_joins[0], ("join-terminate", 0.5))
                self.assertLess(
                    events.index(("read", 1.0)), events.index(("terminate", None))
                )
                if expected_kills:
                    self.assertEqual(teardown_joins[1], ("join-kill", 1.5))
                    self.assertLess(
                        events.index(("terminate", None)), events.index(("kill", None))
                    )
                if mode == "unreaped":
                    self.assertTrue(process.alive)
                    self.assertEqual(error.args, ("request worker could not be reaped",))
                else:
                    self.assertFalse(process.alive)
                    self.assertEqual(error.args, ("request worker did not complete",))

        # A valid result is not successful unless its child exits by the work cutoff.
        _, error, process, _, events, elapsed = run_case(
            "linger", poll_result=True, poll_delay=0.25, received=valid_result
        )
        self.assertEqual(error.args, ("request worker did not complete",))
        self.assertEqual((process.terminate_calls, process.kill_calls), (1, 1))
        self.assertFalse(process.alive)
        self.assertLessEqual(elapsed, 3.0)
        self.assertIn(("join-work", 0.75), events)

        # EOF/error after readiness is stable and still reaps the child.
        _, error, process, _, _, elapsed = run_case(
            "kill-required", poll_result=True, poll_delay=0.1, received=EOFError()
        )
        self.assertEqual(error.args, ("request worker returned invalid result",))
        self.assertFalse(process.alive)
        self.assertLessEqual(elapsed, 3.0)

        parameters = inspect.signature(prepare_request_in_spawned_worker).parameters
        self.assertEqual(parameters["timeout"].default, 20.0)
        parent_source = inspect.getsource(prepare_request_in_spawned_worker)
        self.assertNotIn("recv_bytes", parent_source)
        self.assertNotIn(".poll(", parent_source)
        for invalid_timeout in (
            True,
            False,
            2,
            2.999,
            math.inf,
            -math.inf,
            math.nan,
            "20",
            None,
            object(),
        ):
            with self.subTest(invalid_timeout=invalid_timeout):
                with mock.patch.object(transport.multiprocessing, "get_context") as context:
                    with self.assertRaises((TypeError, ValueError)):
                        prepare_request_in_spawned_worker(
                            request, timeout=invalid_timeout  # type: ignore[arg-type]
                        )
                    context.assert_not_called()

        # Exercise the real spawn boundary repeatedly after one warm-up that may
        # start multiprocessing's persistent resource-tracker descriptor.
        warmup = prepare_request_in_spawned_worker(request, timeout=5.0)
        self.assertNotIn(
            warmup.worker_pid,
            {child.pid for child in multiprocessing.active_children()},
        )
        fd_directory = "/proc/self/fd"
        descriptor_baseline = len(os.listdir(fd_directory))
        children_baseline = {child.pid for child in multiprocessing.active_children()}
        real_worker_pids = []
        for _ in range(5):
            real_result = prepare_request_in_spawned_worker(request, timeout=5.0)
            real_worker_pids.append(real_result.worker_pid)
            self.assertNotIn(
                real_result.worker_pid,
                {child.pid for child in multiprocessing.active_children()},
            )
        self.assertEqual(len(real_worker_pids), 5)
        self.assertEqual(
            {child.pid for child in multiprocessing.active_children()},
            children_baseline,
        )
        self.assertLessEqual(len(os.listdir(fd_directory)), descriptor_baseline)

    def test_spawned_result_is_exactly_bound_to_request_and_process(self) -> None:
        import technocore_sentinel.transport as transport
        from technocore_sentinel.transport import SpawnedWorkerError

        expected_url = (
            "https://technocore.chat/r/bound-room?"
            "format=json&limit=17&since=42&wait=3"
        )
        valid = {
            "v": 1,
            "kind": "prepared",
            "method": "GET",
            "url": expected_url,
            "body_present": False,
            "pid": 4242,
            "start_method": "spawn",
        }
        tampered = (
            {**valid, "url": expected_url.replace("bound-room", "other-room")},
            {
                **valid,
                "url": (
                    "https://technocore.chat/r/bound-room?"
                    "limit=17&format=json&since=42&wait=3"
                ),
            },
            {**valid, "url": expected_url + "&extra=1"},
            {
                **valid,
                "url": (
                    "https://technocore.chat/r/alternate?"
                    "format=json&limit=17&since=42&wait=3"
                ),
            },
            {**valid, "pid": 4243},
            {**valid, "method": "POST"},
            {**valid, "body_present": True},
            {**valid, "start_method": "fork"},
        )

        for value in tampered:
            with self.subTest(value=value):
                with self.assertRaises(SpawnedWorkerError) as raised:
                    transport._decode_prepared_result(
                        transport._compact_json(value),
                        request_frame_bytes=100,
                        expected_method="GET",
                        expected_url=expected_url,
                        expected_body_present=False,
                        expected_pid=4242,
                    )
                self.assertEqual(
                    raised.exception.args,
                    ("request worker returned invalid result",),
                )

        result = transport._decode_prepared_result(
            transport._compact_json(valid),
            request_frame_bytes=100,
            expected_method="GET",
            expected_url=expected_url,
            expected_body_present=False,
            expected_pid=4242,
        )
        self.assertEqual(
            (result.method, result.url, result.body_present, result.worker_pid),
            ("GET", expected_url, False, 4242),
        )

    def test_spawned_input_is_validated_before_serialization_or_spawn(self) -> None:
        import technocore_sentinel.transport as transport
        from technocore_sentinel.transport import (
            Route,
            SpawnedWorkerError,
            WorkerRequest,
            prepare_request_in_spawned_worker,
        )

        class SpoofString(str):
            pass

        class SpoofInteger(int):
            pass

        invalid = (
            "not-a-worker-request",
            WorkerRequest("room-read", "events", 1),  # type: ignore[arg-type]
            WorkerRequest(Route.ROOM_READ, "x" * 1_000_000, 1),
            WorkerRequest(Route.ROOM_READ, "events", 10**5000),
            WorkerRequest(Route.ROOM_READ, "events", -(10**5000)),
            WorkerRequest(Route.ROOM_READ, SpoofString("events"), 1),
            WorkerRequest(Route.ROOM_READ, "events", SpoofInteger(1)),
            WorkerRequest(Route.ROOM_READ, "events", True),
            WorkerRequest(Route.ROOM_READ, "events", 1, since=False),
            WorkerRequest(Route.ROOM_READ, "events", 1, since=0, wait=True),
        )
        fake_context = mock.Mock()
        for request in invalid:
            with self.subTest(request_type=type(request).__name__):
                with (
                    mock.patch.object(transport, "_compact_json") as compact,
                    mock.patch.object(
                        transport.multiprocessing,
                        "get_context",
                        return_value=fake_context,
                    ) as get_context,
                    self.assertRaises(SpawnedWorkerError) as raised,
                ):
                    prepare_request_in_spawned_worker(request)  # type: ignore[arg-type]
                self.assertEqual(
                    raised.exception.args,
                    ("request worker input rejected",),
                )
                compact.assert_not_called()
                get_context.assert_not_called()
                fake_context.Process.assert_not_called()

        valid = WorkerRequest(Route.ROOM_READ, "events", 1)
        for failure in (
            TypeError("secret"),
            ValueError("secret"),
            OverflowError("secret"),
            RecursionError("secret"),
        ):
            with self.subTest(serialization_failure=type(failure).__name__):
                with (
                    mock.patch.object(
                        transport, "_compact_json", side_effect=failure
                    ),
                    mock.patch.object(
                        transport.multiprocessing,
                        "get_context",
                        return_value=fake_context,
                    ) as get_context,
                    self.assertRaises(SpawnedWorkerError) as raised,
                ):
                    prepare_request_in_spawned_worker(valid)
                self.assertEqual(
                    raised.exception.args,
                    ("request worker input rejected",),
                )
                get_context.assert_not_called()
                fake_context.Process.assert_not_called()

    def test_fixed_origin_and_route_allowlist(self) -> None:
        from technocore_sentinel.transport import ORIGIN, Route, build_request

        self.assertEqual(ORIGIN, "https://technocore.chat")
        self.assertEqual(tuple(Route), (Route.ROOM_READ,))
        self.assertEqual(Route.ROOM_READ.value, "room-read")

        boundary_cases = (
            (
                {"room": "a", "limit": 1},
                "https://technocore.chat/r/a?format=json&limit=1",
            ),
            (
                {"room": "z" * 48, "limit": 200, "since": 0, "wait": 0},
                "https://technocore.chat/r/"
                + ("z" * 48)
                + "?format=json&limit=200&since=0&wait=0",
            ),
            (
                {
                    "room": "room_1-test",
                    "limit": 17,
                    "since": int("9" * 64),
                    "wait": 10,
                },
                "https://technocore.chat/r/room_1-test?format=json&limit=17&since="
                + ("9" * 64)
                + "&wait=10",
            ),
        )
        for arguments, expected_url in boundary_cases:
            with self.subTest(arguments=arguments):
                request = build_request(Route.ROOM_READ, **arguments)
                self.assertEqual(request.full_url, expected_url)
                self.assertEqual(request.get_method(), "GET")
                self.assertIsNone(request.data)
                split = urlsplit(request.full_url)
                self.assertEqual(
                    (split.scheme, split.netloc, split.fragment),
                    ("https", "technocore.chat", ""),
                )
                self.assertEqual(
                    parse_qsl(split.query, keep_blank_values=True),
                    parse_qsl(expected_url.split("?", 1)[1], keep_blank_values=True),
                )

        invalid_rooms = (
            "",
            "A",
            "a" * 49,
            "/r/events",
            "https://evil.example/r/events",
            "../say",
            "say/signed",
            "room?limit=200",
            "room#fragment",
            "room%2Fsay",
        )
        for room in invalid_rooms:
            with self.subTest(room=room):
                with self.assertRaises((TypeError, ValueError)):
                    build_request(Route.ROOM_READ, room=room, limit=1)

        invalid_calls = (
            ("room-read", {"room": "events", "limit": 1}),
            ("GET", {"room": "events", "limit": 1}),
            ("/r/events", {"room": "events", "limit": 1}),
            ("https://technocore.chat/r/events", {"room": "events", "limit": 1}),
            (object(), {"room": "events", "limit": 1}),
        )
        for route, arguments in invalid_calls:
            with self.subTest(route=route):
                with self.assertRaises((TypeError, ValueError)):
                    build_request(route, **arguments)

        invalid_values = (
            {"room": "events", "limit": True},
            {"room": "events", "limit": 0},
            {"room": "events", "limit": 201},
            {"room": "events", "limit": 1.0},
            {"room": "events", "limit": 1, "since": True},
            {"room": "events", "limit": 1, "since": -1},
            {"room": "events", "limit": 1, "since": int("1" + "0" * 64)},
            {"room": "events", "limit": 1, "since": 1.0},
            {"room": "events", "limit": 1, "wait": 0},
            {"room": "events", "limit": 1, "since": 0, "wait": True},
            {"room": "events", "limit": 1, "since": 0, "wait": -1},
            {"room": "events", "limit": 1, "since": 0, "wait": 11},
            {"room": "events", "limit": 1, "since": 0, "wait": 1.0},
        )
        for arguments in invalid_values:
            with self.subTest(arguments=arguments):
                with self.assertRaises((TypeError, ValueError)):
                    build_request(Route.ROOM_READ, **arguments)

        for forbidden, value in (
            ("origin", "https://evil.example"),
            ("url", "https://evil.example/r/events"),
            ("path", "/say/events"),
            ("method", "POST"),
            ("query", [("limit", 1), ("limit", 2)]),
            ("body", b"unsafe"),
            ("fragment", "unsafe"),
        ):
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(TypeError):
                    build_request(
                        Route.ROOM_READ,
                        room="events",
                        limit=1,
                        **{forbidden: value},
                    )

        parameters = inspect.signature(build_request).parameters
        self.assertEqual(tuple(parameters), ("route", "room", "limit", "since", "wait"))
        self.assertTrue(all(name not in parameters for name in ("origin", "path", "method", "query", "body")))


if __name__ == "__main__":
    unittest.main()
