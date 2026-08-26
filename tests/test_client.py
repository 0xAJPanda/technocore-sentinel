"""Tests for the origin-pinned, bounded HTTP client."""

from __future__ import annotations

from collections.abc import Sequence
from io import BytesIO
import json
import unittest
from unittest import mock
from urllib.error import HTTPError

from technocore_sentinel.client import (
    ClientError,
    MAX_RESPONSE_BYTES,
    ResponseTooLarge,
    SubmitAuthorization,
    TechnocoreClient,
)
from technocore_sentinel.identity import derive_did_key, profile_location, sign_message


class Response:
    def __init__(
        self,
        body: bytes,
        url: str,
        status: int = 200,
        content_type: str | None = "application/json; charset=utf-8",
    ) -> None:
        self.body = BytesIO(body)
        self.url = url
        self.status = status
        self.headers = {} if content_type is None else {"Content-Type": content_type}

    def read(self, size: int = -1) -> bytes:
        return self.body.read(size)

    def geturl(self) -> str:
        return self.url

    def getcode(self) -> int:
        return self.status

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None


class QueueOpener:
    def __init__(
        self,
        items: Sequence[bytes | Exception | tuple[bytes, str] | tuple[bytes, str, str | None]],
    ) -> None:
        self.items = list(items)
        self.requests: list[object] = []
        self.timeouts: list[float] = []

    def open(self, request: object, timeout: float) -> Response:
        self.requests.append(request)
        self.timeouts.append(timeout)
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        requested = request.full_url  # type: ignore[attr-defined]
        if isinstance(item, tuple):
            if len(item) == 3:
                return Response(item[0], item[1], content_type=item[2])
            return Response(item[0], item[1])
        return Response(item, requested)


def room(messages: list[dict[str, object]] | None = None) -> bytes:
    return json.dumps({"room": "lobby", "messages": messages or []}).encode()


def note(value: str) -> bytes:
    return json.dumps({"value": value}).encode()


class ClientValidationTests(unittest.TestCase):
    def test_origin_is_strictly_canonical_and_names_are_local(self) -> None:
        for origin in (
            "http://technocore.chat",
            "https://evil.invalid",
            "https://technocore.chat.evil.invalid",
            "https://user@technocore.chat",
            "https://technocore.chat:443",
            "https://technocore.chat/path",
            "https://technocore.chat?x=1",
            "https://TECHNOCORE.chat",
            "https://technocore.chat.",
        ):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                TechnocoreClient(origin)
        client = TechnocoreClient(opener=QueueOpener([]))
        for value in ("../lobby", "Lobby", "a/b", "a" * 49, ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                client.get_room(value)

    def test_get_shape_headers_timeout_and_scanner_validation(self) -> None:
        opener = QueueOpener([room([{"seq": 1, "from": "x", "text": "hello"}])])
        payload = TechnocoreClient(opener=opener).get_room("lobby", limit=5)
        request = opener.requests[0]
        self.assertEqual(payload["room"], "lobby")
        self.assertEqual(request.get_method(), "GET")  # type: ignore[attr-defined]
        self.assertEqual(request.full_url, "https://technocore.chat/r/lobby?format=json&limit=5")  # type: ignore[attr-defined]
        self.assertEqual(request.headers["Accept-encoding"], "identity")  # type: ignore[attr-defined]
        self.assertEqual(request.headers["Accept"], "application/json")  # type: ignore[attr-defined]
        self.assertIn("technocore-sentinel", request.headers["User-agent"])  # type: ignore[attr-defined]
        self.assertEqual(opener.timeouts, [20.0])

        with self.assertRaises(ClientError):
            TechnocoreClient(opener=QueueOpener([b"[]"])).get_room("lobby")

    def test_redirects_and_response_url_mismatch_are_refused(self) -> None:
        url = "https://technocore.chat/r/lobby?format=json&limit=200"
        redirect = HTTPError(url, 302, "Found", {"Location": "https://evil.invalid"}, BytesIO(b""))
        with self.assertRaises(ClientError):
            TechnocoreClient(opener=QueueOpener([redirect])).get_room("lobby")
        with self.assertRaises(ClientError):
            TechnocoreClient(opener=QueueOpener([(room(), "https://evil.invalid/r/lobby")])).get_room("lobby")

    def test_response_cap_reads_only_one_mib_plus_one(self) -> None:
        with self.assertRaises(ResponseTooLarge):
            TechnocoreClient(opener=QueueOpener([b"x" * (MAX_RESPONSE_BYTES + 1)])).get_room("lobby")

    def test_json_responses_require_json_media_type(self) -> None:
        url = "https://technocore.chat/r/lobby?format=json&limit=200"
        for content_type in (None, "text/plain", "application/problem+json"):
            with self.subTest(content_type=content_type), self.assertRaises(ClientError):
                TechnocoreClient(
                    opener=QueueOpener([(room(), url, content_type)])
                ).get_room("lobby")

    def test_note_requires_exact_json_shape_and_caps_value(self) -> None:
        self.assertEqual(TechnocoreClient.parse_note_response(note("exact")), "exact")
        for invalid in (b'"exact"', b'{"value":"exact","extra":true}', b'{"value":1}', b"{}"):
            with self.subTest(invalid=invalid), self.assertRaises(ClientError):
                TechnocoreClient.parse_note_response(invalid)
        with self.assertRaises(ResponseTooLarge):
            TechnocoreClient.parse_note_response(note("x" * 8193))

        opener = QueueOpener([note("exact")])
        self.assertEqual(TechnocoreClient(opener=opener).get_note("profiles", "alice"), "exact")
        request = opener.requests[0]
        self.assertEqual(request.full_url, "https://technocore.chat/kv/profiles/alice?format=json")  # type: ignore[attr-defined]
        self.assertEqual(request.headers["Accept"], "application/json")  # type: ignore[attr-defined]

    def test_get_room_rejects_payload_for_a_different_room(self) -> None:
        payload = json.dumps({"room": "elsewhere", "messages": []}).encode()
        with self.assertRaises(ClientError):
            TechnocoreClient(opener=QueueOpener([payload])).get_room("lobby")


class ClientWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.seed = bytes(32)
        self.did = derive_did_key(self.seed)
        _, self.namespace, self.key, self.path = profile_location(self.did)

    def test_submit_authorization_is_frozen_and_required(self) -> None:
        with self.assertRaises(PermissionError):
            TechnocoreClient(opener=QueueOpener([])).publish_profile(self.did, "value", None)  # type: ignore[arg-type]
        with self.assertRaises(PermissionError):
            TechnocoreClient(opener=QueueOpener([])).publish_profile(
                self.did, "value", SubmitAuthorization("introduce")
            )
        authorization = SubmitAuthorization("publish-profile")
        with self.assertRaises((AttributeError, TypeError)):
            authorization.operation = "introduce"  # type: ignore[misc]

    def test_profile_post_shape_and_exact_readback(self) -> None:
        opener = QueueOpener([b'{"stored":true}', note("profile")])
        receipt = TechnocoreClient(opener=opener).publish_profile(
            self.did, "profile", SubmitAuthorization("publish-profile")
        )
        post, get = opener.requests
        self.assertEqual(post.get_method(), "POST")  # type: ignore[attr-defined]
        self.assertEqual(post.full_url, f"https://technocore.chat{self.path}?format=json")  # type: ignore[attr-defined]
        self.assertEqual(json.loads(post.data), {"value": "profile", "if_absent": True})  # type: ignore[attr-defined]
        self.assertEqual(get.get_method(), "GET")  # type: ignore[attr-defined]
        self.assertTrue(receipt.created)

    def test_profile_success_requires_exact_stored_acknowledgement(self) -> None:
        invalid_responses = (
            b'{"stored":false}',
            b'{}',
            b'{"stored":true,"extra":true}',
            b'[]',
            b'not-json',
        )
        for response in invalid_responses:
            opener = QueueOpener([response])
            with self.subTest(response=response), self.assertRaises(ClientError):
                TechnocoreClient(opener=opener).publish_profile(
                    self.did, "profile", SubmitAuthorization("publish-profile")
                )
            self.assertEqual(len(opener.requests), 1)

    def test_profile_409_equal_is_idempotent_but_difference_aborts(self) -> None:
        url = f"https://technocore.chat{self.path}?format=json"
        conflict = HTTPError(url, 409, "Conflict", {}, BytesIO(b"conflict"))
        opener = QueueOpener([conflict, note("profile"), note("profile")])
        receipt = TechnocoreClient(opener=opener).publish_profile(
            self.did, "profile", SubmitAuthorization("publish-profile")
        )
        self.assertFalse(receipt.created)
        self.assertEqual([r.get_method() for r in opener.requests], ["POST", "GET", "GET"])  # type: ignore[attr-defined]

        conflict = HTTPError(url, 409, "Conflict", {}, BytesIO(b"conflict"))
        with self.assertRaises(ClientError):
            TechnocoreClient(opener=QueueOpener([conflict, note("other")])).publish_profile(
                self.did, "profile", SubmitAuthorization("publish-profile")
            )

    def test_profile_success_with_wrong_readback_fails(self) -> None:
        with self.assertRaises(ClientError):
            TechnocoreClient(opener=QueueOpener([b"{}", note("other")])).publish_profile(
                self.did, "profile", SubmitAuthorization("publish-profile")
            )

    def test_signed_post_body_and_exact_get_verification(self) -> None:
        signed = sign_message(self.seed, "lobby", "123", "hello")
        verified = room([{"seq": 8, "from": signed.did, "nonce": 123, "text": "hello", "ts": "now"}])
        opener = QueueOpener([b'{"posted":true}', verified])
        receipt = TechnocoreClient(opener=opener).post_signed_message(
            "lobby", signed, SubmitAuthorization("introduce"), prior_last_seq=7
        )
        post, get = opener.requests
        self.assertEqual(json.loads(post.data), {  # type: ignore[attr-defined]
            "did": signed.did, "sig": signed.signature, "nonce": "123", "text": "hello"
        })
        self.assertEqual(get.full_url, "https://technocore.chat/r/lobby?format=json&limit=200&since=7")  # type: ignore[attr-defined]
        self.assertEqual(receipt.seq, 8)

    def test_signed_post_authorization_failures_make_no_requests(self) -> None:
        signed = sign_message(self.seed, "lobby", "123", "hello")
        for authorization in (None, object(), SubmitAuthorization("publish-profile")):
            opener = QueueOpener([])
            with self.subTest(authorization=authorization), self.assertRaises(PermissionError):
                TechnocoreClient(opener=opener).post_signed_message(
                    "lobby", signed, authorization, prior_last_seq=0  # type: ignore[arg-type]
                )
            self.assertEqual(opener.requests, [])

    def test_signed_readback_sequence_must_advance(self) -> None:
        signed = sign_message(self.seed, "lobby", "123", "hello")
        for seq in (True, 7):
            verified = room([{"seq": seq, "from": signed.did, "nonce": 123, "text": "hello"}])
            with self.subTest(seq=seq), self.assertRaises(ClientError):
                TechnocoreClient(opener=QueueOpener([b'{"posted":true}', verified])).post_signed_message(
                    "lobby", signed, SubmitAuthorization("introduce"), prior_last_seq=7
                )

    def test_signed_readback_nonce_must_be_bounded_integer_and_canonical(self) -> None:
        invalid_cases = (
            ("123", 0),
            (True, 0),
            (0, 0),
            (10_000_000_000_000_000_000, 0),
            (123.0, 0),
        )
        signed = sign_message(self.seed, "lobby", "123", "hello")
        for readback_nonce, prior_last_seq in invalid_cases:
            verified = room(
                [{"seq": prior_last_seq + 1, "from": signed.did, "nonce": readback_nonce, "text": "hello"}]
            )
            with self.subTest(readback_nonce=readback_nonce), self.assertRaises(ClientError):
                TechnocoreClient(opener=QueueOpener([b'{"posted":true}', verified])).post_signed_message(
                    "lobby", signed, SubmitAuthorization("introduce"), prior_last_seq=prior_last_seq
                )

        noncanonical = sign_message(self.seed, "lobby", "00123", "hello")
        verified = room([{"seq": 1, "from": noncanonical.did, "nonce": 123, "text": "hello"}])
        with self.assertRaises(ClientError):
            TechnocoreClient(opener=QueueOpener([b'{"posted":true}', verified])).post_signed_message(
                "lobby", noncanonical, SubmitAuthorization("introduce"), prior_last_seq=0
            )

    def test_http_200_is_not_enough_for_signed_post(self) -> None:
        signed = sign_message(self.seed, "lobby", "123", "hello")
        for first, second in ((b'{"posted":false}', None), (b'{"posted":true}', room())):
            items = [first] if second is None else [first, second]
            with self.subTest(first=first), self.assertRaises(ClientError):
                TechnocoreClient(opener=QueueOpener(items)).post_signed_message(
                    "lobby", signed, SubmitAuthorization("introduce"), prior_last_seq=0
                )


if __name__ == "__main__":
    unittest.main()
