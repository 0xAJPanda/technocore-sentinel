"""Fixed-origin request construction and strict transport primitives.

This module deliberately performs no I/O.  Opening requests, headers, response
media, encodings, and bodies belong to later transport boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from email.message import Message
from enum import Enum
import hashlib
import hmac
from http.client import HTTPMessage
import json
import math
import multiprocessing
from multiprocessing.connection import Connection
import os
import selectors
import struct
import time
from typing import Any, NoReturn
from urllib.request import (
    HTTPRedirectHandler,
    OpenerDirector,
    ProxyHandler,
    Request,
    build_opener,
)

from .naming import is_valid_name

ORIGIN = "https://technocore.chat"
REQUEST_FRAME_MAX_BYTES = 8_192
RESULT_FRAME_MAX_BYTES = 8_192
ROOM_RESPONSE_MAX_BYTES = 1_048_576
_WORKER_COMPLETION_SECONDS = 20.0
_WORKER_TEARDOWN_SECONDS = 2.0
_WORKER_TERMINATE_SECONDS = 0.5
_WORKER_KILL_SECONDS = 1.5
_MAX_SEQUENCE = (10**64) - 1
_REDIRECT_REFUSED_MESSAGE = "redirect response refused"
_UNSUPPORTED_CONTENT_ENCODING_MESSAGE = "unsupported response content encoding"
_UNSUPPORTED_RESPONSE_MEDIA_MESSAGE = "unsupported response media type"
_INVALID_RESPONSE_BODY_MESSAGE = "invalid response body"
_RESPONSE_BODY_TOO_LARGE_MESSAGE = "response body exceeds byte limit"
_INVALID_RESPONSE_ATTESTATION_MESSAGE = "invalid response attestation"


class TransportError(Exception):
    """Base error for strict transport policy failures."""


class RedirectRefusedError(TransportError):
    """Raised without remote content when strict transport receives a redirect."""


class UnsupportedContentEncodingError(TransportError):
    """Raised without remote content for an unsafe response content encoding."""


class UnsupportedResponseMediaError(TransportError):
    """Raised without remote content for an unsafe response media type."""


class ResponseTooLargeError(TransportError):
    """Raised without remote content when a response body exceeds its byte cap."""


class InvalidResponseBodyError(TransportError):
    """Raised without remote content for an unsupported response body result."""


class InvalidResponseAttestationError(TransportError):
    """Raised without remote content when response metadata is not exact."""


class SpawnedWorkerError(TransportError):
    """Raised without request content when the private worker boundary fails."""


def read_bounded_body(response: Any, *, max_bytes: int = ROOM_RESPONSE_MAX_BYTES) -> bytes:
    """Read and snapshot one size-bounded urllib/http-style response body.

    ``response.read(n)`` must have the standard blocking file/HTTP semantics:
    it returns up to ``n`` bytes and a short result means EOF.  Exactly one
    cap-plus-one read is made, so the requested allocation budget cannot exceed
    ``max_bytes + 1`` and a nonconforming short-chunk reader is not silently
    drained with additional requests.

    The caller retains ownership of ``response`` on every outcome and must close
    it. Reader exceptions propagate unchanged; malformed reader results use a
    stable transport error that never includes response content or metadata.
    """

    if type(max_bytes) is not int:
        raise TypeError("max_bytes must be an integer")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")

    body = response.read(max_bytes + 1)
    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise InvalidResponseBodyError(_INVALID_RESPONSE_BODY_MESSAGE)

    try:
        view = memoryview(body)
    except (BufferError, TypeError, ValueError):
        raise InvalidResponseBodyError(_INVALID_RESPONSE_BODY_MESSAGE) from None

    try:
        try:
            byte_length = view.nbytes
        except (BufferError, TypeError, ValueError):
            raise InvalidResponseBodyError(_INVALID_RESPONSE_BODY_MESSAGE) from None
        if byte_length > max_bytes:
            raise ResponseTooLargeError(_RESPONSE_BODY_TOO_LARGE_MESSAGE)
        try:
            snapshot = view.tobytes()
        except (BufferError, TypeError, ValueError):
            raise InvalidResponseBodyError(_INVALID_RESPONSE_BODY_MESSAGE) from None
    finally:
        view.release()

    return snapshot


class _InvalidRawHeaderState(Exception):
    """Internal sentinel for header state that cannot be trusted as evidence."""


_HTTP_FIELD_NAME_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)


def _raw_header_values_from_snapshot(
    raw_headers: tuple[object, ...], target: str
) -> tuple[str, ...]:
    """Validate and select fields from one exact immutable raw-header snapshot."""

    if type(raw_headers) is not tuple:
        raise _InvalidRawHeaderState

    values: list[str] = []
    for entry in raw_headers:
        if type(entry) is not tuple or len(entry) != 2:
            raise _InvalidRawHeaderState
        name, value = entry
        if (
            type(name) is not str
            or type(value) is not str
            or not name
            or not name.isascii()
            or any(character not in _HTTP_FIELD_NAME_CHARS for character in name)
        ):
            raise _InvalidRawHeaderState
        if name.lower() == target:
            values.append(value)
    return tuple(values)


def _raw_header_values(headers: Message | HTTPMessage, target: str) -> tuple[str, ...]:
    """Snapshot exact raw fields without MIME policy or header method dispatch."""

    if type(headers) not in {Message, HTTPMessage}:
        raise _InvalidRawHeaderState

    state = vars(headers)
    if type(state) is not dict:
        raise _InvalidRawHeaderState
    raw_headers = dict.get(state, "_headers")
    if type(raw_headers) is not list:
        raise _InvalidRawHeaderState
    raw_headers = tuple(raw_headers)

    return _raw_header_values_from_snapshot(raw_headers, target)


def validate_content_encoding(headers: Message | HTTPMessage) -> None:
    """Require absent or one identity Content-Encoding field without doing I/O.

    A present field may contain ASCII ``identity`` case-insensitively, surrounded
    only by HTTP optional whitespace (SP or HTAB). Duplicate fields, lists,
    parameters, folded/control/non-ASCII values, and unsupported header
    containers fail closed.
    """

    try:
        values = _raw_header_values(headers, "content-encoding")
    except _InvalidRawHeaderState:
        raise UnsupportedContentEncodingError(
            _UNSUPPORTED_CONTENT_ENCODING_MESSAGE
        ) from None

    if not values:
        return
    if len(values) != 1:
        raise UnsupportedContentEncodingError(_UNSUPPORTED_CONTENT_ENCODING_MESSAGE)

    value = values[0]
    if (
        type(value) is not str
        or not value.isascii()
        or value.strip(" \t").lower() != "identity"
    ):
        raise UnsupportedContentEncodingError(_UNSUPPORTED_CONTENT_ENCODING_MESSAGE)


class RedirectRefusalHandler(HTTPRedirectHandler):
    """Reject every HTTP redirect status before URL or body processing."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> NoReturn:
        raise RedirectRefusedError(_REDIRECT_REFUSED_MESSAGE)

    def _refuse_redirect(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
    ) -> NoReturn:
        # The HTTP error path owns the response.  Close it without reading, but
        # keep ordinary cleanup failures from replacing the stable policy error.
        try:
            fp.close()
        except Exception:
            pass

        # Route every supported status through redirect_request, without reading
        # Location or applying the standard library's method/body exceptions.
        self.redirect_request(req, fp, code, msg, headers, "")

    http_error_301 = _refuse_redirect
    http_error_302 = _refuse_redirect
    http_error_303 = _refuse_redirect
    http_error_307 = _refuse_redirect
    http_error_308 = _refuse_redirect


def build_strict_opener() -> OpenerDirector:
    """Construct a no-system-proxy opener that deterministically refuses redirects."""

    return build_opener(ProxyHandler({}), RedirectRefusalHandler())


class Route(str, Enum):
    """Closed identities for strict transport routes grounded for Task 1."""

    ROOM_READ = "room-read"


@dataclass(frozen=True, slots=True)
class WorkerRequest:
    """Closed immutable input transferred to one spawned request worker."""

    route: Route
    room: str
    limit: int
    since: int | None = None
    wait: int | None = None


_VALIDATED_ROOM_RESPONSE_TOKEN = object()
_ATTESTATION_METHOD_MAX_BYTES = 16
_ATTESTATION_URL_MAX_BYTES = REQUEST_FRAME_MAX_BYTES


def _bounded_attestation_text(value: str, *, max_bytes: int) -> bytes:
    """Encode one already type-checked attestation field within a fixed budget."""

    if not value or len(value) > max_bytes:
        raise ValueError("invalid validated response fields")
    encoded = value.encode("utf-8")
    if len(encoded) > max_bytes:
        raise ValueError("invalid validated response fields")
    return encoded


def _validated_room_response_digest(
    route: object,
    method: object,
    url: object,
    status: object,
    body: object,
) -> bytes:
    """Validate and digest bounded exact response semantics."""

    if (
        type(route) is not Route
        or type(method) is not str
        or type(url) is not str
        or type(status) is not int
        or type(body) is not bytes
    ):
        raise TypeError("invalid validated response fields")
    if (
        route is not Route.ROOM_READ
        or status != 200
        or len(body) > ROOM_RESPONSE_MAX_BYTES
    ):
        raise ValueError("invalid validated response fields")

    route_bytes = b"room-read"
    method_bytes = _bounded_attestation_text(
        method, max_bytes=_ATTESTATION_METHOD_MAX_BYTES
    )
    url_bytes = _bounded_attestation_text(url, max_bytes=_ATTESTATION_URL_MAX_BYTES)
    status_bytes = status.to_bytes(2, "big", signed=False)

    digest = hashlib.sha256(b"technocore-validated-room-response-v1\x00")
    for value in (route_bytes, method_bytes, url_bytes):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    digest.update(status_bytes)
    digest.update(len(body).to_bytes(8, "big"))
    digest.update(body)
    return digest.digest()


@dataclass(frozen=True, slots=True, init=False)
class ValidatedRoomResponse:
    """Immutable proof that one exact strict response passed all validators.

    Instances are issued only by :func:`validate_room_response`; callers
    cannot ordinarily construct an attestation around unvalidated bytes.
    """

    route: Route
    method: str
    url: str
    status: int
    body: bytes
    _proof: tuple[object, bytes] = field(repr=False, compare=False)

    def __init__(
        self,
        route: Route,
        method: str,
        url: str,
        status: int,
        body: bytes,
        *,
        _proof: object = None,
    ) -> None:
        if _proof is not _VALIDATED_ROOM_RESPONSE_TOKEN:
            raise TypeError("ValidatedRoomResponse must be created by its validator")
        object.__setattr__(self, "route", route)
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "url", url)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "body", body)
        digest = _validated_room_response_digest(route, method, url, status, body)
        object.__setattr__(self, "_proof", (_VALIDATED_ROOM_RESPONSE_TOKEN, digest))


def _has_validated_room_response_proof(value: object) -> bool:
    """Verify exact type, private issuance token, and bound semantic digest."""

    try:
        if type(value) is not ValidatedRoomResponse:
            return False
        proof = object.__getattribute__(value, "_proof")
        if (
            type(proof) is not tuple
            or len(proof) != 2
            or proof[0] is not _VALIDATED_ROOM_RESPONSE_TOKEN
            or type(proof[1]) is not bytes
            or len(proof[1]) != hashlib.sha256().digest_size
        ):
            return False
        expected = _validated_room_response_digest(
            object.__getattribute__(value, "route"),
            object.__getattribute__(value, "method"),
            object.__getattribute__(value, "url"),
            object.__getattribute__(value, "status"),
            object.__getattribute__(value, "body"),
        )
        return hmac.compare_digest(proof[1], expected)
    except (
        AttributeError,
        TypeError,
        ValueError,
        OverflowError,
        UnicodeEncodeError,
    ):
        return False


@dataclass(frozen=True, slots=True)
class PreparedRequestResult:
    """Bounded typed proof that a spawned worker prepared the strict request."""

    method: str
    url: str
    body_present: bool
    worker_pid: int
    start_method: str
    request_frame_bytes: int
    result_frame_bytes: int


_RESPONSE_MEDIA_BY_ROUTE = {
    Route.ROOM_READ: "application/json",
}


def validate_response_media(route: Route, headers: Message | HTTPMessage) -> None:
    """Require the exact response media grammar registered for ``route``.

    The room-read endpoint accepts only bare ``application/json``,
    case-insensitively and with optional surrounding HTTP OWS (SP or HTAB).
    Header values are inspected without body access, MIME policy parsing, or
    mutable header method dispatch.
    """

    if type(route) is not Route or route not in _RESPONSE_MEDIA_BY_ROUTE:
        raise UnsupportedResponseMediaError(_UNSUPPORTED_RESPONSE_MEDIA_MESSAGE)
    try:
        values = _raw_header_values(headers, "content-type")
    except _InvalidRawHeaderState:
        raise UnsupportedResponseMediaError(_UNSUPPORTED_RESPONSE_MEDIA_MESSAGE) from None

    if len(values) != 1:
        raise UnsupportedResponseMediaError(_UNSUPPORTED_RESPONSE_MEDIA_MESSAGE)

    value = values[0]
    if (
        type(value) is not str
        or not value.isascii()
        or _RESPONSE_MEDIA_BY_ROUTE[route] != "application/json"
        or value.strip(" \t").lower() != "application/json"
    ):
        raise UnsupportedResponseMediaError(_UNSUPPORTED_RESPONSE_MEDIA_MESSAGE)


def _bounded_integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside its permitted range")
    return value


def build_request(
    route: Route,
    *,
    room: str,
    limit: int,
    since: int | None = None,
    wait: int | None = None,
) -> Request:
    """Build one deterministic request from a closed strict route identity.

    The only currently grounded route is the ordinary room read.  Discovery is
    gated on Task 4 evidence, and POST authorization/transport is intentionally
    absent here.
    """

    if type(route) is not Route:
        raise TypeError("route must be a Route member")
    if route is not Route.ROOM_READ:  # pragma: no cover - exhaustive enum guard
        raise ValueError("unsupported route")
    if type(room) is not str or not is_valid_name(room):
        raise ValueError("invalid room")

    bounded_limit = _bounded_integer(limit, "limit", 1, 200)
    query_parts = ["format=json", f"limit={bounded_limit}"]

    if since is not None:
        bounded_since = _bounded_integer(since, "since", 0, _MAX_SEQUENCE)
        query_parts.append(f"since={bounded_since}")
    if wait is not None:
        if since is None:
            raise ValueError("wait requires since")
        bounded_wait = _bounded_integer(wait, "wait", 0, 10)
        query_parts.append(f"wait={bounded_wait}")

    url = f"{ORIGIN}/r/{room}?{'&'.join(query_parts)}"
    return Request(url, method="GET")


def validate_room_response(
    request: WorkerRequest,
    *,
    final_url: str,
    status: int,
    headers: Message | HTTPMessage,
    response: Any,
) -> ValidatedRoomResponse:
    """Validate and bind a strict response to its exact local request.

    Redirect outcome, status, encoding, media type, and bounded immutable body
    are checked before an attestation is issued. Header checks precede body I/O.
    This adapter never closes ``response``; the executor that opened it owns its
    lifecycle and must close it on success and failure.
    """

    try:
        if type(request) is not WorkerRequest:
            raise TypeError
        prepared = build_request(
            request.route,
            room=request.room,
            limit=request.limit,
            since=request.since,
            wait=request.wait,
        )
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise InvalidResponseAttestationError(
            _INVALID_RESPONSE_ATTESTATION_MESSAGE
        ) from None
    expected_url = prepared.full_url
    method = prepared.get_method()
    if (
        type(expected_url) is not str
        or type(method) is not str
        or method != "GET"
        or prepared.data is not None
    ):
        raise InvalidResponseAttestationError(_INVALID_RESPONSE_ATTESTATION_MESSAGE)
    if type(final_url) is not str or final_url != expected_url:
        raise InvalidResponseAttestationError(_INVALID_RESPONSE_ATTESTATION_MESSAGE)
    if type(status) is not int or status != 200:
        raise InvalidResponseAttestationError(_INVALID_RESPONSE_ATTESTATION_MESSAGE)

    validate_content_encoding(headers)
    validate_response_media(request.route, headers)
    body = read_bounded_body(response, max_bytes=ROOM_RESPONSE_MAX_BYTES)
    if type(body) is not bytes:  # pragma: no cover - guaranteed by primitive
        raise InvalidResponseAttestationError(_INVALID_RESPONSE_ATTESTATION_MESSAGE)
    return ValidatedRoomResponse(
        request.route,
        method,
        expected_url,
        status,
        body,
        _proof=_VALIDATED_ROOM_RESPONSE_TOKEN,
    )


_ERROR_FRAME = b'{"v":1,"kind":"error","error":"invalid-request"}'
_REQUEST_FRAME_FIELDS = frozenset({"v", "kind", "route", "request"})
_REQUEST_VALUE_FIELDS = frozenset({"room", "limit", "since", "wait"})
_RESULT_FRAME_FIELDS = frozenset(
    {"v", "kind", "method", "url", "body_present", "pid", "start_method"}
)
_WORKER_INPUT_REJECTED_MESSAGE = "request worker input rejected"


def _compact_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _decode_worker_request(frame: bytes, request_cap: int) -> WorkerRequest:
    from .protocol import decode_strict_json

    value = decode_strict_json(frame, max_bytes=request_cap)
    if type(value) is not dict or value.keys() != _REQUEST_FRAME_FIELDS:
        raise ValueError("invalid request frame")
    if (
        type(value["v"]) is not int
        or value["v"] != 1
        or type(value["kind"]) is not str
        or value["kind"] != "request"
    ):
        raise ValueError("invalid request frame")
    request_value = value["request"]
    if type(request_value) is not dict or request_value.keys() != _REQUEST_VALUE_FIELDS:
        raise ValueError("invalid request frame")
    if value["route"] != Route.ROOM_READ.value:
        raise ValueError("invalid request frame")
    return WorkerRequest(
        route=Route.ROOM_READ,
        room=request_value["room"],
        limit=request_value["limit"],
        since=request_value["since"],
        wait=request_value["wait"],
    )


def _spawned_request_worker(
    request_receiver: Connection,
    result_sender: Connection,
    request_cap: int,
    result_cap: int,
) -> None:
    """Prepare one request in a spawned child using only bounded byte frames."""

    try:
        try:
            frame = request_receiver.recv_bytes(request_cap)
            worker_request = _decode_worker_request(frame, request_cap)
            prepared = build_request(
                worker_request.route,
                room=worker_request.room,
                limit=worker_request.limit,
                since=worker_request.since,
                wait=worker_request.wait,
            )
            result_frame = _compact_json(
                {
                    "v": 1,
                    "kind": "prepared",
                    "method": prepared.get_method(),
                    "url": prepared.full_url,
                    "body_present": prepared.data is not None,
                    "pid": os.getpid(),
                    "start_method": multiprocessing.get_start_method(),
                }
            )
            if len(result_frame) > result_cap:
                raise ValueError("result frame exceeds cap")
        except BaseException:
            result_frame = _ERROR_FRAME

        if len(result_frame) <= result_cap:
            try:
                result_sender.send_bytes(result_frame)
            except BaseException:
                pass
    finally:
        request_receiver.close()
        result_sender.close()


def _validated_worker_request(request: WorkerRequest) -> Request:
    """Validate the closed input and prepare its exact parent-side expectation."""

    try:
        if type(request) is not WorkerRequest:
            raise TypeError
        return build_request(
            request.route,
            room=request.room,
            limit=request.limit,
            since=request.since,
            wait=request.wait,
        )
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise SpawnedWorkerError(_WORKER_INPUT_REJECTED_MESSAGE) from None


def _encode_worker_request(
    request: WorkerRequest, *, prepared: Request | None = None
) -> bytes:
    """Encode only fields already accepted by the strict request builder."""

    if prepared is None:
        prepared = _validated_worker_request(request)
    try:
        frame = _compact_json(
            {
                "v": 1,
                "kind": "request",
                "route": request.route.value,
                "request": {
                    "room": request.room,
                    "limit": request.limit,
                    "since": request.since,
                    "wait": request.wait,
                },
            }
        )
        if len(frame) > REQUEST_FRAME_MAX_BYTES:
            raise ValueError
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise SpawnedWorkerError(_WORKER_INPUT_REJECTED_MESSAGE) from None
    return frame


def _worker_timeout_seconds(timeout: int | float) -> float:
    """Validate one finite total worker deadline with its teardown reserve."""

    if type(timeout) not in {int, float}:
        raise TypeError("timeout must be a number")
    try:
        seconds = float(timeout)
    except (OverflowError, ValueError):
        raise ValueError("timeout must be finite") from None
    if not math.isfinite(seconds):
        raise ValueError("timeout must be finite")
    if seconds < 3.0:
        raise ValueError("timeout must be at least 3 seconds")
    return seconds


def _remaining(deadline: float) -> float:
    """Return a non-negative budget against one monotonic deadline."""

    return max(0.0, deadline - time.monotonic())


class _ConnectionFrameTimeout(Exception):
    """Internal signal that a complete Connection frame missed its deadline."""


class _InvalidConnectionFrame(Exception):
    """Internal signal for malformed, truncated, or oversized result framing."""


def _read_bounded_connection_frame(
    connection: Connection, *, maximum: int, deadline: float
) -> bytes:
    """Read one bounded ``Connection.send_bytes`` frame without blocking.

    This intentionally depends on CPython's POSIX multiprocessing Connection
    wire format: a 4-byte network-order signed payload length, with ``-1``
    introducing an 8-byte unsigned extended length.  Extended framing is never
    emitted for our bounded frames and is parsed only far enough to reject it
    safely.  The descriptor is nonblocking and every selector wait uses the one
    absolute work deadline, so readiness for a partial frame cannot overrun it.
    """

    if type(maximum) is not int or maximum < 0:
        raise ValueError("maximum must be a non-negative integer")

    try:
        descriptor = connection.fileno()
        was_blocking = os.get_blocking(descriptor)
    except (OSError, TypeError, ValueError):
        raise _InvalidConnectionFrame from None

    selector = selectors.DefaultSelector()
    header = bytearray()
    payload = bytearray()
    payload_length: int | None = None
    header_length = 4
    try:
        os.set_blocking(descriptor, False)
        selector.register(descriptor, selectors.EVENT_READ)
        while True:
            if payload_length is not None and len(payload) == payload_length:
                if time.monotonic() > deadline:
                    raise _ConnectionFrameTimeout
                return bytes(payload)
            remaining = _remaining(deadline)
            if remaining <= 0.0:
                raise _ConnectionFrameTimeout
            try:
                ready = selector.select(remaining)
            except (OSError, ValueError):
                raise _InvalidConnectionFrame from None
            if not ready:
                raise _ConnectionFrameTimeout

            if payload_length is None:
                needed = header_length - len(header)
            else:
                needed = payload_length - len(payload)

            try:
                chunk = os.read(descriptor, needed)
            except BlockingIOError:
                continue
            except OSError:
                raise _InvalidConnectionFrame from None
            if not chunk:
                raise _InvalidConnectionFrame

            if payload_length is None:
                header.extend(chunk)
                if len(header) < header_length:
                    continue
                if header_length == 4:
                    declared = struct.unpack("!i", header)[0]
                    if declared == -1:
                        header_length = 12
                        continue
                    if declared < 0 or declared > maximum:
                        raise _InvalidConnectionFrame
                    payload_length = declared
                else:
                    declared = struct.unpack("!Q", header[4:])[0]
                    if declared > maximum:
                        raise _InvalidConnectionFrame
                    # CPython send_bytes uses extended framing only above the
                    # signed 32-bit range, so a bounded declaration here is
                    # malformed rather than an alternate accepted encoding.
                    raise _InvalidConnectionFrame
            else:
                payload.extend(chunk)
    except _ConnectionFrameTimeout:
        raise
    except _InvalidConnectionFrame:
        raise
    except (OSError, TypeError, ValueError):
        raise _InvalidConnectionFrame from None
    finally:
        selector.close()
        try:
            os.set_blocking(descriptor, was_blocking)
        except OSError:
            pass


def _stop_worker(process: Any, *, deadline: float) -> bool:
    """Terminate then kill within the exact reserve of the original deadline."""

    if not process.is_alive():
        return True

    try:
        process.terminate()
    except BaseException:
        pass
    try:
        process.join(min(_WORKER_TERMINATE_SECONDS, _remaining(deadline)))
    except BaseException:
        pass
    if not process.is_alive():
        return True

    try:
        process.kill()
    except BaseException:
        pass
    try:
        process.join(min(_WORKER_KILL_SECONDS, _remaining(deadline)))
    except BaseException:
        pass
    return not process.is_alive()


def _decode_prepared_result(
    frame: bytes,
    *,
    request_frame_bytes: int,
    expected_method: str,
    expected_url: str,
    expected_body_present: bool,
    expected_pid: int,
) -> PreparedRequestResult:
    from .protocol import decode_strict_json

    try:
        value = decode_strict_json(frame, max_bytes=RESULT_FRAME_MAX_BYTES)
        if type(value) is not dict:
            raise ValueError
        if value.get("kind") == "error":
            if (
                value.keys() != frozenset({"v", "kind", "error"})
                or type(value["v"]) is not int
                or value["v"] != 1
                or type(value["kind"]) is not str
                or value["kind"] != "error"
                or type(value["error"]) is not str
                or value["error"] != "invalid-request"
            ):
                raise ValueError
            raise SpawnedWorkerError("request worker rejected input")
        if value.keys() != _RESULT_FRAME_FIELDS:
            raise ValueError
        if (
            type(value["v"]) is not int
            or value["v"] != 1
            or type(value["kind"]) is not str
            or value["kind"] != "prepared"
            or type(value["method"]) is not str
            or value["method"] != expected_method
            or type(value["url"]) is not str
            or value["url"] != expected_url
            or type(value["body_present"]) is not bool
            or value["body_present"] is not expected_body_present
            or type(value["pid"]) is not int
            or type(expected_pid) is not int
            or value["pid"] != expected_pid
            or type(value["start_method"]) is not str
            or value["start_method"] != "spawn"
        ):
            raise ValueError
        return PreparedRequestResult(
            method=value["method"],
            url=value["url"],
            body_present=value["body_present"],
            worker_pid=value["pid"],
            start_method=value["start_method"],
            request_frame_bytes=request_frame_bytes,
            result_frame_bytes=len(frame),
        )
    except SpawnedWorkerError:
        raise
    except BaseException:
        raise SpawnedWorkerError("request worker returned invalid result") from None


def prepare_request_in_spawned_worker(
    request: WorkerRequest, *, timeout: int | float = _WORKER_COMPLETION_SECONDS
) -> PreparedRequestResult:
    """Prepare one strict request through bounded one-way private IPC channels.

    Work, result transfer/validation, and a clean join share the interval ending
    two seconds before the total monotonic deadline.  The final two seconds are
    reserved for a 0.5-second terminate/join phase and a 1.5-second kill/join
    phase; cleanup never extends the caller's original total timeout.
    """

    timeout_seconds = _worker_timeout_seconds(timeout)
    deadline = time.monotonic() + timeout_seconds
    work_deadline = deadline - _WORKER_TEARDOWN_SECONDS
    expected = _validated_worker_request(request)
    expected_method = expected.get_method()
    expected_url = expected.full_url
    expected_body_present = expected.data is not None
    frame = _encode_worker_request(request, prepared=expected)
    connections: list[Any] = []
    process: Any | None = None
    started = False
    try:
        context = multiprocessing.get_context("spawn")
        request_receiver, request_sender = context.Pipe(duplex=False)
        connections.extend((request_receiver, request_sender))
        result_receiver, result_sender = context.Pipe(duplex=False)
        connections.extend((result_receiver, result_sender))
        process = context.Process(
            target=_spawned_request_worker,
            args=(
                request_receiver,
                result_sender,
                REQUEST_FRAME_MAX_BYTES,
                RESULT_FRAME_MAX_BYTES,
            ),
        )
        process.start()
        started = True
        worker_pid = process.pid
        if type(worker_pid) is not int:
            raise SpawnedWorkerError("request worker failed")
        request_receiver.close()
        result_sender.close()
        request_sender.send_bytes(frame)
        request_sender.close()

        try:
            result_frame = _read_bounded_connection_frame(
                result_receiver,
                maximum=RESULT_FRAME_MAX_BYTES,
                deadline=work_deadline,
            )
        except _ConnectionFrameTimeout:
            raise SpawnedWorkerError("request worker did not complete") from None
        except _InvalidConnectionFrame:
            raise SpawnedWorkerError("request worker returned invalid result") from None

        result = _decode_prepared_result(
            result_frame,
            request_frame_bytes=len(frame),
            expected_method=expected_method,
            expected_url=expected_url,
            expected_body_present=expected_body_present,
            expected_pid=worker_pid,
        )
        process.join(_remaining(work_deadline))
        if (
            time.monotonic() > work_deadline
            or process.is_alive()
            or process.exitcode != 0
        ):
            raise SpawnedWorkerError("request worker did not complete")
        return result
    except SpawnedWorkerError:
        raise
    except BaseException:
        raise SpawnedWorkerError("request worker failed") from None
    finally:
        for connection in connections:
            try:
                connection.close()
            except BaseException:
                pass
        reaped = True
        if started:
            try:
                reaped = _stop_worker(process, deadline=deadline)
            except BaseException:
                reaped = False
        if process is not None:
            try:
                process.close()
            except BaseException:
                pass
        if not reaped:
            raise SpawnedWorkerError("request worker could not be reaped") from None
