"""Strict, bounded decoding primitives for Signalbox protocol data."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import math
from typing import NoReturn


DEFAULT_MAX_JSON_BYTES = 1_048_576
MAX_REQUEST_SEQUENCE = 10**64 - 1


class ProtocolDecodeError(ValueError):
    """Raised when protocol input is not one bounded, strict JSON value."""


@dataclass(frozen=True, slots=True)
class RoomMessage:
    """One immutable message projected from a closed room response."""

    seq: int
    ts: str
    sender: str
    text: str
    nonce: int | None = None


@dataclass(frozen=True, slots=True)
class RoomWindow:
    """An immutable, order-preserving room response window."""

    room: str
    count: int
    last_seq: int
    messages: tuple[RoomMessage, ...]
    first_seq: int | None = None
    leading_gap: bool | None = None


_ROOM_WINDOW_REQUIRED_FIELDS = frozenset({"room", "count", "last_seq", "messages"})
_ROOM_WINDOW_FIELDS = _ROOM_WINDOW_REQUIRED_FIELDS | {"first_seq"}
_ROOM_MESSAGE_REQUIRED_FIELDS = frozenset({"seq", "ts", "from", "text"})
_ROOM_MESSAGE_FIELDS = _ROOM_MESSAGE_REQUIRED_FIELDS | {"nonce"}


def _parse_room_message(value: object) -> RoomMessage:
    if type(value) is not dict:
        raise ProtocolDecodeError("room message must be an object")
    if not _ROOM_MESSAGE_REQUIRED_FIELDS <= value.keys() <= _ROOM_MESSAGE_FIELDS:
        raise ProtocolDecodeError("room message has invalid fields")

    if (
        type(value["seq"]) is not int
        or type(value["ts"]) is not str
        or type(value["from"]) is not str
        or type(value["text"]) is not str
        or ("nonce" in value and type(value["nonce"]) is not int)
    ):
        raise ProtocolDecodeError("room message field has invalid type")

    return RoomMessage(
        seq=value["seq"],
        ts=value["ts"],
        sender=value["from"],
        text=value["text"],
        nonce=value.get("nonce"),
    )


def parse_room_window(value: object) -> RoomWindow:
    """Project an already strict-decoded JSON value into closed room models."""
    if type(value) is not dict:
        raise ProtocolDecodeError("room window must be an object")
    if not _ROOM_WINDOW_REQUIRED_FIELDS <= value.keys() <= _ROOM_WINDOW_FIELDS:
        raise ProtocolDecodeError("room window has invalid fields")

    if (
        type(value["room"]) is not str
        or type(value["count"]) is not int
        or type(value["last_seq"]) is not int
        or (
            "first_seq" in value
            and value["first_seq"] is not None
            and type(value["first_seq"]) is not int
        )
    ):
        raise ProtocolDecodeError("room window field has invalid type")
    if type(value["messages"]) is not list:
        raise ProtocolDecodeError("room window messages must be an array")

    messages = tuple(_parse_room_message(message) for message in value["messages"])
    return RoomWindow(
        room=value["room"],
        count=value["count"],
        last_seq=value["last_seq"],
        messages=messages,
        first_seq=value.get("first_seq"),
    )


def parse_room_window_for_request(
    value: object,
    *,
    requested_room: str,
    requested_limit: int,
    since: int | None = None,
) -> RoomWindow:
    """Parse a room window and bind it to the request that produced it.

    Invalid local request arguments raise ``TypeError`` or ``ValueError`` before
    remote data is parsed. Response/request mismatches raise stable,
    non-echoing ``ProtocolDecodeError`` categories.
    """
    if type(requested_room) is not str:
        raise TypeError("requested_room must be a string")
    if not requested_room:
        raise ValueError("requested_room must not be empty")
    if type(requested_limit) is not int:
        raise TypeError("requested_limit must be an integer")
    if not 1 <= requested_limit <= 200:
        raise ValueError("requested_limit must be between 1 and 200")
    if since is not None and type(since) is not int:
        raise TypeError("since must be an integer or None")
    if since is not None and (since < 0 or since > MAX_REQUEST_SEQUENCE):
        raise ValueError("since must be non-negative and at most 64 digits")

    window = parse_room_window(value)
    if window.room != requested_room:
        raise ProtocolDecodeError("room window does not match requested room")
    if not 0 <= window.count <= requested_limit:
        raise ProtocolDecodeError("room window count is outside requested limit")
    if any(message.seq <= 0 for message in window.messages):
        raise ProtocolDecodeError("room window contains nonpositive message sequence")
    if since is not None and any(message.seq <= since for message in window.messages):
        raise ProtocolDecodeError("room window contains non-incremental message")
    if any(
        current.seq != previous.seq + 1
        for previous, current in zip(window.messages, window.messages[1:])
    ):
        raise ProtocolDecodeError("room window messages are not contiguous")
    if window.messages:
        if window.last_seq != window.messages[-1].seq:
            raise ProtocolDecodeError(
                "room window last sequence does not match messages"
            )
        if window.first_seq is not None and window.first_seq != window.messages[0].seq:
            raise ProtocolDecodeError(
                "room window first sequence does not match messages"
            )
        expected_first = (since if since is not None else 0) + 1
        leading_gap = window.messages[0].seq > expected_first
    else:
        leading_gap = False
    return replace(window, leading_gap=leading_gap)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolDecodeError("JSON object contains a duplicate key")
        result[key] = value
    return result


def _reject_nonfinite_constant(_constant: str) -> NoReturn:
    raise ProtocolDecodeError("JSON document contains a non-finite number")


def _parse_finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise ProtocolDecodeError("JSON document contains a non-finite number")
    return value


def _parse_bounded_int(token: str) -> int:
    digit_count = len(token) - (token.startswith("-"))
    if digit_count > 64:
        raise ProtocolDecodeError("JSON integer exceeds digit limit")
    return int(token)


def _validate_unicode_scalars(value: object) -> None:
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            if any(0xD800 <= ord(character) <= 0xDFFF for character in current):
                raise ProtocolDecodeError(
                    "JSON document contains a non-scalar Unicode value"
                )
        elif isinstance(current, list):
            pending.extend(current)
        elif isinstance(current, dict):
            pending.extend(current.keys())
            pending.extend(current.values())


_STRICT_DECODER = json.JSONDecoder(
    object_pairs_hook=_reject_duplicate_keys,
    parse_constant=_reject_nonfinite_constant,
    parse_float=_parse_finite_float,
    parse_int=_parse_bounded_int,
)


def decode_strict_json(
    data: bytes | bytearray | memoryview,
    *,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
) -> object:
    """Decode one strict JSON value from bounded bytes-like input.

    ``bytes``, ``bytearray``, and ``memoryview`` are accepted. The byte limit
    is checked before UTF-8 decoding. JSON whitespace may surround the value,
    while duplicate object keys, non-finite constants, and trailing data are
    rejected.
    """
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool):
        raise TypeError("max_bytes must be an integer")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes, bytearray, or memoryview")

    try:
        view = memoryview(data)
    except (TypeError, ValueError):
        raise ProtocolDecodeError("invalid bytes-like input") from None

    try:
        try:
            byte_length = view.nbytes
        except (TypeError, ValueError):
            raise ProtocolDecodeError("invalid bytes-like input") from None
        if byte_length > max_bytes:
            raise ProtocolDecodeError("JSON input exceeds byte limit")
        try:
            encoded = view.tobytes()
        except (TypeError, ValueError):
            raise ProtocolDecodeError("invalid bytes-like input") from None
    finally:
        view.release()

    text = encoded.decode("utf-8")
    try:
        value = _STRICT_DECODER.decode(text)
    except json.JSONDecodeError:
        raise ProtocolDecodeError("invalid JSON document") from None
    except RecursionError:
        raise ProtocolDecodeError("JSON document exceeds nesting limit") from None

    _validate_unicode_scalars(value)
    return value
