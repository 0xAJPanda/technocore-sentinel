"""Read-only, content-free awareness for tclk/1 room frames."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from .contract import SCHEMA_VERSION
from .protocol import ProtocolDecodeError, decode_strict_json
from .scanner import is_message_signed, validate_room_payload

TCLK_PREFIX = "tclk1 "
TCLK_FRAME_TYPES = (
    "offer",
    "accept",
    "lock",
    "reveal",
    "refund",
    "cancel",
    "receipt",
)
_TCLK_FRAME_TYPE_SET = frozenset(TCLK_FRAME_TYPES)
_TCLK_SUMMARY_KEYS = (
    "schema_version",
    "room",
    "previous_seq",
    "first_seq",
    "last_seq",
    "next_seq",
    "new_message_count",
    "tclk_frame_count",
    "valid_frame_count",
    "malformed_frame_count",
    "unsigned_tclk_count",
    "frame_type_counts",
    "coverage_gap",
    "missing_sequence_count",
    "baseline_only",
    "review_required",
)
_TCLK_SUMMARY_KEY_SET = frozenset(_TCLK_SUMMARY_KEYS)
_TCLK_INTEGER_FIELDS = (
    "previous_seq",
    "next_seq",
    "new_message_count",
    "tclk_frame_count",
    "valid_frame_count",
    "malformed_frame_count",
    "unsigned_tclk_count",
    "missing_sequence_count",
)
_TCLK_BOOLEAN_FIELDS = ("coverage_gap", "baseline_only", "review_required")
_INVALID_TCLK_REPORT = "invalid tclk report"


def _frame_type(text: str) -> str | None:
    """Return a valid tclk frame type, or ``None`` for malformed tclk-like text."""

    if not text.startswith(TCLK_PREFIX):
        return None
    try:
        payload = decode_strict_json(text[len(TCLK_PREFIX):].encode("ascii"))
    except (UnicodeEncodeError, ProtocolDecodeError):
        return None
    if not isinstance(payload, dict) or set(payload) == set():
        return None
    frame_type = payload.get("type")
    if not isinstance(frame_type, str) or frame_type not in _TCLK_FRAME_TYPE_SET:
        return None
    return frame_type


def validate_tclk_summary(
    report: object,
    *,
    requested_room: str,
    expected_previous_seq: int,
) -> dict[str, object]:
    """Validate and detach one closed, content-free tclk summary."""

    def invalid() -> None:
        raise ValueError(_INVALID_TCLK_REPORT)

    if type(requested_room) is not str or type(expected_previous_seq) is not int:
        invalid()
    if expected_previous_seq < 0 or type(report) is not dict:
        invalid()
    untyped_report = cast(dict[object, object], report)
    if (
        not all(type(key) is str for key in untyped_report)
        or set(untyped_report) != _TCLK_SUMMARY_KEY_SET
    ):
        invalid()
    report = cast(dict[str, object], untyped_report)

    if type(report["schema_version"]) is not int or report["schema_version"] != SCHEMA_VERSION:
        invalid()
    if type(report["room"]) is not str or report["room"] != requested_room:
        invalid()
    for field in _TCLK_INTEGER_FIELDS:
        value = report[field]
        if type(value) is not int or value < 0:
            invalid()
    for field in ("first_seq", "last_seq"):
        value = report[field]
        if value is not None and (type(value) is not int or value < 0):
            invalid()
    for field in _TCLK_BOOLEAN_FIELDS:
        if type(report[field]) is not bool:
            invalid()
    if report["previous_seq"] != expected_previous_seq:
        invalid()

    frame_type_counts = report["frame_type_counts"]
    if type(frame_type_counts) is not dict:
        invalid()
    untyped_frame_type_counts = cast(dict[object, object], frame_type_counts)
    if (
        not all(type(key) is str for key in untyped_frame_type_counts)
        or set(untyped_frame_type_counts) != _TCLK_FRAME_TYPE_SET
    ):
        invalid()
    frame_type_counts = cast(dict[str, object], untyped_frame_type_counts)
    for frame_type in TCLK_FRAME_TYPES:
        value = frame_type_counts[frame_type]
        if type(value) is not int or value < 0:
            invalid()

    previous_seq = cast(int, report["previous_seq"])
    first_seq = cast(int | None, report["first_seq"])
    last_seq = cast(int | None, report["last_seq"])
    next_seq = cast(int, report["next_seq"])
    new_message_count = cast(int, report["new_message_count"])
    tclk_frame_count = cast(int, report["tclk_frame_count"])
    valid_frame_count = cast(int, report["valid_frame_count"])
    malformed_frame_count = cast(int, report["malformed_frame_count"])
    unsigned_tclk_count = cast(int, report["unsigned_tclk_count"])
    missing_sequence_count = cast(int, report["missing_sequence_count"])
    coverage_gap = cast(bool, report["coverage_gap"])

    if not 0 <= new_message_count <= 200:
        invalid()
    if not 0 <= tclk_frame_count <= new_message_count:
        invalid()
    if valid_frame_count + malformed_frame_count != tclk_frame_count:
        invalid()
    if not 0 <= unsigned_tclk_count <= tclk_frame_count:
        invalid()
    if sum(cast(dict[str, int], frame_type_counts).values()) != valid_frame_count:
        invalid()

    if new_message_count == 0:
        if (
            first_seq is not None
            or last_seq is not None
            or next_seq != previous_seq
            or missing_sequence_count != 0
            or coverage_gap
            or tclk_frame_count != 0
            or valid_frame_count != 0
            or malformed_frame_count != 0
            or unsigned_tclk_count != 0
            or any(cast(dict[str, int], frame_type_counts).values())
        ):
            invalid()
    else:
        if first_seq is None or last_seq is None:
            invalid()
        if not previous_seq < first_seq <= last_seq or next_seq != last_seq:
            invalid()
        interval = last_seq - previous_seq
        visible_interval = cast(int, last_seq) - cast(int, first_seq) + 1
        if new_message_count > interval or new_message_count > visible_interval:
            invalid()
        expected_missing = interval - new_message_count
        if missing_sequence_count != expected_missing or coverage_gap != (expected_missing > 0):
            invalid()

    if report["baseline_only"] != (previous_seq == 0):
        invalid()
    if report["review_required"] != bool(
        coverage_gap or malformed_frame_count or unsigned_tclk_count
    ):
        invalid()

    snapshot = {key: report[key] for key in _TCLK_SUMMARY_KEYS}
    snapshot["frame_type_counts"] = {
        frame_type: frame_type_counts[frame_type]
        for frame_type in TCLK_FRAME_TYPES
    }
    return snapshot


def summarize_tclk_room_payload(payload: object, previous_seq: int) -> dict[str, object]:
    """Return a content-free tclk/1 awareness summary for new room messages.

    The function validates the same bounded Technocore room envelope used by the
    monitor, scans only records newer than ``previous_seq``, recognizes exact
    ``tclk1 `` frame prefixes, and reports aggregate counts only. It never emits
    frame bodies, DIDs, signatures, secrets, contract ids, rails, URLs, or sender
    values.
    """

    if isinstance(previous_seq, bool) or not isinstance(previous_seq, int) or previous_seq < 0:
        raise ValueError("previous_seq must be a non-negative integer")

    room, messages = validate_room_payload(payload)
    new_messages = tuple(
        message
        for message in messages
        if cast(int, message.get("seq")) > previous_seq
    )
    sequences = [cast(int, message.get("seq")) for message in new_messages]
    first_seq = sequences[0] if sequences else None
    last_seq = sequences[-1] if sequences else None
    next_seq = last_seq if last_seq is not None else previous_seq
    missing_sequence_count = (
        last_seq - previous_seq - len(new_messages)
        if last_seq is not None
        else 0
    )
    coverage_gap = missing_sequence_count > 0

    frame_type_counts = {frame_type: 0 for frame_type in TCLK_FRAME_TYPES}
    tclk_frame_count = 0
    valid_frame_count = 0
    malformed_frame_count = 0
    unsigned_tclk_count = 0

    for message in new_messages:
        text = cast(str, message.get("text"))
        if not text.startswith(TCLK_PREFIX):
            continue
        tclk_frame_count += 1
        if not is_message_signed(cast(Mapping[str, object], message)):
            unsigned_tclk_count += 1
        frame_type = _frame_type(text)
        if frame_type is None:
            malformed_frame_count += 1
        else:
            valid_frame_count += 1
            frame_type_counts[frame_type] += 1

    review_required = bool(
        coverage_gap
        or malformed_frame_count
        or unsigned_tclk_count
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "room": room,
        "previous_seq": previous_seq,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "next_seq": next_seq,
        "new_message_count": len(new_messages),
        "tclk_frame_count": tclk_frame_count,
        "valid_frame_count": valid_frame_count,
        "malformed_frame_count": malformed_frame_count,
        "unsigned_tclk_count": unsigned_tclk_count,
        "frame_type_counts": frame_type_counts,
        "coverage_gap": coverage_gap,
        "missing_sequence_count": missing_sequence_count,
        "baseline_only": previous_seq == 0,
        "review_required": review_required,
    }
