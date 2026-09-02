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
    coverage_gap = first_seq is not None and first_seq > previous_seq + 1
    missing_sequence_count = (
        first_seq - previous_seq - 1
        if first_seq is not None and coverage_gap
        else 0
    )

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
