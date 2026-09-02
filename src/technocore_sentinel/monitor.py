"""Pure incremental reporting for validated Technocore room payloads.

This module performs no I/O. URLs in untrusted content are handled only by the
scanner's local matching and display-redaction logic.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from .contract import SCHEMA_VERSION
from .scanner import (
    ScanCategory,
    Severity,
    is_message_signed,
    sanitize_display,
    scan_text,
    validate_room_payload,
)


def monitor_room_payload(payload: object, previous_seq: int) -> dict[str, object]:
    """Validate *payload* and report only messages newer than *previous_seq*.

    The complete room payload is shallowly schema-validated, including its
    aggregate text budget, ordered sequences, optional protocol metadata, and
    display attributions before any message text is scanned.  The
    ``server_signed_count`` is recognized server-exposed signed-lane marker
    evidence; it is not independent live cryptographic signature verification.
    The function is deterministic and has no external side effects.
    """

    if isinstance(previous_seq, bool) or not isinstance(previous_seq, int) or previous_seq < 0:
        raise ValueError("previous_seq must be a non-negative integer")

    if isinstance(payload, Mapping):
        raw_messages = payload.get("messages")
        raw_last_seq = payload.get("last_seq")
        if (
            isinstance(raw_messages, list)
            and not raw_messages
            and "last_seq" in payload
            and isinstance(raw_last_seq, int)
            and not isinstance(raw_last_seq, bool)
            and raw_last_seq >= 0
            and raw_last_seq != previous_seq
        ):
            raise ValueError(
                "empty payload last_seq must equal previous_seq for an incremental monitor response"
            )

    room, messages = validate_room_payload(payload)
    new_messages = tuple(
        message
        for message in messages
        if cast(int, message.get("seq")) > previous_seq
    )

    category_counts = {category.value: 0 for category in ScanCategory}
    severity_counts = {severity.value: 0 for severity in Severity}
    findings: list[dict[str, object]] = []
    sequences: list[int] = []
    server_signed_count = 0

    for message in new_messages:
        seq = cast(int, message.get("seq"))
        sender = cast(str, message.get("from"))
        text = cast(str, message.get("text"))
        sequences.append(seq)
        if is_message_signed(message):
            server_signed_count += 1

        sanitized_sender = sanitize_display(sender)
        for finding in scan_text(text):
            category = finding.category.value
            severity = finding.severity.value
            category_counts[category] += 1
            severity_counts[severity] += 1
            findings.append(
                {
                    "seq": seq,
                    "from": sanitized_sender,
                    "category": category,
                    "severity": severity,
                    "rule": finding.rule,
                    "excerpt": finding.excerpt,
                }
            )

    first_seq = sequences[0] if sequences else None
    last_seq = sequences[-1] if sequences else None
    next_seq = last_seq if last_seq is not None else previous_seq
    coverage_gap = first_seq is not None and first_seq > previous_seq + 1
    missing_sequence_count = (
        first_seq - previous_seq - 1
        if first_seq is not None and coverage_gap
        else 0
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "room": room,
        "previous_seq": previous_seq,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "next_seq": next_seq,
        "new_message_count": len(new_messages),
        "server_signed_count": server_signed_count,
        "unsigned_count": len(new_messages) - server_signed_count,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "findings": findings,
        "coverage_gap": coverage_gap,
        "missing_sequence_count": missing_sequence_count,
        "baseline_only": previous_seq == 0,
    }
