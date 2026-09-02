"""Strict validation and content-free summaries for Sentinel v1 reports.

This module is deterministic, uses only the standard library, and performs no
I/O or networking on import.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import BinaryIO
import json

from .naming import is_valid_name

MAX_INPUT_BYTES = 1024 * 1024

SEVERITIES = ("low", "medium", "high")
CATEGORIES = (
    "prompt_injection",
    "command_execution",
    "wallet_secret_solicitation",
    "impersonation",
    "suspicious_url",
    "repetitive_farming",
)
CURSOR_STATUSES = frozenset(
    {"baseline", "advanced", "healthy_idle", "recovered_baseline"}
)
REQUIRED_FIELDS = frozenset(
    {
        "schema_version", "room", "previous_seq", "first_seq", "last_seq",
        "next_seq", "new_message_count", "server_signed_count", "unsigned_count",
        "severity_counts", "category_counts", "findings", "coverage_gap",
        "missing_sequence_count", "baseline_only", "minimum_severity",
        "cursor_status", "cursor_recovered", "recovered_from_seq",
    }
)
FINDING_FIELDS = frozenset(
    {"seq", "from", "category", "severity", "rule", "excerpt"}
)
_SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}
_SUMMARY_FIELDS = frozenset(
    {
        "schema_version", "room", "cursor_status", "new_message_count",
        "minimum_severity", "severity_counts", "category_counts", "coverage_gap",
        "missing_sequence_count", "baseline_only", "cursor_recovered",
        "review_required",
    }
)


class InvalidReport(ValueError):
    """Content-free signal that a report does not satisfy the v1 contract."""

    def __init__(self) -> None:
        super().__init__("invalid report")


def _invalid(*_args: object) -> InvalidReport:
    return InvalidReport()


def _reject_constant(_value: str) -> object:
    raise _invalid()


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise _invalid()
        value[key] = item
    return value


def _nonnegative_integer(value: object) -> bool:
    return type(value) is int and value >= 0


def _nullable_nonnegative_integer(value: object) -> bool:
    return value is None or _nonnegative_integer(value)


def _count_object(value: object, expected_keys: tuple[str, ...]) -> dict[str, int]:
    if not isinstance(value, dict) or set(value) != set(expected_keys):
        raise _invalid()
    result: dict[str, int] = {}
    for key in expected_keys:
        count = value[key]
        if not _nonnegative_integer(count):
            raise _invalid()
        result[key] = count
    return result


def parse_report_bytes(payload: bytes) -> dict[str, object]:
    """Decode one bounded, duplicate-free UTF-8 JSON object.

    Syntax, encoding, duplicate keys, non-standard constants, trailing data,
    arrays, and scalar roots all fail with the same content-free exception.
    Semantic v1 validation is performed by :func:`summarize_report`.
    """

    if not isinstance(payload, bytes) or len(payload) > MAX_INPUT_BYTES:
        raise _invalid()
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (ValueError, RecursionError) as error:
        raise _invalid() from error
    if not isinstance(value, dict):
        raise _invalid()
    summarize_report(value)
    return value


def _validate_finding(finding: object, minimum_severity: str) -> tuple[int, str, str]:
    if not isinstance(finding, Mapping) or set(finding) != FINDING_FIELDS:
        raise _invalid()
    sequence = finding["seq"]
    if not _nonnegative_integer(sequence):
        raise _invalid()
    for field in ("from", "rule", "excerpt"):
        if not isinstance(finding[field], str):
            raise _invalid()
    category = finding["category"]
    severity = finding["severity"]
    if (
        not isinstance(category, str)
        or category not in CATEGORIES
        or not isinstance(severity, str)
        or severity not in SEVERITIES
    ):
        raise _invalid()
    if _SEVERITY_RANK[severity] < _SEVERITY_RANK[minimum_severity]:
        raise _invalid()
    return sequence, severity, category


def summarize_report(report: object) -> dict[str, object]:
    """Validate a strict v1 report and return a fresh content-free summary."""

    if not isinstance(report, Mapping) or set(report) != REQUIRED_FIELDS:
        raise _invalid()
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise _invalid()
    if not is_valid_name(report["room"]):
        raise _invalid()
    cursor_status = report["cursor_status"]
    minimum_severity = report["minimum_severity"]
    if (
        not isinstance(cursor_status, str)
        or cursor_status not in CURSOR_STATUSES
        or not isinstance(minimum_severity, str)
        or minimum_severity not in SEVERITIES
    ):
        raise _invalid()

    integer_fields = (
        "previous_seq", "next_seq", "new_message_count", "server_signed_count",
        "unsigned_count", "missing_sequence_count",
    )
    if any(not _nonnegative_integer(report[field]) for field in integer_fields):
        raise _invalid()
    if any(
        not _nullable_nonnegative_integer(report[field])
        for field in ("first_seq", "last_seq", "recovered_from_seq")
    ):
        raise _invalid()
    if any(type(report[field]) is not bool for field in ("coverage_gap", "baseline_only", "cursor_recovered")):
        raise _invalid()

    previous_seq = report["previous_seq"]
    first_seq = report["first_seq"]
    last_seq = report["last_seq"]
    next_seq = report["next_seq"]
    new_count = report["new_message_count"]
    signed_count = report["server_signed_count"]
    unsigned_count = report["unsigned_count"]
    missing_count = report["missing_sequence_count"]
    recovered_from = report["recovered_from_seq"]
    assert isinstance(previous_seq, int) and isinstance(next_seq, int)
    assert isinstance(new_count, int) and isinstance(signed_count, int)
    assert isinstance(unsigned_count, int) and isinstance(missing_count, int)

    if signed_count + unsigned_count != new_count:
        raise _invalid()

    severity_counts = _count_object(report["severity_counts"], SEVERITIES)
    category_counts = _count_object(report["category_counts"], CATEGORIES)
    findings = report["findings"]
    if not isinstance(findings, list):
        raise _invalid()
    observed_severity = {key: 0 for key in SEVERITIES}
    observed_category = {key: 0 for key in CATEGORIES}
    finding_sequences: list[int] = []
    for finding in findings:
        sequence, severity, category = _validate_finding(finding, minimum_severity)
        finding_sequences.append(sequence)
        observed_severity[severity] += 1
        observed_category[category] += 1
    if observed_severity != severity_counts or observed_category != category_counts:
        raise _invalid()

    expected_missing = (
        max(first_seq - previous_seq - 1, 0)
        if isinstance(first_seq, int) and not isinstance(first_seq, bool)
        else 0
    )
    if missing_count != expected_missing or report["coverage_gap"] is not (missing_count > 0):
        raise _invalid()

    if new_count == 0:
        if first_seq is not None or last_seq is not None or next_seq != previous_seq:
            raise _invalid()
    else:
        if not (
            isinstance(first_seq, int) and not isinstance(first_seq, bool)
            and isinstance(last_seq, int) and not isinstance(last_seq, bool)
            and previous_seq < first_seq <= last_seq == next_seq
        ):
            raise _invalid()
    if finding_sequences and (
        not isinstance(first_seq, int)
        or not isinstance(last_seq, int)
        or any(sequence < first_seq or sequence > last_seq for sequence in finding_sequences)
    ):
        raise _invalid()

    baseline_only = report["baseline_only"]
    cursor_recovered = report["cursor_recovered"]
    if baseline_only is not (previous_seq == 0):
        raise _invalid()

    if cursor_status == "baseline":
        valid_status = (
            previous_seq == 0 and baseline_only is True
            and cursor_recovered is False and recovered_from is None
        )
    elif cursor_status == "advanced":
        valid_status = (
            previous_seq > 0 and next_seq > previous_seq and new_count >= 1
            and baseline_only is False and cursor_recovered is False
            and recovered_from is None
        )
    elif cursor_status == "healthy_idle":
        valid_status = (
            previous_seq > 0 and next_seq == previous_seq and new_count == 0
            and baseline_only is False and cursor_recovered is False
            and recovered_from is None
        )
    else:
        valid_status = (
            previous_seq == 0 and baseline_only is True and cursor_recovered is True
            and isinstance(recovered_from, int) and not isinstance(recovered_from, bool)
            and recovered_from > next_seq
        )
    if not valid_status:
        raise _invalid()

    review_required = (
        any(count > 0 for count in severity_counts.values())
        or report["coverage_gap"] is True
        or baseline_only is True
        or cursor_recovered is True
    )
    return {
        "schema_version": 1,
        "room": report["room"],
        "cursor_status": cursor_status,
        "new_message_count": new_count,
        "minimum_severity": minimum_severity,
        "severity_counts": dict(severity_counts),
        "category_counts": dict(category_counts),
        "coverage_gap": report["coverage_gap"],
        "missing_sequence_count": missing_count,
        "baseline_only": baseline_only,
        "cursor_recovered": cursor_recovered,
        "review_required": review_required,
    }


def _normalize_summary(summary: object) -> dict[str, object]:
    """Validate summary schema and semantics, returning only copied safe data."""

    if not isinstance(summary, Mapping) or set(summary) != _SUMMARY_FIELDS:
        raise _invalid()
    if type(summary["schema_version"]) is not int or summary["schema_version"] != 1:
        raise _invalid()

    room = summary["room"]
    cursor_status = summary["cursor_status"]
    minimum_severity = summary["minimum_severity"]
    if (
        not is_valid_name(room)
        or type(cursor_status) is not str
        or cursor_status not in CURSOR_STATUSES
        or type(minimum_severity) is not str
        or minimum_severity not in SEVERITIES
    ):
        raise _invalid()

    new_count = summary["new_message_count"]
    missing_count = summary["missing_sequence_count"]
    if not _nonnegative_integer(new_count) or not _nonnegative_integer(missing_count):
        raise _invalid()

    boolean_fields = (
        "coverage_gap", "baseline_only", "cursor_recovered", "review_required",
    )
    if any(type(summary[field]) is not bool for field in boolean_fields):
        raise _invalid()

    severity_counts = _count_object(summary["severity_counts"], SEVERITIES)
    category_counts = _count_object(summary["category_counts"], CATEGORIES)
    if sum(severity_counts.values()) != sum(category_counts.values()):
        raise _invalid()

    coverage_gap = summary["coverage_gap"]
    baseline_only = summary["baseline_only"]
    cursor_recovered = summary["cursor_recovered"]
    if coverage_gap is not (missing_count > 0):
        raise _invalid()

    if cursor_status == "baseline":
        valid_cursor_flags = baseline_only is True and cursor_recovered is False
    elif cursor_status == "recovered_baseline":
        valid_cursor_flags = baseline_only is True and cursor_recovered is True
    elif cursor_status == "healthy_idle":
        valid_cursor_flags = (
            baseline_only is False and cursor_recovered is False and new_count == 0
        )
    else:
        valid_cursor_flags = (
            baseline_only is False and cursor_recovered is False and new_count > 0
        )
    if not valid_cursor_flags:
        raise _invalid()

    review_required = (
        any(count > 0 for count in severity_counts.values())
        or coverage_gap is True
        or baseline_only is True
        or cursor_recovered is True
    )
    if summary["review_required"] is not review_required:
        raise _invalid()

    return {
        "schema_version": 1,
        "room": room,
        "cursor_status": cursor_status,
        "new_message_count": new_count,
        "minimum_severity": minimum_severity,
        "severity_counts": dict(severity_counts),
        "category_counts": dict(category_counts),
        "coverage_gap": coverage_gap,
        "missing_sequence_count": missing_count,
        "baseline_only": baseline_only,
        "cursor_recovered": cursor_recovered,
        "review_required": review_required,
    }


def render_summary(summary: object) -> str:
    """Validate and compactly render a safe summary without adding a newline."""

    try:
        normalized = _normalize_summary(summary)
        return json.dumps(normalized, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except InvalidReport:
        raise
    except Exception as error:
        raise _invalid() from error


def summarize_stdin(stdin: BinaryIO) -> str:
    """Read at most MAX+1 bytes and return one rendered safe summary."""

    try:
        payload = stdin.read(MAX_INPUT_BYTES + 1)
    except Exception as error:
        raise _invalid() from error
    if not isinstance(payload, bytes) or len(payload) > MAX_INPUT_BYTES:
        raise _invalid()
    return render_summary(summarize_report(parse_report_bytes(payload)))


__all__ = [
    "InvalidReport", "MAX_INPUT_BYTES", "parse_report_bytes", "summarize_report",
    "render_summary", "summarize_stdin",
]
