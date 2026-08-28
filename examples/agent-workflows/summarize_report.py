#!/usr/bin/env python3
"""Validate a Sentinel v1 report and emit a safe decision summary."""

import json
import sys


MAX_INPUT_BYTES = 1024 * 1024
ERROR_MESSAGE = "error: invalid report\n"
CURSOR_STATUSES = frozenset(
    {"baseline", "advanced", "healthy_idle", "recovered_baseline"}
)
SEVERITIES = frozenset({"low", "medium", "high"})
CATEGORIES = frozenset(
    {
        "prompt_injection",
        "command_execution",
        "wallet_secret_solicitation",
        "impersonation",
        "suspicious_url",
        "repetitive_farming",
    }
)
REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "room",
        "previous_seq",
        "first_seq",
        "last_seq",
        "next_seq",
        "new_message_count",
        "server_signed_count",
        "unsigned_count",
        "severity_counts",
        "category_counts",
        "findings",
        "coverage_gap",
        "missing_sequence_count",
        "baseline_only",
        "minimum_severity",
        "cursor_status",
        "cursor_recovered",
        "recovered_from_seq",
    }
)
FINDING_FIELDS = frozenset(
    {"seq", "from", "category", "severity", "rule", "excerpt"}
)


class InvalidReport(ValueError):
    """A content-free signal that the input report is invalid."""


def _reject_constant(_value):
    raise InvalidReport


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidReport
        result[key] = value
    return result


def _nonnegative_integer(value):
    return type(value) is int and value >= 0


def _count_object(value, expected_keys):
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise InvalidReport
    if any(not _nonnegative_integer(count) for count in value.values()):
        raise InvalidReport
    return value.copy()


def _nullable_nonnegative_integer(value):
    return value is None or _nonnegative_integer(value)


def _validate_finding(finding):
    if not isinstance(finding, dict) or not FINDING_FIELDS.issubset(finding):
        raise InvalidReport
    if not _nonnegative_integer(finding["seq"]):
        raise InvalidReport
    for field in ("from", "rule", "excerpt"):
        if not isinstance(finding[field], str):
            raise InvalidReport
    if finding["category"] not in CATEGORIES:
        raise InvalidReport
    if finding["severity"] not in SEVERITIES:
        raise InvalidReport


def _summary(report):
    if not isinstance(report, dict) or not REQUIRED_FIELDS.issubset(report):
        raise InvalidReport
    if type(report.get("schema_version")) is not int or report["schema_version"] != 1:
        raise InvalidReport
    if not isinstance(report.get("room"), str):
        raise InvalidReport
    if report["cursor_status"] not in CURSOR_STATUSES:
        raise InvalidReport
    if report["minimum_severity"] not in SEVERITIES:
        raise InvalidReport

    integer_fields = (
        "previous_seq",
        "next_seq",
        "new_message_count",
        "server_signed_count",
        "unsigned_count",
        "missing_sequence_count",
    )
    if any(not _nonnegative_integer(report[field]) for field in integer_fields):
        raise InvalidReport
    nullable_integer_fields = ("first_seq", "last_seq", "recovered_from_seq")
    if any(
        not _nullable_nonnegative_integer(report[field])
        for field in nullable_integer_fields
    ):
        raise InvalidReport

    severity_counts = _count_object(report["severity_counts"], SEVERITIES)
    category_counts = _count_object(report["category_counts"], CATEGORIES)

    findings = report["findings"]
    if not isinstance(findings, list):
        raise InvalidReport
    observed_severity_counts = {severity: 0 for severity in SEVERITIES}
    observed_category_counts = {category: 0 for category in CATEGORIES}
    for finding in findings:
        _validate_finding(finding)
        observed_severity_counts[finding["severity"]] += 1
        observed_category_counts[finding["category"]] += 1
    if (
        observed_severity_counts != severity_counts
        or observed_category_counts != category_counts
    ):
        raise InvalidReport

    for field in ("coverage_gap", "baseline_only", "cursor_recovered"):
        if type(report[field]) is not bool:
            raise InvalidReport

    review_required = (
        severity_counts["high"] > 0
        or report["coverage_gap"]
        or report["baseline_only"]
        or report["cursor_recovered"]
    )
    return {
        "schema_version": report["schema_version"],
        "room": report["room"],
        "cursor_status": report["cursor_status"],
        "new_message_count": report["new_message_count"],
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "coverage_gap": report["coverage_gap"],
        "missing_sequence_count": report["missing_sequence_count"],
        "baseline_only": report["baseline_only"],
        "cursor_recovered": report["cursor_recovered"],
        "review_required": review_required,
    }


def main():
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(payload) > MAX_INPUT_BYTES:
            raise InvalidReport
        text = payload.decode("utf-8", errors="strict")
        report = json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
        summary = _summary(report)
        output = json.dumps(summary, separators=(",", ":"), sort_keys=True)
    except Exception:
        sys.stderr.write(ERROR_MESSAGE)
        return 1

    sys.stdout.write(output + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
