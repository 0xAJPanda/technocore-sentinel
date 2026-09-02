"""Versioned, deterministic agent contract for monitor JSON reports.

This module performs no I/O or networking.
"""

from __future__ import annotations

from .naming import NAME_PATTERN


SCHEMA_VERSION = 1

_SEVERITIES = ["low", "medium", "high"]
_CATEGORIES = [
    "prompt_injection",
    "command_execution",
    "wallet_secret_solicitation",
    "impersonation",
    "suspicious_url",
    "repetitive_farming",
]
_CURSOR_STATUSES = ["baseline", "advanced", "healthy_idle", "recovered_baseline"]


def _non_negative_integer() -> dict[str, object]:
    return {"type": "integer", "minimum": 0}


def _nullable_non_negative_integer() -> dict[str, object]:
    return {"type": ["integer", "null"], "minimum": 0}


def _count_schema(keys: list[str]) -> dict[str, object]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(keys),
        "properties": {key: _non_negative_integer() for key in keys},
    }


def _report_schema(*, include_room_pattern: bool = True) -> dict[str, object]:
    finding_fields = {
        "seq": _non_negative_integer(),
        "from": {"type": "string"},
        "category": {"type": "string", "enum": list(_CATEGORIES)},
        "severity": {"type": "string", "enum": list(_SEVERITIES)},
        "rule": {"type": "string"},
        "excerpt": {"type": "string"},
    }
    properties: dict[str, object] = {
        "schema_version": {"type": "integer", "const": SCHEMA_VERSION},
        "room": (
            {"type": "string", "pattern": NAME_PATTERN}
            if include_room_pattern
            else {"type": "string"}
        ),
        "previous_seq": _non_negative_integer(),
        "first_seq": _nullable_non_negative_integer(),
        "last_seq": _nullable_non_negative_integer(),
        "next_seq": _non_negative_integer(),
        "new_message_count": _non_negative_integer(),
        "server_signed_count": _non_negative_integer(),
        "unsigned_count": _non_negative_integer(),
        "severity_counts": _count_schema(_SEVERITIES),
        "category_counts": _count_schema(_CATEGORIES),
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": list(finding_fields),
                "properties": finding_fields,
            },
        },
        "coverage_gap": {"type": "boolean"},
        "missing_sequence_count": _non_negative_integer(),
        "baseline_only": {"type": "boolean"},
        "minimum_severity": {"type": "string", "enum": list(_SEVERITIES)},
        "cursor_status": {"type": "string", "enum": list(_CURSOR_STATUSES)},
        "cursor_recovered": {"type": "boolean"},
        "recovered_from_seq": _nullable_non_negative_integer(),
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": list(properties),
        "properties": properties,
    }


def _summary_schema() -> dict[str, object]:
    properties: dict[str, object] = {
        "schema_version": {"type": "integer", "const": SCHEMA_VERSION},
        "room": {"type": "string", "pattern": NAME_PATTERN},
        "cursor_status": {"type": "string", "enum": list(_CURSOR_STATUSES)},
        "new_message_count": _non_negative_integer(),
        "minimum_severity": {"type": "string", "enum": list(_SEVERITIES)},
        "severity_counts": _count_schema(_SEVERITIES),
        "category_counts": _count_schema(_CATEGORIES),
        "coverage_gap": {"type": "boolean"},
        "missing_sequence_count": _non_negative_integer(),
        "baseline_only": {"type": "boolean"},
        "cursor_recovered": {"type": "boolean"},
        "review_required": {"type": "boolean"},
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": list(properties),
        "properties": properties,
    }


def agent_contract() -> dict[str, object]:
    """Return a fresh deterministic description of the agent-facing report."""

    return {
        "schema_version": SCHEMA_VERSION,
        "name": "technocore-sentinel-monitor-report",
        "display_name": "Technocore Room Safety Monitor",
        "integration_purpose": "content-free room safety and coverage gating",
        "commands": ["agent-check", "summarize-report"],
        "origin": "https://technocore.chat",
        "method": "GET",
        "max_reads_per_cycle": 2,
        "max_records_per_response": 200,
        "writes_exposed": False,
        "content_trust": "untrusted_sanitized_heuristics",
        "report_schema": _report_schema(),
        "summary_schema": _summary_schema(),
    }


def monitor_contract() -> dict[str, object]:
    """Return the byte-stable compatibility monitor contract."""

    return {
        "schema_version": SCHEMA_VERSION,
        "name": "technocore-sentinel-monitor-report",
        "origin": "https://technocore.chat",
        "method": "GET",
        "max_reads_per_cycle": 2,
        "max_records_per_response": 200,
        "writes_exposed": False,
        "content_trust": "untrusted_sanitized_heuristics",
        "report_schema": _report_schema(include_room_pattern=False),
    }
