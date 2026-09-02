"""Executable specifications for the versioned agent JSON contract."""

from __future__ import annotations

import json
from pathlib import Path
import tomllib
import unittest
from unittest import mock

import technocore_sentinel
from technocore_sentinel.contract import SCHEMA_VERSION, agent_contract
from technocore_sentinel.scanner import ScanCategory, Severity


REPORT_FIELDS = {
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
FINDING_FIELDS = {"seq", "from", "category", "severity", "rule", "excerpt"}


class AgentContractTests(unittest.TestCase):
    def test_fixed_contract_is_deterministic_and_json_serializable(self) -> None:
        with (
            mock.patch("socket.socket", side_effect=AssertionError("network forbidden")),
            mock.patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")),
        ):
            first = agent_contract()
            second = agent_contract()

        self.assertEqual(SCHEMA_VERSION, 1)
        self.assertEqual(first, second)
        self.assertEqual(
            {key: first[key] for key in first if key != "report_schema"},
            {
                "schema_version": 1,
                "name": "technocore-sentinel-monitor-report",
                "origin": "https://technocore.chat",
                "method": "GET",
                "max_reads_per_cycle": 2,
                "max_records_per_response": 200,
                "writes_exposed": False,
                "content_trust": "untrusted_sanitized_heuristics",
            },
        )
        self.assertEqual(json.loads(json.dumps(first, sort_keys=True)), first)

    def test_report_schema_is_closed_complete_and_enumerated(self) -> None:
        schema = agent_contract()["report_schema"]
        self.assertIsInstance(schema, dict)
        self.assertEqual(schema["type"], "object")
        self.assertIs(schema["additionalProperties"], False)
        self.assertEqual(set(schema["required"]), REPORT_FIELDS)
        self.assertEqual(set(schema["properties"]), REPORT_FIELDS)

        properties = schema["properties"]
        self.assertEqual(properties["schema_version"], {"type": "integer", "const": 1})
        self.assertEqual(
            properties["cursor_status"]["enum"],
            ["baseline", "advanced", "healthy_idle", "recovered_baseline"],
        )
        self.assertEqual(properties["minimum_severity"]["enum"], [severity.value for severity in Severity])
        self.assertEqual(
            properties["findings"]["items"]["properties"]["severity"]["enum"],
            [severity.value for severity in Severity],
        )
        categories = [category.value for category in ScanCategory]
        self.assertEqual(properties["findings"]["items"]["properties"]["category"]["enum"], categories)
        self.assertEqual(set(properties["category_counts"]["required"]), set(categories))

        finding = properties["findings"]["items"]
        self.assertIs(finding["additionalProperties"], False)
        self.assertEqual(set(finding["required"]), FINDING_FIELDS)
        self.assertEqual(set(finding["properties"]), FINDING_FIELDS)
        for field in ("first_seq", "last_seq", "recovered_from_seq"):
            self.assertEqual(properties[field]["type"], ["integer", "null"])

    def test_package_version_matches_project_version(self) -> None:
        project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(technocore_sentinel.__version__, project["project"]["version"])
        self.assertEqual(technocore_sentinel.__version__, "0.2.0")


if __name__ == "__main__":
    unittest.main()
