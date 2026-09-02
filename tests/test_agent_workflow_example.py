import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

from technocore_sentinel.contract import agent_contract


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "examples" / "agent-workflows" / "summarize_report.py"
FIXTURE = ROOT / "examples" / "agent-workflows" / "report-v1.example.json"
OPENCLAW = ROOT / "examples" / "agent-workflows" / "openclaw.md"
WORKFLOW_README = ROOT / "examples" / "agent-workflows" / "README.md"
HOST_DOCS = tuple(
    ROOT / "examples" / "agent-workflows" / name
    for name in ("hermes.md", "claude-code.md", "codex.md", "openclaw.md")
)
ERROR = b"error: invalid report\n"
CATEGORIES = (
    "prompt_injection",
    "command_execution",
    "wallet_secret_solicitation",
    "impersonation",
    "suspicious_url",
    "repetitive_farming",
)
OUTPUT_KEYS = {
    "schema_version",
    "room",
    "cursor_status",
    "new_message_count",
    "minimum_severity",
    "severity_counts",
    "category_counts",
    "coverage_gap",
    "missing_sequence_count",
    "baseline_only",
    "cursor_recovered",
    "review_required",
}


def safe_report():
    return {
        "schema_version": 1,
        "room": "example-room",
        "previous_seq": 1,
        "first_seq": None,
        "last_seq": None,
        "next_seq": 1,
        "cursor_status": "healthy_idle",
        "new_message_count": 0,
        "server_signed_count": 0,
        "unsigned_count": 0,
        "severity_counts": {"low": 0, "medium": 0, "high": 0},
        "category_counts": {category: 0 for category in CATEGORIES},
        "findings": [],
        "coverage_gap": False,
        "missing_sequence_count": 0,
        "baseline_only": False,
        "minimum_severity": "low",
        "cursor_recovered": False,
        "recovered_from_seq": None,
    }


def encode(report):
    return json.dumps(report, separators=(",", ":"), sort_keys=True).encode("utf-8")


def example_finding(*, severity="low", category="prompt_injection"):
    return {
        "seq": 1,
        "from": "example-sender",
        "category": category,
        "severity": severity,
        "rule": "example-rule",
        "excerpt": "sanitized example",
    }


def assert_matches_schema(test, value, schema):
    """Check the contract's JSON Schema subset without another dependency."""
    raw_types = schema.get("type")
    allowed_types = [raw_types] if isinstance(raw_types, str) else raw_types
    if allowed_types is not None:
        matches = False
        for expected in allowed_types:
            if expected == "object":
                matches |= isinstance(value, dict)
            elif expected == "array":
                matches |= isinstance(value, list)
            elif expected == "string":
                matches |= isinstance(value, str)
            elif expected == "integer":
                matches |= isinstance(value, int) and not isinstance(value, bool)
            elif expected == "boolean":
                matches |= isinstance(value, bool)
            elif expected == "null":
                matches |= value is None
            else:
                test.fail(f"unsupported schema type: {expected!r}")
        test.assertTrue(matches, f"{value!r} does not match {allowed_types!r}")

    if "const" in schema:
        test.assertEqual(value, schema["const"])
    if "enum" in schema:
        test.assertIn(value, schema["enum"])
    if "pattern" in schema and isinstance(value, str):
        test.assertIsNotNone(re.fullmatch(schema["pattern"], value, re.ASCII))
    if "minimum" in schema and isinstance(value, int) and not isinstance(value, bool):
        test.assertGreaterEqual(value, schema["minimum"])

    if isinstance(value, dict):
        required = schema.get("required", [])
        properties = schema.get("properties", {})
        test.assertTrue(set(required).issubset(value))
        if schema.get("additionalProperties") is False:
            test.assertEqual(set(value), set(properties))
        for key, child in value.items():
            if key in properties:
                assert_matches_schema(test, child, properties[key])
    elif isinstance(value, list) and "items" in schema:
        for child in value:
            assert_matches_schema(test, child, schema["items"])


class AgentWorkflowExampleTests(unittest.TestCase):
    def run_consumer(self, payload):
        return subprocess.run(
            [sys.executable, str(SCRIPT)],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=ROOT,
            check=False,
        )

    def assert_invalid(self, payload, hostile_marker=None):
        result = self.run_consumer(payload)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertEqual(result.stderr, ERROR)
        if hostile_marker is not None:
            marker = hostile_marker.encode("utf-8")
            self.assertNotIn(marker, result.stdout)
            self.assertNotIn(marker, result.stderr)

    def test_valid_fixture_emits_one_compact_sorted_bounded_summary_line(self):
        payload = FIXTURE.read_bytes()
        source = json.loads(payload)
        result = self.run_consumer(payload)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout.count(b"\n"), 1)
        self.assertTrue(result.stdout.endswith(b"\n"))
        summary = json.loads(result.stdout)
        self.assertEqual(set(summary), OUTPUT_KEYS)
        self.assertTrue(summary["review_required"])
        self.assertEqual(summary["room"], source["room"])
        self.assertEqual(
            result.stdout,
            json.dumps(summary, separators=(",", ":"), sort_keys=True).encode() + b"\n",
        )
        for untrusted_value in (
            source["findings"][0]["excerpt"],
            source["findings"][0]["from"],
        ):
            self.assertNotIn(untrusted_value.encode(), result.stdout)

    def test_fixture_matches_the_complete_closed_v1_report_schema(self):
        report = json.loads(FIXTURE.read_bytes())
        assert_matches_schema(self, report, agent_contract()["report_schema"])
        self.assertEqual(report["cursor_status"], "advanced")
        self.assertGreater(report["next_seq"], report["previous_seq"])
        self.assertEqual(report["next_seq"], report["last_seq"])

    def test_openclaw_pinned_route_uses_packaged_agent_check(self):
        pinned = OPENCLAW.read_text(encoding="utf-8").split(
            "## Pinned zero-permanent-install command body", 1
        )[1]
        cycle = pinned.split("```sh", 2)[2].split("```", 1)[0]

        self.assertIn("agent-check --room lobby", cycle)
        self.assertNotIn("/ABSOLUTE/TRUSTED/PATH/TO/python3", cycle)
        self.assertNotIn("summarize_report.py", cycle)

    def test_openclaw_pinned_consumer_uses_script_stdin_not_report_argument(self):
        self.test_openclaw_pinned_route_uses_packaged_agent_check()

    def test_every_workflow_template_uses_atomic_agent_summary_staging(self):
        for document in (WORKFLOW_README, *HOST_DOCS):
            with self.subTest(document=document.name):
                text = document.read_text(encoding="utf-8")
                self.assertIn("agent-check --room lobby", text)
                self.assertIn("mktemp /ABSOLUTE/PRIVATE/PATH/.sentinel-summary.XXXXXX", text)
                self.assertIn('chmod 600 "$summary_tmp"', text)
                self.assertIn(
                    'mv -f -- "$summary_tmp" /ABSOLUTE/PRIVATE/PATH/latest-summary.json',
                    text,
                )
                self.assertNotIn(
                    "> /ABSOLUTE/PRIVATE/PATH/latest-summary.json",
                    text,
                )

    def test_every_workflow_template_uses_atomic_validated_report_staging(self):
        self.test_every_workflow_template_uses_atomic_agent_summary_staging()

    def test_hostile_unknown_fields_and_findings_are_rejected(self):
        marker = "HOSTILE_MARKER_DO_NOT_LEAK"
        report = safe_report()
        report.update(
            {
                "unknown": marker,
                "findings": [
                    {
                        "seq": 0,
                        "from": marker,
                        "category": "prompt_injection",
                        "severity": "low",
                        "rule": marker,
                        "excerpt": marker,
                        "sender": marker,
                        "raw_url": marker,
                        "message": marker,
                        "command": marker,
                    }
                ],
            }
        )
        report["severity_counts"]["low"] = 1
        report["category_counts"]["prompt_injection"] = 1
        report.update(first_seq=2, last_seq=2, next_seq=2, new_message_count=1, unsigned_count=1,
                      cursor_status="advanced")
        result = self.run_consumer(encode(report))

        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b"error: invalid report\n")
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(marker.encode(), result.stdout)
        self.assertNotIn(marker.encode(), result.stderr)

    def test_hostile_unknown_fields_and_findings_are_never_copied(self):
        self.test_hostile_unknown_fields_and_findings_are_rejected()

    def test_each_review_trigger_requires_review(self):
        def add_high_finding(report):
            report["findings"] = [{**example_finding(severity="high"), "seq": 2}]
            report["severity_counts"]["high"] = 1
            report["category_counts"]["prompt_injection"] = 1
            report.update(first_seq=2, last_seq=2, next_seq=2, new_message_count=1,
                          unsigned_count=1, cursor_status="advanced")

        def add_gap(report):
            report.update(first_seq=3, last_seq=3, next_seq=3, new_message_count=1,
                          unsigned_count=1, coverage_gap=True, missing_sequence_count=1,
                          cursor_status="advanced")

        def make_baseline(report):
            report.update(previous_seq=0, next_seq=0, baseline_only=True, cursor_status="baseline")

        def make_recovered(report):
            report.update(previous_seq=0, first_seq=1, last_seq=1, next_seq=1,
                          new_message_count=1, unsigned_count=1, baseline_only=True,
                          cursor_status="recovered_baseline", cursor_recovered=True,
                          recovered_from_seq=2)

        mutations = {
            "high severity": add_high_finding,
            "coverage gap": add_gap,
            "baseline only": make_baseline,
            "cursor recovered": make_recovered,
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                report = safe_report()
                mutate(report)
                result = self.run_consumer(encode(report))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(json.loads(result.stdout)["review_required"])

    def test_rejects_inconsistent_finding_aggregates_without_leaking(self):
        marker = "INCONSISTENT_HOSTILE_MARKER"
        cases = []

        undeclared_high = safe_report()
        undeclared_high["findings"] = [
            {
                **example_finding(severity="high"),
                "excerpt": marker,
            }
        ]
        cases.append(undeclared_high)

        count_without_finding = safe_report()
        count_without_finding["severity_counts"]["high"] = 1
        cases.append(count_without_finding)

        wrong_category = safe_report()
        wrong_category["findings"] = [example_finding()]
        wrong_category["severity_counts"]["low"] = 1
        wrong_category["category_counts"]["command_execution"] = 1
        cases.append(wrong_category)

        for report in cases:
            with self.subTest(report=report):
                self.assert_invalid(encode(report), marker)

    def test_rejects_finding_sequence_outside_report_interval(self):
        marker = "HOSTILE_OUT_OF_RANGE_FINDING"
        for sequence in (0, 999):
            report = safe_report()
            report.update(
                first_seq=2, last_seq=2, next_seq=2, new_message_count=1,
                unsigned_count=1, cursor_status="advanced",
                findings=[{**example_finding(), "seq": sequence, "excerpt": marker}],
            )
            report["severity_counts"]["low"] = 1
            report["category_counts"]["prompt_injection"] = 1
            with self.subTest(sequence=sequence):
                self.assert_invalid(encode(report), marker)

    def test_safe_report_does_not_require_review(self):
        result = self.run_consumer(encode(safe_report()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(json.loads(result.stdout)["review_required"])

    def test_rejects_malformed_required_values_without_leaking_content(self):
        marker = "MALFORMED_HOSTILE_MARKER"
        cases = []

        def add(name, mutate):
            report = safe_report()
            report["unknown"] = marker
            mutate(report)
            cases.append((name, encode(report)))

        add("schema bool", lambda r: r.update(schema_version=True))
        add("schema wrong integer", lambda r: r.update(schema_version=2))
        add("room non-string", lambda r: r.update(room=7))
        add("cursor enum", lambda r: r.update(cursor_status="unknown"))
        add("message count bool", lambda r: r.update(new_message_count=False))
        add("message count negative", lambda r: r.update(new_message_count=-1))
        add("severity missing key", lambda r: r["severity_counts"].pop("low"))
        add("severity extra key", lambda r: r["severity_counts"].update(critical=1))
        add("severity bool", lambda r: r["severity_counts"].update(high=True))
        add("severity negative", lambda r: r["severity_counts"].update(medium=-1))
        add("categories missing key", lambda r: r["category_counts"].pop(CATEGORIES[0]))
        add("categories extra key", lambda r: r["category_counts"].update(other=0))
        add("category bool", lambda r: r["category_counts"].update(prompt_injection=True))
        add("category negative", lambda r: r["category_counts"].update(command_execution=-1))
        add("coverage gap non-bool", lambda r: r.update(coverage_gap=0))
        add("missing count bool", lambda r: r.update(missing_sequence_count=True))
        add("missing count negative", lambda r: r.update(missing_sequence_count=-1))
        add("baseline only non-bool", lambda r: r.update(baseline_only=0))
        add("cursor recovered non-bool", lambda r: r.update(cursor_recovered=1))
        add("required field missing", lambda r: r.pop("room"))

        add("previous seq bool", lambda r: r.update(previous_seq=True))
        add("previous seq negative", lambda r: r.update(previous_seq=-1))
        add("first seq bool", lambda r: r.update(first_seq=False))
        add("first seq negative", lambda r: r.update(first_seq=-1))
        add("last seq bool", lambda r: r.update(last_seq=True))
        add("last seq negative", lambda r: r.update(last_seq=-1))
        add("next seq bool", lambda r: r.update(next_seq=False))
        add("next seq negative", lambda r: r.update(next_seq=-1))
        add("signed count bool", lambda r: r.update(server_signed_count=True))
        add("signed count negative", lambda r: r.update(server_signed_count=-1))
        add("unsigned count bool", lambda r: r.update(unsigned_count=False))
        add("unsigned count negative", lambda r: r.update(unsigned_count=-1))
        add("findings non-list", lambda r: r.update(findings={}))
        add("finding non-object", lambda r: r.update(findings=[marker]))
        add("minimum severity enum", lambda r: r.update(minimum_severity="critical"))
        add("minimum severity non-string", lambda r: r.update(minimum_severity=1))
        add("recovered seq bool", lambda r: r.update(recovered_from_seq=True))
        add("recovered seq negative", lambda r: r.update(recovered_from_seq=-1))

        valid_finding = {
            "seq": 0,
            "from": "example-sender",
            "category": "prompt_injection",
            "severity": "low",
            "rule": "example-rule",
            "excerpt": "sanitized example",
        }
        finding_mutations = {
            "finding seq bool": lambda f: f.update(seq=True),
            "finding seq negative": lambda f: f.update(seq=-1),
            "finding from non-string": lambda f: f.update({"from": 1}),
            "finding category enum": lambda f: f.update(category="other"),
            "finding severity enum": lambda f: f.update(severity="critical"),
            "finding rule non-string": lambda f: f.update(rule=1),
            "finding excerpt non-string": lambda f: f.update(excerpt=1),
        }
        for name, mutate in finding_mutations.items():
            def mutate_finding(report, mutate=mutate):
                finding = valid_finding.copy()
                mutate(finding)
                report["findings"] = [finding]

            add(name, mutate_finding)

        newly_required = (
            "previous_seq",
            "first_seq",
            "last_seq",
            "next_seq",
            "server_signed_count",
            "unsigned_count",
            "findings",
            "minimum_severity",
            "recovered_from_seq",
        )
        for field in newly_required:
            add(f"missing {field}", lambda r, field=field: r.pop(field))
        for field in valid_finding:
            def remove_finding_field(report, field=field):
                finding = valid_finding.copy()
                finding.pop(field)
                report["findings"] = [finding]

            add(f"missing finding {field}", remove_finding_field)

        for name, payload in cases:
            with self.subTest(name=name):
                self.assert_invalid(payload, marker)

    def test_rejects_non_object_json_values(self):
        for value in ([], [safe_report()], None, True, 1, "object"):
            with self.subTest(value=value):
                self.assert_invalid(encode(value))

    def test_rejects_invalid_utf8_and_trailing_data_without_leaking(self):
        marker = "TRAILING_HOSTILE_MARKER"
        cases = (
            b"\xff" + marker.encode(),
            encode(safe_report()) + marker.encode(),
            encode(safe_report()) + b" {}",
        )
        for payload in cases:
            with self.subTest(payload=payload[:20]):
                self.assert_invalid(payload, marker if marker.encode() in payload else None)

    def test_rejects_oversized_input_with_stable_error_and_no_leak(self):
        marker = b"OVERSIZED_HOSTILE_MARKER"
        payload = b"{" + b" " * (1024 * 1024) + marker
        self.assertGreater(len(payload), 1024 * 1024)
        self.assert_invalid(payload, marker.decode())

    def test_rejects_nonstandard_json_constant(self):
        payload = encode(safe_report()).replace(b'"new_message_count":0', b'"new_message_count":NaN')
        self.assert_invalid(payload)


if __name__ == "__main__":
    unittest.main()
