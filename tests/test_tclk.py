"""Executable specifications for read-only tclk frame awareness."""

import json
import unittest

from technocore_sentinel.tclk import (
    TCLK_FRAME_TYPES,
    summarize_tclk_room_payload,
    validate_tclk_summary,
)


LIVE_DID = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"


def frame(frame_type: str, **extra: object) -> str:
    payload = {"type": frame_type, **extra}
    return "tclk1 " + json.dumps(payload, sort_keys=True, separators=(",", ":"))


class TclkAwarenessTests(unittest.TestCase):
    @staticmethod
    def payload(*messages: dict[str, object], room: str = "tclk-offers") -> dict[str, object]:
        return {"room": room, "count": len(messages), "messages": list(messages)}

    def test_counts_valid_frame_types_without_exposing_frame_content(self) -> None:
        report = summarize_tclk_room_payload(
            self.payload(
                {"seq": 1, "from": LIVE_DID, "nonce": 10, "text": frame("offer", id="0x" + "a" * 64)},
                {"seq": 2, "from": LIVE_DID, "nonce": 11, "text": frame("accept", ref="0x" + "b" * 64)},
                {"seq": 3, "from": "anon", "text": "ordinary room chatter"},
            ),
            previous_seq=0,
        )

        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["room"], "tclk-offers")
        self.assertEqual(report["new_message_count"], 3)
        self.assertEqual(report["tclk_frame_count"], 2)
        self.assertEqual(report["valid_frame_count"], 2)
        self.assertEqual(report["malformed_frame_count"], 0)
        self.assertEqual(report["unsigned_tclk_count"], 0)
        self.assertEqual(report["frame_type_counts"]["offer"], 1)  # type: ignore[index]
        self.assertEqual(report["frame_type_counts"]["accept"], 1)  # type: ignore[index]
        self.assertFalse(report["review_required"])
        rendered = json.dumps(report, sort_keys=True)
        self.assertNotIn("aaaaaaaa", rendered)
        self.assertNotIn("bbbbbbbb", rendered)
        self.assertNotIn(LIVE_DID, rendered)

    def test_malformed_unknown_and_unsigned_tclk_like_messages_require_review(self) -> None:
        report = summarize_tclk_room_payload(
            self.payload(
                {"seq": 5, "from": "anon", "text": frame("offer")},
                {"seq": 6, "from": LIVE_DID, "nonce": 12, "text": "tclk1 {not json"},
                {"seq": 7, "from": LIVE_DID, "nonce": 13, "text": frame("steal")},
            ),
            previous_seq=4,
        )

        self.assertEqual(report["tclk_frame_count"], 3)
        self.assertEqual(report["valid_frame_count"], 1)
        self.assertEqual(report["malformed_frame_count"], 2)
        self.assertEqual(report["unsigned_tclk_count"], 1)
        self.assertTrue(report["review_required"])

    def test_previous_cursor_filters_old_frames_and_reports_coverage_gap(self) -> None:
        report = summarize_tclk_room_payload(
            self.payload(
                {"seq": 2, "from": LIVE_DID, "nonce": 1, "text": "tclk1 {not json"},
                {"seq": 10, "from": LIVE_DID, "nonce": 2, "text": frame("receipt")},
            ),
            previous_seq=5,
        )

        self.assertEqual(report["first_seq"], 10)
        self.assertEqual(report["last_seq"], 10)
        self.assertEqual(report["next_seq"], 10)
        self.assertEqual(report["tclk_frame_count"], 1)
        self.assertEqual(report["malformed_frame_count"], 0)
        self.assertTrue(report["coverage_gap"])
        self.assertEqual(report["missing_sequence_count"], 4)
        self.assertTrue(report["review_required"])

    def test_internal_sequence_gap_requires_review_without_blocking_cursor(self) -> None:
        report = summarize_tclk_room_payload(
            self.payload(
                {"seq": 6, "from": LIVE_DID, "nonce": 1, "text": frame("offer")},
                {"seq": 8, "from": LIVE_DID, "nonce": 2, "text": frame("accept")},
            ),
            previous_seq=5,
        )

        self.assertTrue(report["coverage_gap"])
        self.assertEqual(report["missing_sequence_count"], 1)
        self.assertTrue(report["review_required"])
        self.assertEqual(report["next_seq"], 8)

    def test_leading_and_internal_sequence_gaps_count_all_missing_positions(self) -> None:
        report = summarize_tclk_room_payload(
            self.payload(
                {"seq": 8, "from": LIVE_DID, "nonce": 1, "text": frame("offer")},
                {"seq": 10, "from": LIVE_DID, "nonce": 2, "text": frame("accept")},
            ),
            previous_seq=5,
        )

        self.assertTrue(report["coverage_gap"])
        self.assertEqual(report["missing_sequence_count"], 3)
        self.assertTrue(report["review_required"])
        self.assertEqual(report["next_seq"], 10)

    def test_frame_type_counts_are_closed_and_json_serializable(self) -> None:
        report = summarize_tclk_room_payload(self.payload(), previous_seq=0)
        self.assertEqual(tuple(report["frame_type_counts"]), TCLK_FRAME_TYPES)  # type: ignore[arg-type]
        self.assertEqual(set(report["frame_type_counts"].values()), {0})  # type: ignore[union-attr]
        self.assertFalse(report["review_required"])
        json.dumps(report, sort_keys=True)


class TclkSummaryValidationTests(unittest.TestCase):
    class IntSpoof(int):
        pass

    class StrSpoof(str):
        pass

    class DictSpoof(dict[str, object]):
        pass

    @staticmethod
    def valid_report(*, previous_seq: int = 0, sequence: int | None = 1) -> dict[str, object]:
        messages = [] if sequence is None else [
            {"seq": sequence, "from": "anon", "text": frame("offer")},
        ]
        return summarize_tclk_room_payload(
            {"room": "tclk-offers", "count": len(messages), "messages": messages},
            previous_seq=previous_seq,
        )

    def assert_invalid(self, report: object, *, previous_seq: int = 0) -> None:
        with self.assertRaisesRegex(ValueError, "^invalid tclk report$"):
            validate_tclk_summary(
                report,
                requested_room="tclk-offers",
                expected_previous_seq=previous_seq,
            )

    def test_returns_detached_exact_plain_dict_snapshot(self) -> None:
        source = self.valid_report()
        validated = validate_tclk_summary(
            source,
            requested_room="tclk-offers",
            expected_previous_seq=0,
        )

        self.assertIs(type(validated), dict)
        self.assertIs(type(validated["frame_type_counts"]), dict)
        self.assertEqual(validated, source)
        self.assertIsNot(validated, source)
        self.assertIsNot(validated["frame_type_counts"], source["frame_type_counts"])

    def test_rejects_non_plain_report_and_unknown_or_missing_fields(self) -> None:
        valid = self.valid_report()
        cases: list[object] = [
            self.DictSpoof(valid),
            {**valid, "secret": "https://hostile.invalid/private"},
            {key: value for key, value in valid.items() if key != "review_required"},
        ]
        for report in cases:
            with self.subTest(report_type=type(report), keys=getattr(report, "keys", lambda: ())()):
                self.assert_invalid(report)

    def test_rejects_wrong_schema_room_or_expected_cursor(self) -> None:
        cases = [
            ("schema", {**self.valid_report(), "schema_version": 2}, "tclk-offers", 0),
            ("room", {**self.valid_report(), "room": "other-room"}, "tclk-offers", 0),
            ("cursor", self.valid_report(), "tclk-offers", 1),
        ]
        for name, report, room, previous_seq in cases:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "^invalid tclk report$"):
                    validate_tclk_summary(
                        report,
                        requested_room=room,
                        expected_previous_seq=previous_seq,
                    )

    def test_rejects_every_field_type_class_and_integer_spoofs(self) -> None:
        integer_fields = (
            "schema_version", "previous_seq", "next_seq", "new_message_count",
            "tclk_frame_count", "valid_frame_count", "malformed_frame_count",
            "unsigned_tclk_count", "missing_sequence_count",
        )
        nullable_integer_fields = ("first_seq", "last_seq")
        boolean_fields = ("coverage_gap", "baseline_only", "review_required")
        mutations: list[tuple[str, object]] = [
            ("room", self.StrSpoof("tclk-offers")),
            ("room", 1),
        ]
        for field in integer_fields:
            mutations.extend(((field, True), (field, self.IntSpoof(1)), (field, "1"), (field, -1)))
        for field in nullable_integer_fields:
            mutations.extend(((field, True), (field, self.IntSpoof(1)), (field, "1"), (field, -1)))
        for field in boolean_fields:
            mutations.append((field, 0))

        for field, value in mutations:
            with self.subTest(field=field, value_type=type(value), value=value):
                report = self.valid_report()
                report[field] = value
                self.assert_invalid(report)

    def test_rejects_frame_count_mapping_key_and_value_defects(self) -> None:
        valid = self.valid_report()
        counts = valid["frame_type_counts"]
        assert isinstance(counts, dict)
        cases: list[object] = [
            self.DictSpoof(counts),
            {**counts, "secret": 0},
            {key: value for key, value in counts.items() if key != "receipt"},
            {**counts, "offer": True},
            {**counts, "offer": self.IntSpoof(1)},
            {**counts, "offer": "1"},
            {**counts, "offer": -1},
        ]
        for defective_counts in cases:
            with self.subTest(value=defective_counts):
                report = dict(valid)
                report["frame_type_counts"] = defective_counts
                self.assert_invalid(report)

    def test_rejects_each_cross_field_contradiction(self) -> None:
        nonempty = self.valid_report(sequence=2)
        empty = self.valid_report(sequence=None)
        cases: list[tuple[str, dict[str, object]]] = []

        def changed(source: dict[str, object], **updates: object) -> dict[str, object]:
            return {**source, **updates}

        cases.extend((
            ("message count maximum", changed(nonempty, new_message_count=201)),
            ("tclk exceeds messages", changed(nonempty, tclk_frame_count=2)),
            ("valid plus malformed", changed(nonempty, malformed_frame_count=1)),
            ("unsigned exceeds tclk", changed(nonempty, unsigned_tclk_count=2)),
            ("frame sum differs", changed(nonempty, valid_frame_count=0)),
            ("empty first", changed(empty, first_seq=1)),
            ("empty last", changed(empty, last_seq=1)),
            ("empty next", changed(empty, next_seq=1)),
            ("empty missing", changed(empty, missing_sequence_count=1)),
            ("empty gap", changed(empty, coverage_gap=True, review_required=True)),
            ("empty aggregate", changed(empty, new_message_count=1)),
            ("first not after previous", changed(nonempty, first_seq=0)),
            ("first after last", changed(nonempty, first_seq=3)),
            ("next differs from last", changed(nonempty, next_seq=1)),
            ("messages exceed interval", changed(nonempty, new_message_count=3)),
            (
                "messages exceed visible interval",
                changed(
                    self.valid_report(sequence=100),
                    new_message_count=100,
                    missing_sequence_count=0,
                    coverage_gap=False,
                ),
            ),
            ("missing differs", changed(nonempty, missing_sequence_count=0)),
            ("gap differs", changed(nonempty, coverage_gap=False)),
            ("baseline differs", changed(nonempty, baseline_only=False)),
            ("review differs", changed(nonempty, review_required=False)),
        ))
        for name, report in cases:
            with self.subTest(name=name):
                self.assert_invalid(report)


if __name__ == "__main__":
    unittest.main()
