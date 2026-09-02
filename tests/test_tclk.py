"""Executable specifications for read-only tclk frame awareness."""

import json
import unittest

from technocore_sentinel.tclk import TCLK_FRAME_TYPES, summarize_tclk_room_payload


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

    def test_frame_type_counts_are_closed_and_json_serializable(self) -> None:
        report = summarize_tclk_room_payload(self.payload(), previous_seq=0)
        self.assertEqual(tuple(report["frame_type_counts"]), TCLK_FRAME_TYPES)  # type: ignore[arg-type]
        self.assertEqual(set(report["frame_type_counts"].values()), {0})  # type: ignore[union-attr]
        self.assertFalse(report["review_required"])
        json.dumps(report, sort_keys=True)


if __name__ == "__main__":
    unittest.main()
