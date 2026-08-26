"""Tests for dry-run gating, rendering, and secure CLI state."""

from __future__ import annotations

from io import StringIO
import json
from pathlib import Path
import stat
import tempfile
import threading
import time
import unittest
from unittest import mock

from technocore_sentinel.cli import (
    _STATE_JOURNAL,
    _commit_state,
    _locked_state,
    _read_json_at,
    _write_json_at,
    run,
)
from technocore_sentinel.client import MessageReceipt
from technocore_sentinel.identity import derive_did_key, sign_message


class FakeClient:
    def __init__(self) -> None:
        self.posts = 0
        self.prior_last_seq: int | None = None

    def scan_room(self, room: str, *, limit: int) -> dict[str, object]:
        return {
            "room": room,
            "first_seq": 1,
            "last_seq": 2,
            "scanned_count": 2,
            "signed_count": 1,
            "unsigned_count": 1,
            "severity_counts": {"low": 0, "medium": 0, "high": 1},
            "category_counts": {"prompt_injection": 1},
            "examples": {"prompt_injection": [{"seq": 2, "from": "x", "severity": "high", "rule": "rule", "excerpt": "excerpt"}]},
        }

    def get_room(self, room: str, *, limit: int) -> dict[str, object]:
        return {"room": room, "messages": [{"seq": 4, "from": "x", "text": "old"}]}

    def post_signed_message(self, room: str, signed: object, authorization: object, *, prior_last_seq: int) -> MessageReceipt:
        self.posts += 1
        self.prior_last_seq = prior_last_seq
        return MessageReceipt(signed.did, room, 5, "2026-01-01T00:00:00Z", signed.nonce, signed.text)  # type: ignore[attr-defined]


class CLITests(unittest.TestCase):
    def key(self, root: Path) -> Path:
        root.chmod(0o700)
        key = root / "identity.key"
        key.write_bytes(bytes(32))
        key.chmod(0o600)
        return key

    def test_identity_init_and_show_print_public_data_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            key = Path(temporary) / "private" / "identity.key"
            output = StringIO()
            with mock.patch("technocore_sentinel.identity.secrets.token_bytes", return_value=bytes(32)):
                self.assertEqual(run(["identity", "init", "--key-file", str(key)], stdout=output), 0)
            rendered = output.getvalue()
            self.assertIn(derive_did_key(bytes(32)), rendered)
            self.assertIn("profile_path", rendered)
            self.assertNotIn("signature", rendered)
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)

            shown = StringIO()
            run(["identity", "show", "--key-file", str(key)], stdout=shown)
            self.assertEqual(json.loads(shown.getvalue()), json.loads(rendered))

    def test_publish_and_introduce_dry_runs_make_no_client_or_post_and_do_not_persist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = self.key(root)
            nonce = root / "nonce.json"
            signature = sign_message(bytes(32), "lobby", "1", "hello").signature

            def forbidden() -> FakeClient:
                raise AssertionError("dry run must not construct a network client")

            profile_output = StringIO()
            run(
                ["publish-profile", "--key-file", str(key)],
                client_factory=forbidden,  # type: ignore[arg-type]
                stdout=profile_output,
            )
            intro_output = StringIO()
            run(
                ["introduce", "--key-file", str(key), "--nonce-file", str(nonce), "--text", "hello"],
                client_factory=forbidden,  # type: ignore[arg-type]
                stdout=intro_output,
            )
            self.assertFalse(nonce.exists())
            self.assertIn('"dry_run": true', profile_output.getvalue())
            self.assertIn('"method": "POST"', intro_output.getvalue())
            self.assertIn("[redacted]", intro_output.getvalue())
            self.assertNotIn(signature, intro_output.getvalue())
            self.assertNotIn(bytes(32).hex(), profile_output.getvalue() + intro_output.getvalue())

    def test_submit_creates_authorization_and_secure_public_state_only_after_verified_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = self.key(root)
            nonce = root / "nonce.json"
            receipt = root / "receipt.json"
            fake = FakeClient()
            output = StringIO()
            with mock.patch("technocore_sentinel.cli.next_nonce", return_value="123"):
                run(
                    [
                        "introduce", "--key-file", str(key), "--nonce-file", str(nonce),
                        "--receipt-file", str(receipt), "--room", "lobby", "--text", "hello", "--submit",
                    ],
                    client_factory=lambda: fake,  # type: ignore[arg-type]
                    stdout=output,
                )
            self.assertEqual(fake.posts, 1)
            self.assertEqual(stat.S_IMODE(nonce.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(json.loads(nonce.read_text()), {"nonce": "123"})
            receipt_data = json.loads(receipt.read_text())
            self.assertEqual(
                set(receipt_data),
                {"did", "profile_path", "room", "seq", "timestamp", "nonce", "text_hash"},
            )
            self.assertNotIn("sig", receipt.read_text())
            self.assertNotIn("signature", output.getvalue())

    def test_introduction_boundary_includes_all_message_sequence_evidence(self) -> None:
        class InconsistentClient(FakeClient):
            def get_room(self, room: str, *, limit: int) -> dict[str, object]:
                return {
                    "room": room,
                    "last_seq": 0,
                    "messages": [{"seq": 100, "from": "x", "text": "old"}],
                }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = self.key(root)
            fake = InconsistentClient()
            run(
                [
                    "introduce", "--key-file", str(key),
                    "--nonce-file", str(root / "nonce.json"),
                    "--receipt-file", str(root / "receipt.json"),
                    "--text", "hello", "--submit",
                ],
                client_factory=lambda: fake,  # type: ignore[arg-type]
                stdout=StringIO(),
            )
            self.assertEqual(fake.prior_last_seq, 100)

    def test_introduction_boundary_rejects_invalid_message_sequences(self) -> None:
        class InvalidSequenceClient(FakeClient):
            def get_room(self, room: str, *, limit: int) -> dict[str, object]:
                return {"room": room, "last_seq": 10, "messages": [{"seq": True}]}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake = InvalidSequenceClient()
            with self.assertRaises(ValueError):
                run(
                    [
                        "introduce", "--key-file", str(self.key(root)),
                        "--nonce-file", str(root / "nonce.json"),
                        "--receipt-file", str(root / "receipt.json"),
                        "--text", "hello", "--submit",
                    ],
                    client_factory=lambda: fake,  # type: ignore[arg-type]
                    stdout=StringIO(),
                )
            self.assertEqual(fake.posts, 0)

    def test_state_destination_symlinks_are_rejected_before_network(self) -> None:
        for target_name in ("nonce.json", "receipt.json"):
            with self.subTest(target=target_name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                key = self.key(root)
                outside = root / "outside"
                outside.write_text("unchanged", encoding="utf-8")
                outside.chmod(0o600)
                (root / target_name).symlink_to(outside)
                fake = FakeClient()
                with self.assertRaises(ValueError):
                    run(
                        [
                            "introduce", "--key-file", str(key),
                            "--nonce-file", str(root / "nonce.json"),
                            "--receipt-file", str(root / "receipt.json"),
                            "--text", "hello", "--submit",
                        ],
                        client_factory=lambda: fake,  # type: ignore[arg-type]
                        stdout=StringIO(),
                    )
                self.assertEqual(fake.posts, 0)
                self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged")

    def test_partial_commit_is_recovered_and_stale_journal_cannot_roll_back(self) -> None:
        receipt: dict[str, object] = {"nonce": "200", "room": "lobby"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nonce_path = str(root / "nonce.json")
            receipt_path = str(root / "receipt.json")
            real_write = _write_json_at
            failed = False

            def interrupt(parent: int, name: str, value: dict[str, object], label: str) -> None:
                nonlocal failed
                if name == "nonce.json" and not failed:
                    failed = True
                    raise OSError("simulated interrupted nonce commit")
                real_write(parent, name, value, label)

            with self.assertRaises(OSError), _locked_state(nonce_path, receipt_path) as state:
                with mock.patch("technocore_sentinel.cli._write_json_at", side_effect=interrupt):
                    _commit_state(*state, {"nonce": "200"}, receipt)
            self.assertTrue((root / _STATE_JOURNAL).exists())
            self.assertEqual(stat.S_IMODE((root / _STATE_JOURNAL).stat().st_mode), 0o600)

            with _locked_state(nonce_path, receipt_path) as (parent, nonce_name, receipt_name):
                self.assertEqual(_read_json_at(parent, nonce_name, "nonce state"), {"nonce": "200"})
                self.assertEqual(_read_json_at(parent, receipt_name, "receipt state"), receipt)
            self.assertFalse((root / _STATE_JOURNAL).exists())

            # Simulate a stale journal left behind after a newer completed write.
            with _locked_state(nonce_path, receipt_path) as (parent, nonce_name, receipt_name):
                real_write(parent, nonce_name, {"nonce": "300"}, "nonce state")
                newer_receipt: dict[str, object] = {"nonce": "300", "room": "lobby"}
                real_write(parent, receipt_name, newer_receipt, "receipt state")
                real_write(
                    parent,
                    _STATE_JOURNAL,
                    {"nonce": {"nonce": "200"}, "receipt": receipt},
                    "state journal",
                )
            with _locked_state(nonce_path, receipt_path) as (parent, nonce_name, receipt_name):
                self.assertEqual(_read_json_at(parent, nonce_name, "nonce state"), {"nonce": "300"})
                self.assertEqual(_read_json_at(parent, receipt_name, "receipt state"), newer_receipt)

    def test_concurrent_submissions_are_serialized_and_state_files_match(self) -> None:
        class BlockingClient(FakeClient):
            def get_room(self, room: str, *, limit: int) -> dict[str, object]:
                with counter_lock:
                    active[0] += 1
                    maximum[0] = max(maximum[0], active[0])
                    entered.set()
                release.wait(2)
                try:
                    return super().get_room(room, limit=limit)
                finally:
                    with counter_lock:
                        active[0] -= 1

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = self.key(root)
            nonce = root / "nonce.json"
            receipt = root / "receipt.json"
            entered = threading.Event()
            release = threading.Event()
            counter_lock = threading.Lock()
            active = [0]
            maximum = [0]
            outputs = [StringIO(), StringIO()]
            errors: list[BaseException] = []
            start = threading.Barrier(3)

            def submit(index: int) -> None:
                try:
                    start.wait()
                    run(
                        [
                            "introduce", "--key-file", str(key),
                            "--nonce-file", str(nonce), "--receipt-file", str(receipt),
                            "--text", f"hello {index}", "--submit",
                        ],
                        client_factory=BlockingClient,  # type: ignore[arg-type]
                        stdout=outputs[index],
                    )
                except BaseException as error:
                    errors.append(error)

            threads = [threading.Thread(target=submit, args=(index,)) for index in range(2)]
            for thread in threads:
                thread.start()
            start.wait()
            self.assertTrue(entered.wait(1))
            time.sleep(0.05)
            self.assertEqual(maximum[0], 1)
            release.set()
            for thread in threads:
                thread.join(2)
            self.assertFalse(errors)
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            committed = json.loads(nonce.read_text(encoding="utf-8"))["nonce"]
            receipt_data = json.loads(receipt.read_text(encoding="utf-8"))
            returned = [json.loads(output.getvalue().splitlines()[-1])["nonce"] for output in outputs]
            self.assertEqual(len(set(returned)), 2)
            self.assertEqual(committed, max(returned, key=int))
            self.assertEqual(receipt_data["nonce"], committed)
            self.assertEqual(stat.S_IMODE((root / ".introduce.lock").stat().st_mode), 0o600)

    def test_scan_text_and_json_render_use_get_digest(self) -> None:
        fake = FakeClient()
        text = StringIO()
        run(["scan", "--room", "lobby", "--limit", "2"], client_factory=lambda: fake, stdout=text)  # type: ignore[arg-type]
        self.assertIn("messages: 2", text.getvalue())
        self.assertIn("prompt_injection examples", text.getvalue())
        self.assertIn("heuristics", text.getvalue())

        rendered_json = StringIO()
        run(["scan", "--format", "json"], client_factory=lambda: fake, stdout=rendered_json)  # type: ignore[arg-type]
        self.assertEqual(json.loads(rendered_json.getvalue())["scanned_count"], 2)


if __name__ == "__main__":
    unittest.main()
