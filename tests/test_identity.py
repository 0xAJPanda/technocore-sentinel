"""Executable specifications for Sentinel identity and signing."""

import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unicodedata
import unittest
from unittest import mock

from technocore_sentinel.identity import (
    MESSAGE_MAX_LENGTH,
    NOTE_MAX_LENGTH,
    SignedMessage,
    create_identity,
    derive_did_key,
    load_identity,
    next_nonce,
    profile_location,
    sign_canonical,
    sign_message,
    sweep_text,
    sweep_unicode,
)


ZERO_SEED_DID = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
ZERO_SEED_SIGNATURE = (
    "LskuTfFq_a_g2kgieIr7ljNp_J_z8XYzyiM_m1Cw6U_dwQeKI39VqwQqEmJFGayoiPMkw6bh7OCDMgCBX214CA"
)


class IdentityProtocolTests(unittest.TestCase):
    def test_ed25519_did_key_uses_base58btc_multicodec(self) -> None:
        self.assertEqual(derive_did_key(bytes(32)), ZERO_SEED_DID)

    def test_seed_must_be_exactly_32_bytes(self) -> None:
        for malformed in (b"", bytes(31), bytes(33), bytearray(32), "not bytes"):
            with self.subTest(malformed=type(malformed).__name__, length=len(malformed)):
                with self.assertRaises(ValueError):
                    derive_did_key(malformed)  # type: ignore[arg-type]
                with self.assertRaises(ValueError):
                    sign_canonical(malformed, "canonical")  # type: ignore[arg-type]

    def test_unicode_sweep_replaces_server_rejected_categories(self) -> None:
        rejected_by_category = {
            "Cc": "\x00",
            "Cf": "\u200b",
            "Cs": "\ud800",
            "Co": "\ue000",
            "Zl": "\u2028",
            "Zp": "\u2029",
        }

        for category, character in rejected_by_category.items():
            with self.subTest(category=category):
                self.assertEqual(unicodedata.category(character), category)
                self.assertEqual(sweep_unicode(f"left{character}right"), "left right")

        self.assertEqual(sweep_unicode("left   right"), "left   right")
        self.assertEqual(sweep_unicode("\x00left\u2029"), "left")

    def test_sweep_text_rejects_empty_or_oversized_content(self) -> None:
        self.assertEqual(MESSAGE_MAX_LENGTH, 4096)
        self.assertEqual(NOTE_MAX_LENGTH, 8192)
        self.assertEqual(sweep_text("  hello\u200bworld  ", MESSAGE_MAX_LENGTH), "hello world")
        self.assertEqual(sweep_text("a" * MESSAGE_MAX_LENGTH, MESSAGE_MAX_LENGTH), "a" * MESSAGE_MAX_LENGTH)

        for empty in ("", "   ", "\x00\u2029"):
            with self.subTest(empty=repr(empty)):
                with self.assertRaises(ValueError):
                    sweep_text(empty, MESSAGE_MAX_LENGTH)
        with self.assertRaises(ValueError):
            sweep_text("a" * (NOTE_MAX_LENGTH + 1), NOTE_MAX_LENGTH)

    def test_signature_is_unpadded_base64url_with_86_characters(self) -> None:
        encoded = sign_canonical(
            bytes(32), "lobby|1700000000000|hello from hermes sentinel"
        )

        self.assertEqual(encoded, ZERO_SEED_SIGNATURE)
        self.assertEqual(len(encoded), 86)
        self.assertNotIn("=", encoded)
        self.assertNotIn("+", encoded)
        self.assertNotIn("/", encoded)

    def test_sign_message_validates_and_returns_exact_canonical_payload(self) -> None:
        signed = sign_message(
            bytes(32), "lobby", "1700000000000", "  hello\u200bfrom hermes sentinel  "
        )

        self.assertIsInstance(signed, SignedMessage)
        self.assertEqual(signed.did, ZERO_SEED_DID)
        self.assertEqual(signed.signature, ZERO_SEED_SIGNATURE)
        self.assertEqual(signed.nonce, "1700000000000")
        self.assertEqual(signed.text, "hello from hermes sentinel")
        self.assertEqual(
            signed.canonical,
            "lobby|1700000000000|hello from hermes sentinel",
        )

    def test_sign_message_rejects_invalid_rooms(self) -> None:
        invalid_rooms = ("", "Lobby", "-lobby", "room.name", "a" * 49, "room/one")
        for room in invalid_rooms:
            with self.subTest(room=room):
                with self.assertRaises(ValueError):
                    sign_message(bytes(32), room, "1", "hello")

    def test_sign_message_accepts_room_boundary_and_rejects_invalid_nonces(self) -> None:
        sign_message(bytes(32), "a" + "_" * 47, "9" * 19, "hello")
        invalid_nonces = ("", "0" * 20, "12a", "-1", "１２", 123)
        for nonce in invalid_nonces:
            with self.subTest(nonce=nonce):
                with self.assertRaises(ValueError):
                    sign_message(bytes(32), "lobby", nonce, "hello")  # type: ignore[arg-type]

    def test_sign_message_enforces_message_limit_after_sweeping(self) -> None:
        with self.assertRaises(ValueError):
            sign_message(bytes(32), "lobby", "1", "x" * (MESSAGE_MAX_LENGTH + 1))
        with self.assertRaises(ValueError):
            sign_message(bytes(32), "lobby", "1", "\u200b\x00")

    def test_profile_location_is_sharded_from_full_did_fingerprint(self) -> None:
        expected_fingerprint = "ad90ec18fd5e0735"

        self.assertEqual(
            hashlib.sha256(ZERO_SEED_DID.encode("utf-8")).hexdigest()[:16],
            expected_fingerprint,
        )
        self.assertEqual(
            profile_location(ZERO_SEED_DID),
            (
                expected_fingerprint,
                "did-ad",
                "90ec18fd5e0735",
                "/kv/did-ad/90ec18fd5e0735",
            ),
        )


class IdentityPersistenceTests(unittest.TestCase):
    def test_create_identity_stays_anchored_when_parent_path_is_replaced(self) -> None:
        seed = bytes(range(32))
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            parent = root / "private"
            parent.mkdir(mode=0o700)
            displaced_parent = root / "original-private"
            key_path = parent / "identity.key"
            real_open = os.open
            replaced = False

            def replace_after_parent_open(path: object, *args: object, **kwargs: object) -> int:
                nonlocal replaced
                descriptor = real_open(path, *args, **kwargs)  # type: ignore[arg-type]
                if not replaced and path == parent:
                    replaced = True
                    parent.rename(displaced_parent)
                    parent.mkdir(mode=0o700)
                return descriptor

            with (
                mock.patch("technocore_sentinel.identity.os.open", side_effect=replace_after_parent_open),
                mock.patch(
                    "technocore_sentinel.identity.secrets.token_bytes", return_value=seed
                ),
            ):
                self.assertEqual(create_identity(key_path), seed)

            self.assertTrue(replaced)
            self.assertEqual((displaced_parent / key_path.name).read_bytes(), seed)
            self.assertFalse((parent / key_path.name).exists())

    def test_load_identity_stays_anchored_when_parent_path_is_replaced(self) -> None:
        original_seed = bytes(range(32))
        replacement_seed = bytes(reversed(range(32)))
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            parent = root / "private"
            parent.mkdir(mode=0o700)
            key_path = parent / "identity.key"
            key_path.write_bytes(original_seed)
            key_path.chmod(0o600)
            displaced_parent = root / "original-private"
            real_open = os.open
            replaced = False

            def replace_after_parent_open(path: object, *args: object, **kwargs: object) -> int:
                nonlocal replaced
                descriptor = real_open(path, *args, **kwargs)  # type: ignore[arg-type]
                if not replaced and path == parent:
                    replaced = True
                    parent.rename(displaced_parent)
                    parent.mkdir(mode=0o700)
                    replacement = parent / key_path.name
                    replacement.write_bytes(replacement_seed)
                    replacement.chmod(0o600)
                return descriptor

            with mock.patch(
                "technocore_sentinel.identity.os.open", side_effect=replace_after_parent_open
            ):
                self.assertEqual(load_identity(key_path), original_seed)

            self.assertTrue(replaced)
            self.assertEqual((parent / key_path.name).read_bytes(), replacement_seed)

    def test_identity_paths_reject_empty_dot_and_dot_dot_basenames(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            invalid_paths = ("", ".", "..", f"{temporary_directory}/")
            for invalid_path in invalid_paths:
                with self.subTest(path=invalid_path):
                    with self.assertRaises(ValueError):
                        create_identity(invalid_path)
                    with self.assertRaises(ValueError):
                        load_identity(invalid_path)

    def test_create_identity_uses_deterministic_mock_and_restrictive_modes(self) -> None:
        seed = bytes(range(32))
        with tempfile.TemporaryDirectory() as temporary_directory:
            key_path = Path(temporary_directory) / "private" / "identity.key"
            with mock.patch(
                "technocore_sentinel.identity.secrets.token_bytes", return_value=seed
            ) as token_bytes:
                returned = create_identity(key_path)

            token_bytes.assert_called_once_with(32)
            self.assertEqual(returned, seed)
            self.assertEqual(key_path.read_bytes(), seed)
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(key_path.parent.stat().st_mode), 0o700)

    def test_create_identity_refuses_existing_file_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            existing = root / "identity.key"
            existing.write_bytes(b"unchanged")
            with self.assertRaises(FileExistsError):
                create_identity(existing)
            self.assertEqual(existing.read_bytes(), b"unchanged")

            target = root / "target"
            target.write_bytes(b"target unchanged")
            link = root / "identity-link.key"
            link.symlink_to(target)
            with self.assertRaises((FileExistsError, ValueError)):
                create_identity(link)
            self.assertEqual(target.read_bytes(), b"target unchanged")

    def test_create_and_load_refuse_unsafe_or_symlinked_parent(self) -> None:
        seed = bytes(range(32))
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            unsafe_parent = root / "unsafe"
            unsafe_parent.mkdir(mode=0o755)
            unsafe_key = unsafe_parent / "identity.key"
            unsafe_key.write_bytes(seed)
            unsafe_key.chmod(0o600)
            with self.assertRaises(ValueError):
                create_identity(unsafe_parent / "new.key")
            with self.assertRaises(ValueError):
                load_identity(unsafe_key)

            real_parent = root / "real"
            real_parent.mkdir(mode=0o700)
            parent_link = root / "parent-link"
            parent_link.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaises(ValueError):
                create_identity(parent_link / "new.key")

    def test_load_identity_returns_seed_from_secure_regular_file(self) -> None:
        seed = bytes(range(32))
        with tempfile.TemporaryDirectory() as temporary_directory:
            key_path = Path(temporary_directory) / "identity.key"
            key_path.write_bytes(seed)
            key_path.chmod(0o600)
            self.assertEqual(load_identity(key_path), seed)

    def test_load_identity_refuses_symlink_non_regular_wrong_size_or_unsafe_mode(self) -> None:
        seed = bytes(range(32))
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)

            secure = root / "secure.key"
            secure.write_bytes(seed)
            secure.chmod(0o600)
            link = root / "link.key"
            link.symlink_to(secure)
            with self.assertRaises(ValueError):
                load_identity(link)

            directory = root / "directory.key"
            directory.mkdir()
            with self.assertRaises(ValueError):
                load_identity(directory)

            wrong_size = root / "short.key"
            wrong_size.write_bytes(bytes(31))
            wrong_size.chmod(0o600)
            with self.assertRaises(ValueError):
                load_identity(wrong_size)

            unsafe = root / "unsafe.key"
            unsafe.write_bytes(seed)
            unsafe.chmod(0o640)
            with self.assertRaises(ValueError):
                load_identity(unsafe)


class NonceTests(unittest.TestCase):
    @mock.patch("technocore_sentinel.identity.time.time_ns", return_value=1_700_000_000_000_000_000)
    def test_next_nonce_uses_time_ns_and_increases_past_previous(self, time_ns: mock.Mock) -> None:
        self.assertEqual(next_nonce(), "1700000000000000000")
        self.assertEqual(next_nonce("1700000000000000005"), "1700000000000000006")
        time_ns.assert_called()

    def test_next_nonce_rejects_invalid_previous_and_19_digit_overflow(self) -> None:
        for previous in ("", "12a", "0" * 20, -1):
            with self.subTest(previous=previous):
                with self.assertRaises(ValueError):
                    next_nonce(previous)  # type: ignore[arg-type]

        with mock.patch(
            "technocore_sentinel.identity.time.time_ns", return_value=9_999_999_999_999_999_999
        ):
            with self.assertRaises(OverflowError):
                next_nonce("9999999999999999999")


if __name__ == "__main__":
    unittest.main()
