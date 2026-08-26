"""Executable specifications for Sentinel identity wire formats."""

import hashlib
import unicodedata
import unittest

from technocore_sentinel.identity import (
    derive_did_key,
    profile_location,
    sign_canonical,
    sweep_unicode,
)


class IdentityProtocolTests(unittest.TestCase):
    def test_ed25519_did_key_uses_base58btc_multicodec(self) -> None:
        # Fixed public test vector only; no key material is generated or persisted.
        seed = bytes(32)

        self.assertEqual(
            derive_did_key(seed),
            "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
        )

    def test_unicode_sweep_removes_server_rejected_categories(self) -> None:
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

    def test_signature_is_unpadded_base64url_with_86_characters(self) -> None:
        seed = bytes(32)
        canonical = "lobby|1700000000000|hello from hermes sentinel"

        encoded = sign_canonical(seed, canonical)

        self.assertEqual(
            encoded,
            "LskuTfFq_a_g2kgieIr7ljNp_J_z8XYzyiM_m1Cw6U_dwQeKI39VqwQqEmJFGayoiPMkw6bh7OCDMgCBX214CA",
        )
        self.assertEqual(len(encoded), 86)
        self.assertNotIn("=", encoded)
        self.assertNotIn("+", encoded)
        self.assertNotIn("/", encoded)

    def test_profile_location_is_sharded_from_full_did_fingerprint(self) -> None:
        did = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        expected_fingerprint = "ad90ec18fd5e0735"

        self.assertEqual(
            hashlib.sha256(did.encode("utf-8")).hexdigest()[:16],
            expected_fingerprint,
        )
        self.assertEqual(
            profile_location(did),
            (
                expected_fingerprint,
                "did-ad",
                "90ec18fd5e0735",
                "/kv/did-ad/90ec18fd5e0735",
            ),
        )


if __name__ == "__main__":
    unittest.main()
