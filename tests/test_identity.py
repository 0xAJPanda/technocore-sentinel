"""Executable specifications for Sentinel identity wire formats."""

from pathlib import Path
import unittest

from technocore_sentinel.identity import (
    derive_did_key,
    fingerprint_path,
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
        rejected = "\x00\u200b\ud800\ue000\u2028\u2029"
        # Respectively: Cc, Cf, Cs, Co, Zl, and Zp. Ordinary spaces (Zs) remain.
        self.assertEqual(sweep_unicode(f"left {rejected} right"), "left  right")

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

    def test_fingerprint_path_is_sharded_by_leading_bytes(self) -> None:
        fingerprint = "abcdef0123456789"

        self.assertEqual(
            fingerprint_path(Path("state"), fingerprint),
            Path("state/fingerprints/ab/cd/abcdef0123456789.json"),
        )


if __name__ == "__main__":
    unittest.main()
