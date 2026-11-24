"""Test 2/9 — Monero wallet address validation."""
import unittest

from tests import REPO_ROOT  # noqa: F401
from hashflow.core import validate_wallet

# Format-correct sample addresses (checksums not validated by design).
STANDARD = "4" + "A" * 94                      # 95 chars, prefix 4
SUBADDR = "8" + "B" * 94                       # 95 chars, prefix 8
INTEGRATED = "4" + "C" * 105                   # 106 chars
TESTNET = "9" + "D" * 94                       # testnet standard


class TestWalletValidation(unittest.TestCase):
    def test_standard_address_accepted(self):
        ok, _ = validate_wallet(STANDARD)
        self.assertTrue(ok)

    def test_subaddress_accepted(self):
        self.assertTrue(validate_wallet(SUBADDR)[0])

    def test_integrated_address_accepted(self):
        self.assertTrue(validate_wallet(INTEGRATED)[0])

    def test_testnet_accepted(self):
        self.assertTrue(validate_wallet(TESTNET)[0])

    def test_empty_rejected(self):
        ok, reason = validate_wallet("")
        self.assertFalse(ok)
        self.assertIn("empty", reason)

    def test_short_address_rejected_with_length_hint(self):
        ok, reason = validate_wallet("4ABC")
        self.assertFalse(ok)
        self.assertIn("characters", reason)

    def test_trailing_newline_from_paste_tolerated(self):
        self.assertTrue(validate_wallet(STANDARD + "\n")[0])

    def test_internal_whitespace_rejected(self):
        self.assertFalse(validate_wallet("4 " + "A" * 93)[0])

    def test_illegal_base58_chars_rejected(self):
        bad = "4" + "0" * 94          # '0' not in base58
        self.assertFalse(validate_wallet(bad)[0])
        bad2 = "4" + "l" * 94         # 'l' not in base58
        self.assertFalse(validate_wallet(bad2)[0])

    def test_wrong_prefix_rejected(self):
        self.assertFalse(validate_wallet("5" + "A" * 94)[0])

    def test_reason_is_actionable(self):
        _, reason = validate_wallet("x")
        self.assertTrue(len(reason) > 20)


if __name__ == "__main__":
    unittest.main()
