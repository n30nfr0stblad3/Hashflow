"""Test 6/9 — informed-consent gate (the safety/legal control added in v2)."""
import io
import unittest

from tests import REPO_ROOT  # noqa: F401
from hashflow.core import build_allocation_plan, consent_message, require_consent

PLAN = build_allocation_plan(4, 0.05)
WALLET = "4" + "A" * 94
OWNER = "4" + "B" * 94


class TestConsentMessage(unittest.TestCase):
    def test_message_shows_exact_split(self):
        msg = consent_message(WALLET, OWNER, 0.05, PLAN, "pool.example:3333")
        self.assertIn("5.0% to owner", msg)          # realized share, not marketing
        self.assertIn("pool.example:3333", msg)
        self.assertIn("authorized", msg.lower())

    def test_message_masks_wallets(self):
        msg = consent_message(WALLET, OWNER, 0.05, PLAN, "p")
        self.assertNotIn(WALLET, msg)
        self.assertIn(WALLET[:12], msg)

    def test_zero_donation_message(self):
        solo = build_allocation_plan(8, 0.0)
        msg = consent_message(WALLET, None, 0.0, solo, "p")
        self.assertIn("disabled", msg)
        self.assertNotIn("Owner wallet", msg)


class TestRequireConsent(unittest.TestCase):
    def test_agree_flag_passes(self):
        self.assertTrue(require_consent(True, WALLET, OWNER, 0.05, PLAN, "p",
                                        interactive=False))

    def test_non_interactive_without_agree_refuses(self):
        out = io.StringIO()
        ok = require_consent(False, WALLET, OWNER, 0.05, PLAN, "p",
                             interactive=False, print_fn=lambda *a: print(*a, file=out))
        self.assertFalse(ok)
        self.assertIn("--agree", out.getvalue())

    def test_interactive_yes_passes(self):
        ok = require_consent(False, WALLET, OWNER, 0.05, PLAN, "p",
                             interactive=True,
                             input_fn=lambda prompt: "YES",
                             print_fn=lambda *a: None)
        self.assertTrue(ok)

    def test_interactive_no_refuses(self):
        ok = require_consent(False, WALLET, OWNER, 0.05, PLAN, "p",
                             interactive=True,
                             input_fn=lambda prompt: "no",
                             print_fn=lambda *a: None)
        self.assertFalse(ok)

    def test_interactive_wrong_word_refuses(self):
        ok = require_consent(False, WALLET, OWNER, 0.05, PLAN, "p",
                             interactive=True,
                             input_fn=lambda prompt: "y",  # must type YES exactly
                             print_fn=lambda *a: None)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
