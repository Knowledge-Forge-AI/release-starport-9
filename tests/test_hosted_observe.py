"""Destination observations cannot promote diagnostic metadata to exact readback."""
import unittest

from rs9.hosted_observe import readback_satisfied


class HostedReadbackTests(unittest.TestCase):
    def row(self, adapter, state):
        return {"adapter": adapter, "observation": {"state": state}}

    def test_existing_npm_and_homebrew_require_exact_byte_identity(self):
        for adapter in ("npm", "homebrew"):
            self.assertTrue(readback_satisfied(self.row(adapter, "exact")))
            for state in ("unknown", "incomplete", "absent", "conflict"):
                self.assertFalse(readback_satisfied(self.row(adapter, state)))

    def test_pypi_absence_does_not_attest_a_deployed_pages_site(self):
        self.assertTrue(readback_satisfied(self.row("pypi", "absent")))
        self.assertTrue(readback_satisfied(self.row("pages", "absent")))
        self.assertFalse(readback_satisfied(self.row("pages", "exact")))
        self.assertFalse(readback_satisfied(self.row("pypi", "incomplete")))
