"""Tests for 0.1.5: Open WebUI 0.13.5 (25 November 2026) ships security fixes whose advisories are withheld.
Made with AI agents for MV2 of Munim, Inc. Apache-2.0."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import owui_hardening_check as owc  # noqa: E402


class Release0135Tests(unittest.TestCase):
    def test_versions_before_0_13_5_get_one_medium_finding(self):
        for version in ((0, 13, 1), (0, 13, 3), (0, 13, 4)):
            found = owc.check_version(version)
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0]["severity"], "medium")
            self.assertTrue(found[0]["title"].endswith("has 1 known advisory"))
            self.assertIn("0.13.5 release notes (fixed in 0.13.5)", found[0]["detail"])
            self.assertIn(owc.RELEASE_0_13_5, found[0]["detail"])

    def test_0_13_5_and_newer_are_clean(self):
        self.assertEqual(owc.SAFE_VERSION, "0.13.5")
        for version in ((0, 13, 5), (0, 13, 10), (0, 14, 0), (1, 0, 0)):
            self.assertEqual(owc.check_version(version), [])

    def test_release_note_entry_never_raises_severity(self):
        # 0.13.4 had no advisories before; the withheld 0.13.5 fixes alone must stay medium.
        self.assertEqual(owc.check_version((0, 13, 4), "v0.13.4")[0]["severity"], "medium")
        # Versions with published High advisories stay high.
        self.assertEqual(owc.check_version((0, 11, 2))[0]["severity"], "high")

    def test_update_advice_mentions_the_migration(self):
        fix = owc.check_version((0, 12, 5))[0]["fix"]
        self.assertIn("0.13.5 migrate the database", fix)
        self.assertIn("no rolling updates", fix)

    def test_tag_pin_example_uses_latest(self):
        dep = owc.parse_text("services:\n  w:\n    image: ghcr.io/open-webui/open-webui:main\n", "c.yml")
        fix = [f for f in owc.check_deployment(dep) if "tag moves" in f["title"]][0]["fix"]
        self.assertIn("open-webui:v0.13.5", fix)

    def test_function_metadata_matches_version(self):
        with open(os.path.join(HERE, "owui_hardening_check.py"), encoding="utf-8") as f:
            text = f.read()
        self.assertTrue(text.startswith('"""\ntitle: Open WebUI Hardening Check\n'))
        self.assertIn("\nversion: %s\n" % owc.__version__, text.split('"""')[1])
        self.assertIn("\nlicense: Apache-2.0\n", text.split('"""')[1])
        self.assertEqual(owc.__version__, "0.1.5")
        self.assertEqual(owc.DATA_DATE, "26 November 2026")


if __name__ == "__main__":
    unittest.main()
